"""Αιτήματα έγκρισης (human-in-the-loop) για επικίνδυνες ενέργειες του chatbot.

Ο Guard (P1) καλεί create_pending() όταν μια επικίνδυνη ενέργεια ζητηθεί μετά από
μη-έμπιστο περιεχόμενο. Ο άνθρωπος βλέπει τα αιτήματα στη σελίδα /guard.
"""
import json
from datetime import datetime, timezone

from .db import execute, get_db, query
from .tools import call_tool  # το tools.py δεν κάνει import το approvals, άρα δεν έχουμε κυκλικό import


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _args_to_json(args):
    # sort_keys=True: τα {"a":1,"b":2} και {"b":2,"a":1} δίνουν το ίδιο κείμενο,
    # άρα το ίδιο αίτημα αναγνωρίζεται ως διπλότυπο.
    return json.dumps(args or {}, sort_keys=True, ensure_ascii=False, default=str)


def ensure_tables():
    """Φτιάχνει τον πίνακα guard_approvals αν δεν υπάρχει (φθηνό, το καλούμε συχνά)."""
    execute("""CREATE TABLE IF NOT EXISTS guard_approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        user_id INTEGER,
        tool TEXT,
        args_json TEXT,
        reason TEXT,
        status TEXT,
        approver_id INTEGER,
        resolved_ts TEXT,
        result_json TEXT
    )""")


def create_pending(user, tool, args, reason):
    """Δημιουργεί αίτημα έγκρισης και επιστρέφει το id του.
    Αν υπάρχει ήδη ίδιο pending αίτημα (ίδιος χρήστης, εργαλείο, ορίσματα), επιστρέφει εκείνο."""
    ensure_tables()
    args_json = _args_to_json(args)
    existing = query(
        "SELECT id FROM guard_approvals WHERE user_id = ? AND tool = ? AND args_json = ? AND status = 'pending'",
        (user["id"], tool, args_json), one=True)
    if existing:
        return existing["id"]
    return execute(
        "INSERT INTO guard_approvals (ts, user_id, tool, args_json, reason, status) VALUES (?, ?, ?, ?, ?, 'pending')",
        (_now(), user["id"], tool, args_json, reason))


def _row_to_dict(row):
    d = dict(row)
    d["args"] = json.loads(d["args_json"] or "{}")
    return d


def list_pending(user):
    """Τα pending αιτήματα του χρήστη. Ο admin βλέπει όλα."""
    ensure_tables()
    if user.get("role") == "admin":
        rows = query("SELECT * FROM guard_approvals WHERE status = 'pending' ORDER BY id DESC")
    else:
        rows = query("SELECT * FROM guard_approvals WHERE status = 'pending' AND user_id = ? ORDER BY id DESC",
                     (user["id"],))
    return [_row_to_dict(r) for r in rows]


def _finish(approval_id, status, result):
    """Γράφει το τελικό status και το αποτέλεσμα (ως JSON) στο αίτημα."""
    execute("UPDATE guard_approvals SET status = ?, result_json = ? WHERE id = ?",
            (status, json.dumps(result, ensure_ascii=False, default=str), approval_id))
    return {"status": status, "result": result}


def resolve(approval_id, approver, approve):
    """Ο άνθρωπος εγκρίνει ή απορρίπτει ένα αίτημα. Κάθε αίτημα επιλύεται μία μόνο φορά."""
    ensure_tables()

    # 1. Φόρτωση: πρέπει να υπάρχει και να είναι pending.
    row = query("SELECT * FROM guard_approvals WHERE id = ?", (approval_id,), one=True)
    if row is None or row["status"] != "pending":
        return {"status": "failed", "result": "not found or already resolved"}

    # 2. Εξουσιοδότηση: μόνο ο ίδιος ο αιτών ή ο admin.
    if approver["id"] != row["user_id"] and approver.get("role") != "admin":
        raise PermissionError("only the requester or an admin can resolve this request")

    # «Κλείδωμα»: σημειώνουμε approver/ώρα ΜΟΝΟ αν κανείς άλλος δεν το έχει πιάσει ήδη.
    # Αν δύο κλικ φτάσουν ταυτόχρονα, μόνο το ένα αλλάζει τη γραμμή (rowcount == 1).
    db = get_db()
    cur = db.execute(
        "UPDATE guard_approvals SET approver_id = ?, resolved_ts = ? "
        "WHERE id = ? AND status = 'pending' AND resolved_ts IS NULL",
        (approver["id"], _now(), approval_id))
    db.commit()
    if cur.rowcount != 1:
        return {"status": "failed", "result": "not found or already resolved"}

    # 3. Απόρριψη.
    if not approve:
        return _finish(approval_id, "rejected", "rejected by human")

    # 4. Έγκριση: ξαναρωτάμε την πολιτική ως ο αιτών. Η έγκριση δεν είναι «master key».
    requester = query("SELECT * FROM users WHERE id = ?", (row["user_id"],), one=True)
    if requester is None:
        return _finish(approval_id, "failed", "requester no longer exists")
    tool = row["tool"]
    args = json.loads(row["args_json"] or "{}")
    try:
        from . import eclass_policy  # import εδώ: το αρχείο του P2 μπορεί να μην υπάρχει ακόμα
        from .guard_types import TurnContext
        d = eclass_policy.check(requester, tool, args, TurnContext(requester, ""))
    except Exception as e:  # fail-closed: αν η πολιτική σκάσει, δεν εκτελούμε
        return _finish(approval_id, "failed", f"policy error: {type(e).__name__}: {e}")
    if d.action != "allow":
        return _finish(approval_id, "failed", f"blocked by policy: {d.reason}")

    # 5. Εκτέλεση του πραγματικού εργαλείου, ως ο αιτών (όχι μέσω Guard: ο άνθρωπος ενέκρινε).
    try:
        result = call_tool(requester, tool, args)
    except Exception as e:
        return _finish(approval_id, "failed", f"{type(e).__name__}: {e}")
    # Το call_tool πιάνει μόνο του τα exceptions και επιστρέφει {"error": ...}· κι αυτό είναι αποτυχία.
    if isinstance(result, dict) and "error" in result:
        return _finish(approval_id, "failed", result)
    return _finish(approval_id, "approved", result)
