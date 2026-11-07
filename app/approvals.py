"""Αιτήματα έγκρισης (human-in-the-loop) για επικίνδυνες ενέργειες του chatbot.

Ο Guard (P1) καλεί create_pending() όταν μια επικίνδυνη ενέργεια ζητηθεί μετά από
μη-έμπιστο περιεχόμενο. Ο άνθρωπος βλέπει τα αιτήματα στη σελίδα /guard.
"""
import json
from datetime import datetime, timezone

from .db import execute, query


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
