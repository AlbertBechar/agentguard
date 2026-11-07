"""AgentGuard: ο φύλακας από τον οποίο περνάει κάθε κλήση εργαλείου του chatbot."""
import json
from datetime import datetime, timezone

from . import honeytoken
from .db import execute, query
from .guard_types import TurnContext


# --------------------------------------------------------------------------- πίνακες βάσης

def _ensure_tables():
    """Φτιάχνει τους πίνακες του Guard αν δεν υπάρχουν (φθηνό, το καλούμε συχνά)."""
    execute("""CREATE TABLE IF NOT EXISTS guard_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        user_id INTEGER,
        tool TEXT,
        args_json TEXT,
        action TEXT,
        reason TEXT,
        rule TEXT,
        tainted INTEGER,
        injection_score REAL
    )""")
    execute("""CREATE TABLE IF NOT EXISTS guard_taint (
        user_id INTEGER PRIMARY KEY,
        tainted_at TEXT
    )""")
    execute("""CREATE TABLE IF NOT EXISTS guard_lock (
    user_id INTEGER PRIMARY KEY,
    locked_at TEXT,
    reason TEXT
)""")

def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log_event(user_id, tool, args, action, reason="", rule="", tainted=False, injection_score=0.0):
    """Γράφει μία απόφαση του Guard στον πίνακα guard_events."""
    _ensure_tables()
    execute(
        "INSERT INTO guard_events (ts, user_id, tool, args_json, action, reason, rule, tainted, injection_score) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (_now(), user_id, tool, json.dumps(args, ensure_ascii=False, default=str),
         action, reason, rule, 1 if tainted else 0, float(injection_score)),
    )


# --------------------------------------------------------------------------- taint

def _is_tainted(user_id):
    """True αν η συνομιλία αυτού του χρήστη έχει διαβάσει μη-έμπιστο περιεχόμενο."""
    _ensure_tables()
    return query("SELECT 1 FROM guard_taint WHERE user_id = ?", (user_id,), one=True) is not None


def _set_tainted(user_id):
    """Σημαδεύει τη συνομιλία του χρήστη ως tainted (κρατάει την πρώτη ώρα)."""
    _ensure_tables()
    execute("INSERT OR IGNORE INTO guard_taint (user_id, tainted_at) VALUES (?, ?)", (user_id, _now()))


def _clear_taint(user_id):
    """Καθαρίζει το taint (π.χ. όταν ο χρήστης πατήσει Clear στο chat)."""
    _ensure_tables()
    execute("DELETE FROM guard_taint WHERE user_id = ?", (user_id,))


"""
Η _ensure_tables() φτιάχνει τους δύο πίνακες με CREATE TABLE IF NOT EXISTS, δηλαδή μόνο αν λείπουν. Αυτό χρειάζεται γιατί η βάση ξαναδημιουργείται σε κάθε εκκίνηση του Docker.
Η _log_event() γράφει μια γραμμή «ποιος, ποιο εργαλείο, με ποια ορίσματα, τι αποφασίστηκε και γιατί». Το json.dumps μετατρέπει τα ορίσματα σε κείμενο για να χωρέσουν σε μία στήλη.
Οι _is_tainted, _set_tainted και _clear_taint διαβάζουν, βάζουν και σβήνουν το σημάδι ανά χρήστη. Τα ? στο SQL κάνουν τη βάση να βάλει τις τιμές με ασφάλεια, και αυτό προστατεύει από SQL injection.
"""

# --------------------------------------------------------------------------- κλείδωμα (honeytoken)

def _lock(user_id, reason):
    """Κλειδώνει τη συνομιλία: κανένα εργαλείο δεν εκτελείται μέχρι το Clear."""
    _ensure_tables()
    execute("INSERT OR IGNORE INTO guard_lock (user_id, locked_at, reason) VALUES (?, ?, ?)",
            (user_id, _now(), reason))


def _is_locked(user_id):
    _ensure_tables()
    return query("SELECT 1 FROM guard_lock WHERE user_id = ?", (user_id,), one=True) is not None


def _unlock(user_id):
    _ensure_tables()
    execute("DELETE FROM guard_lock WHERE user_id = ?", (user_id,))
# --------------------------------------------------------------------------- ο Guard

APPROVAL_MESSAGE = ("A human must approve this in the Guard page (/guard). "
                    "Tell the user. Do not retry or find another way.")
APPROVAL_REASON = "high-risk action after untrusted content was read"

HONEYTOKEN_REASON = "honeytoken data in tool arguments (likely data theft); conversation locked"
LOCKED_REASON = "conversation locked after a honeytoken alert; press Clear to start over"

class Guard:
    """Αποφασίζει για κάθε κλήση εργαλείου: μπλόκο, έγκριση από άνθρωπο ή εκτέλεση."""

    def __init__(self, policy, sanitizer, approvals, audit_fn=None):
        # Dependency injection: παίρνουμε τα modules των άλλων ως ορίσματα,
        # ώστε στα τεστ να βάζουμε ψεύτικα στη θέση τους.
        self.policy = policy
        self.sanitizer = sanitizer
        self.approvals = approvals
        self.audit_fn = audit_fn or _log_event

    def new_turn(self, user, user_message):
        """Καλείται στην αρχή κάθε μηνύματος. Φορτώνει το taint από τη βάση."""
        return TurnContext(user=user, user_message=user_message, tainted=_is_tainted(user["id"]))

    def clear_taint(self, user_id):
        _clear_taint(user_id)
        _unlock(user_id)

    def _log(self, ctx, user, name, args, action, reason="", rule="", score=0.0):
        ctx.events.append({"tool": name, "action": action, "reason": reason, "rule": rule})
        self.audit_fn(user["id"], name, args, action, reason=reason, rule=rule,
                      tainted=ctx.tainted, injection_score=score)

    def run_tool(self, ctx, call_tool_fn, user, name, args):
        args = args or {}
        try:
            # 0α. Η συνομιλία έχει κλειδώσει από προηγούμενο συναγερμό; Τότε τίποτα δεν περνάει.
            if _is_locked(user["id"]):
                self._log(ctx, user, name, args, "deny", LOCKED_REASON, "honeytoken.locked")
                return {"error": f"blocked by guard: {LOCKED_REASON}"}

            # 0β. Honeytoken: τα ψεύτικα ευαίσθητα δεδομένα βρίσκονται μέσα στα ορίσματα;
            if honeytoken.found_in(args):
                _lock(user["id"], HONEYTOKEN_REASON)
                self._log(ctx, user, name, args, "deny", HONEYTOKEN_REASON, "honeytoken")
                honeytoken.alert_admin(user, name)
                return {"error": f"blocked by guard: {HONEYTOKEN_REASON}"}
            
            # 1. Επιτρέπεται αυτή η ενέργεια σε αυτόν τον χρήστη;
            d = self.policy.check(user, name, args, ctx)
            if d.action != "allow":  # fail-closed: ό,τι δεν είναι ρητά "allow" μπλοκάρεται
                self._log(ctx, user, name, args, "deny", d.reason, d.rule)
                return {"error": f"blocked by policy: {d.reason}"}

            # 2. Επικίνδυνη ενέργεια αφού διαβάστηκε μη-έμπιστο περιεχόμενο -> έγκριση από άνθρωπο.
            if ctx.tainted and name in self.policy.HIGH_RISK_TOOLS:
                aid = self.approvals.create_pending(user, name, args, APPROVAL_REASON)
                self._log(ctx, user, name, args, "approve", APPROVAL_REASON, "taint.high_risk")
                return {"status": "approval_required", "approval_id": aid, "message": APPROVAL_MESSAGE}

            # 3. Εκτέλεση του πραγματικού εργαλείου.
            result = call_tool_fn(user, name, args)

            # 4. Αφαιρούμε ό,τι δεν δικαιούται να δει ο χρήστης.
            result = self.policy.redact(user, name, args, result)

            # 5. Μη-έμπιστο περιεχόμενο: καθαρισμός και σημάδι taint.
            score = 0.0
            if name in self.policy.UNTRUSTED_TOOLS:
                result, _findings, score = self.sanitizer.sanitize_result(name, result, source=name)
                ctx.tainted = True
                _set_tainted(user["id"])

            # 6. Καταγραφή και επιστροφή στο LLM.
            self._log(ctx, user, name, args, "allow", score=score)
            return result

        except Exception as e:  # fail-closed: αν σκάσει κάτι μέσα στον Guard, μπλοκάρουμε
            try:
                self._log(ctx, user, name, args, "deny", f"internal error: {type(e).__name__}: {e}", "guard.error")
            except Exception:
                pass  # ακόμα κι αν δεν γράφεται το log, η ενέργεια μένει μπλοκαρισμένη
            return {"error": "blocked by guard: internal error"}


_GUARD = None


def get_guard():
    """Επιστρέφει τον έναν και μοναδικό Guard, με τα πραγματικά modules της ομάδας."""
    global _GUARD
    if _GUARD is None:
        # Import εδώ μέσα (όχι στην κορυφή), για να μη σπάει το guard.py
        # όσο τα αρχεία των άλλων δεν έχουν φτάσει ακόμα.
        from . import approvals, eclass_policy, sanitize
        _GUARD = Guard(eclass_policy, sanitize, approvals)
        try:
            honeytoken.plant()
        except Exception as e:  # χωρίς παγίδα ο Guard δουλεύει κανονικά· απλώς το λέμε
            print(f"[guard] honeytoken not planted: {e}", flush=True)
    return _GUARD

"""
Η run_tool ακολουθεί ακριβώς τη σειρά του εγγράφου σας: policy → έγκριση αν η συνομιλία είναι tainted και η ενέργεια high-risk → εκτέλεση → redact → sanitize και taint → log.
Όλο το σώμα της είναι μέσα σε try/except. Αν σκάσει οτιδήποτε (policy, sanitizer, approvals), επιστρέφει blocked by guard: internal error και το εργαλείο δεν τρέχει.
Η _log γράφει κάθε απόφαση και στο ctx.events (για debugging) και στον πίνακα guard_events (για τη σελίδα /guard του P4).
"""