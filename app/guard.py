"""AgentGuard: ο φύλακας από τον οποίο περνάει κάθε κλήση εργαλείου του chatbot."""
import json
from datetime import datetime, timezone

from .db import execute, query


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