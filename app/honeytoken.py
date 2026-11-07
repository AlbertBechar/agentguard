"""Honeytoken: ένας ψεύτικος φοιτητής-παγίδα.

Φυτεύουμε στη βάση έναν φοιτητή που δεν υπάρχει, με τυχαίο ΑΜΚΑ, IBAN και ταυτότητα.
Κανείς δεν έχει νόμιμο λόγο να βάλει αυτές τις τιμές μέσα σε μια κλήση εργαλείου
(π.χ. στο σώμα ενός μηνύματος). Αν εμφανιστούν, κάποιος κλέβει δεδομένα.
"""
import json
import re
import secrets

from werkzeug.security import generate_password_hash

from .db import execute, query

HONEY_USERNAME = "sdi2499999"
HONEY_FULL_NAME = "Nikolaos Stathopoulos"
TRAP_FIELDS = ("amka", "iban", "id_card")   # μόνο ευαίσθητα πεδία: δεν στέλνονται ποτέ νόμιμα


def _random_digits(n):
    return "".join(secrets.choice("0123456789") for _ in range(n))


def plant():
    """Φτιάχνει τον ψεύτικο φοιτητή (αν δεν υπάρχει) και τον γράφει σε όλα τα μαθήματα."""
    execute(
        "INSERT OR IGNORE INTO users (username, password_hash, full_name, email, role, student_number, "
        "department, year_of_study, amka, iban, id_card) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (HONEY_USERNAME,
         generate_password_hash(secrets.token_urlsafe(32)),   # κωδικός που δεν ξέρει κανείς
         HONEY_FULL_NAME,
         f"{HONEY_USERNAME}@students.athena-eclass.local",
         "student",
         "1115202499999",
         "Informatics & Telecommunications",
         2,
         _random_digits(11),                                  # ΑΜΚΑ
         "GR" + _random_digits(25),                           # IBAN
         "AZ " + _random_digits(6)))                          # ταυτότητα
    honey = query("SELECT id FROM users WHERE username = ?", (HONEY_USERNAME,), one=True)
    execute("INSERT OR IGNORE INTO enrollments (user_id, course_id) SELECT ?, id FROM courses", (honey["id"],))


def _normalize(text):
    """Κρατάει μόνο γράμματα και ψηφία, με κεφαλαία: '311 299-041.72' -> '31129904172'."""
    return re.sub(r"[^0-9A-Za-z]", "", str(text)).upper()


def trap_values():
    """Οι τιμές-παγίδα, όπως είναι αποθηκευμένες στη βάση (κανονικοποιημένες)."""
    if query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'", one=True) is None:
        return []   # βάση χωρίς χρήστες (π.χ. άδεια δοκιμαστική): δεν υπάρχει παγίδα να ελέγξουμε
    row = query("SELECT amka, iban, id_card FROM users WHERE username = ?", (HONEY_USERNAME,), one=True)
    if row is None:
        return []
    return [_normalize(row[f]) for f in TRAP_FIELDS if row[f]]


def found_in(args):
    """True αν κάποια τιμή-παγίδα εμφανίζεται οπουδήποτε μέσα στα ορίσματα ενός εργαλείου."""
    text = _normalize(json.dumps(args, ensure_ascii=False, default=str))
    return any(value in text for value in trap_values())


def alert_admin(user, tool):
    """Στέλνει μήνυμα στον admin μέσα στην πλατφόρμα (το βλέπει στα Messages)."""
    admin = query("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1", one=True)
    if admin is None:
        return
    execute("INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?,?,?,?)",
            (admin["id"], admin["id"], "AgentGuard: honeytoken alert",
             f"The chatbot tried to send honeytoken data with the tool '{tool}' "
             f"in the conversation of user '{user['username']}'. The conversation was locked."))


"""
Το secrets (αντί για random) είναι η βιβλιοθήκη της Python για τιμές που δεν πρέπει να μαντευτούν, όπως κωδικοί και κλειδιά. Οι τιμές βγαίνουν διαφορετικές σε κάθε εγκατάσταση, άρα ένας επιτιθέμενος δεν μπορεί να τις διαβάσει στο GitHub σας.
Οι τιμές δεν κρατιούνται σε δικό μας πίνακα: είναι στη γραμμή του ψεύτικου χρήστη στον πίνακα users, και τις ξαναδιαβάζουμε από εκεί.
Ψάχνουμε μόνο ΑΜΚΑ, IBAN και ταυτότητα, όχι όνομα ή username. Αν ένας καθηγητής στείλει νόμιμα μήνυμα σε όλους τους φοιτητές του, ο ψεύτικος θα είναι στους παραλήπτες, και αυτό δεν πρέπει να χτυπήσει συναγερμό.
"""