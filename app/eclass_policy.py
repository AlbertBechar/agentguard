"""
app/eclass_policy.py
Λεπτός adapter (Layer 2) πάνω στον γενικό PolicyEngine.

Οι κανόνες και το redaction του Athena eClass ζουν πλέον στο app/eclass_policy.json (δηλωτικά).
Εδώ μένει μόνο ο «resolver»: η κλάση LazyContext που απαντά, από τη SQLite, στις ερωτήσεις που
κάνουν οι κανόνες ($ctx.<όνομα>), π.χ. «διδάσκει ο χρήστης αυτό το μάθημα;». Υπολογίζει κάθε
ιδιότητα μόνο όταν ζητηθεί (lazy) και μία φορά ανά κλήση.

Το συμβόλαιο προς τον Guard δεν άλλαξε:
    UNTRUSTED_TOOLS, HIGH_RISK_TOOLS (sets), check(user, tool, args, ctx) -> Decision,
    redact(user, tool, args, result)
"""
from __future__ import annotations

import sys
from pathlib import Path

from app.db import query
from app.guard_types import Decision
from app.policy_engine import PolicyEngine
from app.tools import _find_course, _find_user

POLICY_PATH = Path(__file__).with_name("eclass_policy.json")

# Ο engine φορτώνεται ΜΙΑ φορά. Αν το αρχείο λείπει ή είναι λάθος: fail-closed (όλα απορρίπτονται).
try:
    _ENGINE: PolicyEngine | None = PolicyEngine.from_file(POLICY_PATH)
except Exception as _e:  # noqa: BLE001
    _ENGINE = None
    print(f"[eclass_policy] CANNOT LOAD {POLICY_PATH}: {_e} -- every call will be denied", file=sys.stderr)

# Εργαλεία που επιστρέφουν περιεχόμενο από άλλους (πιθανό indirect prompt injection) -> taint.
UNTRUSTED_TOOLS = set(_ENGINE.untrusted_tools) if _ENGINE else set()
# Κρίσιμα εργαλεία που αλλάζουν κατάσταση -> έγκριση ανθρώπου όταν η συνομιλία είναι tainted.
HIGH_RISK_TOOLS = set(_ENGINE.high_risk_tools) if _ENGINE else set()


# ---------------------------------------------------------------------------
# Resolver: βοηθητικά ερωτήματα προς τη βάση
# ---------------------------------------------------------------------------

def _is_enrolled(user_id, course_id) -> bool:
    row = query("SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?", (user_id, course_id), one=True)
    return row is not None


def _is_course_teacher(user_id, course_id) -> bool:
    row = query("SELECT 1 FROM courses WHERE id = ? AND teacher_id = ?", (course_id, user_id), one=True)
    return row is not None


def _resolve_course(course_ref) -> dict | None:
    """Λύνει id / κωδικό / τίτλο σε μάθημα. Ό,τι δεν λύνεται δίνει None (=> οι κανόνες απορρίπτουν)."""
    if course_ref is None:
        return None
    try:
        return _find_course(course_ref)
    except Exception:
        return None


def _resolve_user(user_ref) -> dict | None:
    if user_ref is None:
        return None
    try:
        return _find_user(user_ref)
    except Exception:
        return None


class LazyContext:
    """Τα «γεγονότα» ($ctx.*) που χρειάζεται η πολιτική, υπολογισμένα κατά παραγγελία από τη βάση."""

    def __init__(self, user, tool, args):
        self.user = user if isinstance(user, dict) else {}
        self.tool = tool
        self.args = args if isinstance(args, dict) else {}
        self._cache: dict = {}

    def get(self, name):
        if name in self._cache:
            return self._cache[name]
        fn = _ATTRIBUTES.get(name)
        value = fn(self) if fn is not None else None  # άγνωστη ιδιότητα => None => false στους κανόνες
        self._cache[name] = value
        return value

    # --- ένα εσωτερικό cache για «εγγραφές» που μοιράζονται πολλές ιδιότητες
    def _memo(self, key, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def course(self):
        return self._memo("#course", lambda: _resolve_course(self.args.get("course_ref")))

    def assignment_row(self):
        return self._memo("#assignment", lambda: query(
            "SELECT course_id FROM assignments WHERE id = ?", (self.args.get("assignment_id"),), one=True))

    def submission_row(self):
        return self._memo("#submission", lambda: query(
            "SELECT a.course_id FROM submissions s JOIN assignments a ON a.id = s.assignment_id WHERE s.id = ?",
            (self.args.get("submission_id"),), one=True))

    def exercise_row(self):
        def load():
            exercise_id = self.args.get("exercise_id")
            return query("SELECT * FROM exercises WHERE id = ?", (exercise_id,), one=True) if exercise_id else None
        return self._memo("#exercise", load)


def _id_of(record):
    return record["id"] if record else None


def _effective_id(ctx: LazyContext, arg_name: str):
    """Ο στόχος μιας αναφοράς· αν η αναφορά λείπει (ή είναι κενή), ο στόχος είναι ο ίδιος ο χρήστης."""
    ref = ctx.args.get(arg_name)
    target = _resolve_user(ref) if ref else ctx.user
    return _id_of(target)


def _teaches(ctx: LazyContext, course_id) -> bool:
    return course_id is not None and _is_course_teacher(ctx.user["id"], course_id)


def _enrolled(ctx: LazyContext, course_id) -> bool:
    return course_id is not None and _is_enrolled(ctx.user["id"], course_id)


def _row_course_id(row):
    return row["course_id"] if row else None


_ATTRIBUTES = {
    # --- αναφορές σε χρήστες
    "user_ref_id": lambda c: _id_of(_resolve_user(c.args.get("user_ref"))),
    "student_ref_id": lambda c: _id_of(_resolve_user(c.args.get("student_ref"))) if c.args.get("student_ref") else None,
    "effective_student_id": lambda c: _effective_id(c, "student_ref"),
    "effective_user_id": lambda c: _effective_id(c, "user_ref"),
    "effective_sender_id": lambda c: _effective_id(c, "from_user"),
    # --- μάθημα από args.course_ref
    "course_id": lambda c: _id_of(c.course()),
    "is_course_teacher": lambda c: _teaches(c, _id_of(c.course())),
    "is_enrolled": lambda c: _enrolled(c, _id_of(c.course())),
    # --- εργασία / υποβολή
    "assignment_course_id": lambda c: _row_course_id(c.assignment_row()),
    "is_assignment_course_teacher": lambda c: _teaches(c, _row_course_id(c.assignment_row())),
    "is_assignment_course_enrolled": lambda c: _enrolled(c, _row_course_id(c.assignment_row())),
    "submission_course_id": lambda c: _row_course_id(c.submission_row()),
    "is_submission_course_teacher": lambda c: _teaches(c, _row_course_id(c.submission_row())),
    # --- άσκηση
    "exercise_course_id": lambda c: _row_course_id(c.exercise_row()),
    "is_exercise_course_teacher": lambda c: _teaches(c, _row_course_id(c.exercise_row())),
    "is_exercise_course_enrolled": lambda c: _enrolled(c, _row_course_id(c.exercise_row())),
    "exercise_is_open": lambda c: bool(c.exercise_row()["is_open"]) if c.exercise_row() else None,
    # --- για το redaction
    "enrolled_course_ids": lambda c: [r["course_id"] for r in query(
        "SELECT course_id FROM enrollments WHERE user_id = ?", (c.user.get("id"),))],
}


# ---------------------------------------------------------------------------
# Το δημόσιο συμβόλαιο προς τον Guard
# ---------------------------------------------------------------------------

def check(user: dict, tool: str, args: dict, ctx=None) -> Decision:
    """allow ή deny (με reason και rule). Κάθε σφάλμα => deny (fail-closed)."""
    if _ENGINE is None:
        return Decision("deny", reason="internal error", rule="policy.internal_error")
    try:
        args = args or {}
        d = _ENGINE.evaluate(user, tool, args, LazyContext(user, tool, args))
    except Exception:  # noqa: BLE001
        return Decision("deny", reason="internal error", rule="policy.internal_error")
    if d["action"] == "allow":
        return Decision("allow")
    return Decision("deny", reason=d["reason"], rule=d["rule"])


def redact(user: dict, tool: str, args: dict, result):
    """Κρύβει/αφαιρεί ό,τι δεν δικαιούται να δει ο χρήστης. Σφάλμα => κρύβεται όλο το αποτέλεσμα."""
    if _ENGINE is None:
        return "[redacted]"
    try:
        args = args or {}
        return _ENGINE.redact(user, tool, args, result, LazyContext(user, tool, args))
    except Exception:  # noqa: BLE001
        return "[redacted]"
