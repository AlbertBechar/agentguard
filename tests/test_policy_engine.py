"""
tests/test_policy_engine.py
Τεστ του γενικού PolicyEngine (app/policy_engine.py) + βοηθητικά του golden master.

Μέρος 1: βοηθητικά για το golden master (καταγραφή της συμπεριφοράς του ΠΑΛΙΟΥ eclass_policy).
Το baseline ξαναδημιουργείται ΜΟΝΟ όταν το ζητήσουμε ρητά:

    python -m tests.test_policy_engine --regen-baseline

Ο παλιός κώδικας διαβάζεται από το git tag `pre-engine`, ώστε ο νέος κώδικας να μην
μπορεί ποτέ να «μολύνει» το baseline.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = ROOT / "tests" / "policy_baseline.json"
LEGACY_TAG = "pre-engine"

# Χρήστες του seed που παίζουν ρόλο «ηθοποιού» στο golden master
ACTORS = ["admin", "kpapadopoulos", "mgeorgiou", "dnikolaou",
          "sdi2400001", "sdi2400003", "sdi2400008"]

# Εργαλεία ανάγνωσης: για αυτά καταγράφουμε και το redact. (Το fetch_url είναι δίκτυο, το run_sql απαγορεύεται.)
READ_TOOLS = ["list_users", "get_user", "list_courses", "get_course", "read_forum", "list_assignments",
              "get_submissions", "get_grades", "get_gradebook", "list_exercises", "get_exercise",
              "get_exercise_attempts", "read_messages"]


# ---------------------------------------------------------------------------
# Παραλλαγές ορισμάτων ανά εργαλείο ("@self" = το username του ηθοποιού)
# ---------------------------------------------------------------------------

_USER_REFS = ["@self", "sdi2400002", "sdi2400001", "admin", "kpapadopoulos", "no_such_user_xyz"]
_COURSE_REFS = ["CS101", "CS340", "CS220", "MATH110", "NOPE999"]


def _each(key, values, **extra):
    return [dict({key: v}, **extra) for v in values]


def arg_variants(tool: str) -> list[dict]:
    """Επιστρέφει ≥ 3 παραλλαγές ορισμάτων για το εργαλείο (δικός μου στόχος, στόχος άλλου,
    ανύπαρκτη αναφορά, κενά ορίσματα, ειδικά πεδία)."""
    if tool == "run_sql":
        return [{"sql": "SELECT 1"}, {}, {"sql": "DROP TABLE users"}]
    if tool == "fetch_url":
        return [{"url": "http://evil.example"}, {}, {"url": "file:///etc/passwd"}]
    if tool == "list_users":
        return [{}, {"role": "admin"}, {"role": "student"}]
    if tool == "get_user":
        return _each("user_ref", _USER_REFS) + [{}, {"user_ref": ""}, {"user_ref": "1"}]
    if tool == "update_user":
        return [{"user_ref": "@self", "phone": "123"},
                {"user_ref": "@self", "address": "x", "email": "a@b.gr"},
                {"user_ref": "@self", "role": "admin"},
                {"user_ref": "@self", "iban": "GR00"},
                {"user_ref": "@self", "admin_notes": "n"},
                {"user_ref": "@self", "role": None, "phone": "1"},
                {"user_ref": "@self", "unknown_field": "x"},
                {"user_ref": "sdi2400002", "phone": "1"},
                {"user_ref": "sdi2400001", "role": "teacher"},
                {"user_ref": "admin", "phone": "1"},
                {"user_ref": "no_such_user_xyz", "phone": "1"},
                {}]
    if tool == "reset_password":
        return [{"user_ref": "@self", "new_password": "x"}, {"user_ref": "sdi2400002", "new_password": "x"}, {}]
    if tool == "create_user":
        return [{"username": "n1", "password": "p", "full_name": "F", "role": "student"},
                {"username": "n2", "password": "p", "full_name": "F", "role": "admin"}, {}]
    if tool == "delete_user":
        return [{"user_ref": "@self"}, {"user_ref": "sdi2400002"}, {}]
    if tool == "enroll_user":
        return [{"user_ref": "@self", "course_ref": "CS220"}, {"user_ref": "sdi2400002", "course_ref": "CS101"}, {}]
    if tool == "list_courses":
        return [{}, {"unused": "y"}, {"unused": 1}]
    if tool in ("get_course", "read_forum", "list_assignments", "list_exercises"):
        return _each("course_ref", _COURSE_REFS) + [{}]
    if tool == "post_forum":
        return _each("course_ref", _COURSE_REFS, title="t", body="b") + [{}]
    if tool in ("add_material", "post_announcement"):
        return _each("course_ref", _COURSE_REFS, title="t", body="b") + [{}]
    if tool == "get_submissions":
        return _each("assignment_id", [1, 2, 3, 4, 5, 6, 999]) + [{}]
    if tool == "submit_assignment":
        return [{"assignment_id": 1, "content": "c"}, {"assignment_id": 3, "content": "c"},
                {"assignment_id": 5, "content": "c"}, {"assignment_id": 6, "content": "c"},
                {"assignment_id": 999, "content": "c"},
                {"assignment_id": 1, "content": "c", "student_ref": "@self"},
                {"assignment_id": 1, "content": "c", "student_ref": "sdi2400002"},
                {"assignment_id": 1, "content": "c", "student_ref": "no_such_user_xyz"},
                {"assignment_id": 1, "content": "c", "student_ref": ""}, {}]
    if tool == "grade_submission":
        return _each("submission_id", [1, 2, 3, 4, 9999], grade=10) + [{}]
    if tool == "get_grades":
        return ([{}, {"student_ref": ""}] + _each("student_ref", _USER_REFS) +
                _each("course_ref", _COURSE_REFS) + [{"student_ref": "@self", "course_ref": "CS340"}])
    if tool in ("set_final_grade", "set_component_grade"):
        extra = {"component": "Midterm"} if tool == "set_component_grade" else {}
        return (_each("course_ref", _COURSE_REFS, student_ref="sdi2400001", grade=10, **extra) +
                [{"student_ref": "sdi2400001", "grade": 10}, {}])
    if tool == "publish_grades":
        return _each("course_ref", _COURSE_REFS) + [{"course_ref": "CS101", "component": "Midterm"}, {}]
    if tool == "get_gradebook":
        return _each("course_ref", _COURSE_REFS) + [{}]
    if tool in ("get_exercise", "get_exercise_attempts"):
        return _each("exercise_id", [1, 2, 3, 4, 9999]) + [{}]
    if tool == "submit_exercise":
        return ([{"exercise_id": 1, "answers": "{}"}, {"exercise_id": 2, "answers": "{}"},
                 {"exercise_id": 3, "answers": "{}"}, {"exercise_id": 9999, "answers": "{}"},
                 {"exercise_id": 1, "answers": "{}", "student_ref": "@self"},
                 {"exercise_id": 1, "answers": "{}", "student_ref": "sdi2400002"},
                 {"exercise_id": 1, "answers": "{}", "student_ref": "no_such_user_xyz"}, {}])
    if tool == "read_messages":
        return [{}, {"user_ref": ""}] + _each("user_ref", _USER_REFS)
    if tool == "send_message":
        return ([{"to": "sdi2400002", "subject": "s", "body": "b"}, {}] +
                _each("from_user", ["@self", "admin", "no_such_user_xyz", ""], to="sdi2400002", subject="s", body="b"))
    raise KeyError(tool)


def _expand(args: dict, username: str) -> dict:
    return {k: (username if v == "@self" else v) for k, v in args.items()}


# ---------------------------------------------------------------------------
# Κανονικοποίηση + digest αποτελέσματος
# ---------------------------------------------------------------------------

def _normalize(obj):
    """Μασκάρει τις χρονοσφραγίδες (πεδία *_at: αλλάζουν σε κάθε seed) ώστε το digest να είναι σταθερό."""
    if isinstance(obj, dict):
        return {k: ("<ts>" if str(k).endswith("_at") and v is not None else _normalize(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize(x) for x in obj]
    return obj


def result_digest(obj) -> str:
    text = json.dumps(_normalize(obj), sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalized_json(obj) -> str:
    return json.dumps(_normalize(obj), sort_keys=True, ensure_ascii=False, default=str, indent=1)


# ---------------------------------------------------------------------------
# Φρέσκια seeded βάση σε προσωρινό αρχείο (δεν αγγίζει το test.db των άλλων)
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def fresh_seeded_db():
    """Δίνει (users_by_username) πάνω σε νέα seeded βάση και μέσα σε Flask app context."""
    from flask import Flask
    import app.db as dbmod
    from app.seed import seed

    old_path = dbmod.DB_PATH
    with tempfile.TemporaryDirectory() as tmp:
        dbmod.DB_PATH = os.path.join(tmp, "golden.db")
        try:
            conn = dbmod.connect()
            seed(conn)
            conn.close()
            with Flask("golden_master").app_context():
                users = {u["username"]: u for u in dbmod.query("SELECT * FROM users")}
                yield users
        finally:
            dbmod.DB_PATH = old_path


def build_records(policy_module, users: dict) -> list[dict]:
    """Τρέχει check (και redact για εργαλεία ανάγνωσης) του policy_module για όλους τους συνδυασμούς."""
    from app.tools import FUNCTIONS

    records = []
    for actor in ACTORS:
        user = users[actor]
        for tool in sorted(FUNCTIONS):
            for raw in arg_variants(tool):
                args = _expand(raw, actor)
                d = policy_module.check(user, tool, dict(args), None)
                rec = {"user": actor, "tool": tool, "args": args,
                       "check": {"action": d.action, "rule": d.rule}}
                # Το redact εφαρμόζεται από τον Guard ΜΟΝΟ μετά από allow, άρα μόνο εκεί έχει νόημα.
                if tool in READ_TOOLS and d.action == "allow":
                    try:
                        result = FUNCTIONS[tool](user, **args)
                    except Exception as e:  # όπως το call_tool: το σφάλμα γίνεται αποτέλεσμα
                        result = {"error": f"{type(e).__name__}: {e}"}
                    rec["redact_sha256"] = result_digest(policy_module.redact(user, tool, dict(args), result))
                records.append(rec)
    return records


def load_legacy_policy():
    """Φορτώνει τον ΠΑΛΙΟ eclass_policy.py από το git tag (όχι από το δίσκο)."""
    src = subprocess.run(["git", "show", f"{LEGACY_TAG}:app/eclass_policy.py"], cwd=str(ROOT),
                         capture_output=True, check=True).stdout.decode("utf-8")
    mod = types.ModuleType("legacy_eclass_policy")
    exec(compile(src, "legacy_eclass_policy.py", "exec"), mod.__dict__)  # noqa: S102 (δικός μας κώδικας από git)
    return mod


def write_baseline(records: list[dict], path: Path = BASELINE_PATH) -> None:
    doc = {"about": "Golden master: τι έκανε ο ΠΑΛΙΟΣ eclass_policy (tag pre-engine). "
                    "Δημιουργείται με: python -m tests.test_policy_engine --regen-baseline",
           "records": records}
    text = json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=False) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def regen_baseline() -> int:
    legacy = load_legacy_policy()
    with fresh_seeded_db() as users:
        records = build_records(legacy, users)
    write_baseline(records)
    n_red = sum(1 for r in records if "redact_sha256" in r)
    print(f"[OK] baseline: {len(records)} εγγραφές ({n_red} με redact) -> {BASELINE_PATH}")
    return 0


# === ΤΕΛΟΣ ΜΕΡΟΥΣ 1 ===========================================================
# Μέρος 2: τεστ του γενικού μηχανισμού. Η πολιτική εδώ είναι ΤΡΑΠΕΖΑ (όχι eClass),
# για να αποδεικνύεται ότι ο μηχανισμός δεν εξαρτάται από καμία εφαρμογή.
# ===============================================================================

import copy  # noqa: E402
import unittest  # noqa: E402

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.policy_engine import (  # noqa: E402
    SCHEMA, PolicyEngine, _apply_op, validate_policy,
)

_ACC_TOOLS = ["get_account", "list_transactions", "get_statement"]


def _c(left, op, right=None, **_):
    d = {"left": left, "op": op}
    if op not in ("is_true", "is_false", "exists", "not_exists"):
        d["right"] = right
    return d


BANK = {
    "schema": SCHEMA, "app": "demobank", "default_action": "deny",
    "meta": {"context_attributes": {
        "account_owner_id": "ιδιοκτήτης του args.account_id",
        "from_account_owner_id": "ιδιοκτήτης του args.from_account",
        "ticket_customer_id": "πελάτης του args.ticket_id"}},
    "roles": ["customer", "teller", "admin"],
    "untrusted_tools": ["read_support_ticket", "list_transactions"],
    "high_risk_tools": ["transfer_funds", "close_account", "send_email", "update_contact"],
    "rules": [
        {"id": "never.sql_url", "tools": ["run_sql", "fetch_url"], "roles": ["*"], "effect": "deny",
         "reason": "disabled for the chatbot"},
        {"id": "transfer.hard_limit", "tools": ["transfer_funds"], "roles": ["*"], "effect": "deny",
         "when": [_c("$args.amount", "gt", 10000)], "reason": "above the absolute limit"},
        {"id": "account.read.owner", "tools": _ACC_TOOLS, "roles": ["customer"], "effect": "allow",
         "when": [_c("$ctx.account_owner_id", "equals", "$user.id")], "reason": "own accounts only"},
        {"id": "account.read.staff", "tools": _ACC_TOOLS, "roles": ["teller", "admin"], "effect": "allow"},
        {"id": "transfer.customer", "tools": ["transfer_funds"], "roles": ["customer"], "effect": "allow",
         "when": [_c("$args.amount", "lte", 1000), _c("$ctx.from_account_owner_id", "equals", "$user.id")]},
        {"id": "transfer.admin", "tools": ["transfer_funds"], "roles": ["admin"], "effect": "allow",
         "when": [_c("$args.amount", "lte", 10000)]},
        {"id": "contact.self", "tools": ["update_contact"], "roles": ["customer"], "effect": "allow",
         "when": [_c("$args.customer_id", "equals", "$user.id"),
                  _c("$args_keys", "subset_of", ["customer_id", "email", "phone"])]},
        {"id": "email.staff", "tools": ["send_email"], "roles": ["teller", "admin"], "effect": "allow"},
        {"id": "close.admin", "tools": ["close_account"], "roles": ["admin"], "effect": "allow"},
        {"id": "ticket.owner", "tools": ["read_support_ticket"], "roles": ["customer"], "effect": "allow",
         "when": [_c("$ctx.ticket_customer_id", "equals", "$user.id")]},
        {"id": "ticket.staff", "tools": ["read_support_ticket"], "roles": ["teller", "admin"], "effect": "allow"},
    ],
    "redaction_rules": {
        "always_redact_fields": ["card_number"],
        "restricted_fields": [
            {"id": "email.owner_or_admin", "fields": ["email"],
             "visible_if": [[_c("$user.role", "equals", "admin")],
                            [_c("$row.customer_id", "equals", "$user.id")]]},
            {"id": "iban.owner_or_staff", "fields": ["iban"],
             "visible_if": [[_c("$user.role", "in", ["teller", "admin"])],
                            [_c("$row.owner_id", "equals", "$user.id")]]},
        ],
        "row_filters": [
            {"id": "tx.only_own", "tools": ["list_transactions"], "roles": ["customer"], "result_path": None,
             "drop_if": [[_c("$item.customer_id", "not_equals", "$user.id")]]},
            {"id": "statement.nested", "tools": ["get_statement"], "roles": ["customer"],
             "result_path": "data.transactions",
             "drop_if": [[_c("$item.customer_id", "not_equals", "$user.id")]]},
            {"id": "account.single", "tools": ["get_account"], "roles": ["customer"], "result_path": None,
             "drop_if": [[_c("$item.owner_id", "not_equals", "$user.id")]]},
        ],
    },
}

C1 = {"id": "c1", "role": "customer"}
C2 = {"id": "c2", "role": "customer"}
T1 = {"id": "t1", "role": "teller"}
A1 = {"id": "a1", "role": "admin"}


class CountingContext:
    """Lazy context που μετρά ποιες ιδιότητες ζητήθηκαν."""

    def __init__(self, data):
        self.data, self.calls = data, []

    def get(self, name):
        self.calls.append(name)
        return self.data.get(name)


class EvaluateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = PolicyEngine(BANK)

    def ev(self, user, tool, args=None, ctx=None):
        return self.engine.evaluate(user, tool, args or {}, ctx or {})

    def test_decision_table(self):
        cases = [
            # (user, tool, args, ctx, expected action, expected rule)
            (C1, "get_account", {"account_id": "A1"}, {"account_owner_id": "c1"}, "allow", "account.read.owner"),
            (C1, "get_account", {"account_id": "A2"}, {"account_owner_id": "c2"}, "deny", "default"),
            (T1, "get_account", {"account_id": "A2"}, {"account_owner_id": "c2"}, "allow", "account.read.staff"),
            (A1, "list_transactions", {}, {}, "allow", "account.read.staff"),
            (C1, "get_statement", {}, {"account_owner_id": "c1"}, "allow", "account.read.owner"),
            (C1, "transfer_funds", {"amount": 500}, {"from_account_owner_id": "c1"}, "allow", "transfer.customer"),
            (C1, "transfer_funds", {"amount": 1000}, {"from_account_owner_id": "c1"}, "allow", "transfer.customer"),
            (C1, "transfer_funds", {"amount": 1000.01}, {"from_account_owner_id": "c1"}, "deny", "default"),
            (C1, "transfer_funds", {"amount": "500"}, {"from_account_owner_id": "c1"}, "allow", "transfer.customer"),
            (C1, "transfer_funds", {"amount": "abc"}, {"from_account_owner_id": "c1"}, "deny", "default"),
            (C1, "transfer_funds", {"amount": 5}, {"from_account_owner_id": "c2"}, "deny", "default"),
            (C1, "transfer_funds", {}, {"from_account_owner_id": "c1"}, "deny", "default"),
            (A1, "transfer_funds", {"amount": 9000}, {}, "allow", "transfer.admin"),
            (A1, "transfer_funds", {"amount": 10001}, {}, "deny", "transfer.hard_limit"),
            (T1, "transfer_funds", {"amount": 1}, {}, "deny", "default"),
            (A1, "close_account", {}, {}, "allow", "close.admin"),
            (T1, "close_account", {}, {}, "deny", "default"),
            (C1, "close_account", {}, {}, "deny", "default"),
            (T1, "send_email", {}, {}, "allow", "email.staff"),
            (C1, "send_email", {}, {}, "deny", "default"),
            (C1, "update_contact", {"customer_id": "c1", "email": "x@y.gr"}, {}, "allow", "contact.self"),
            (C1, "update_contact", {"customer_id": "c1", "role": "admin"}, {}, "deny", "default"),
            (C1, "update_contact", {"customer_id": "c2", "phone": "1"}, {}, "deny", "default"),
            (C1, "update_contact", {"customer_id": "c1", "phone": None, "email": "a"}, {}, "allow", "contact.self"),
            (C1, "read_support_ticket", {}, {"ticket_customer_id": "c1"}, "allow", "ticket.owner"),
            (C2, "read_support_ticket", {}, {"ticket_customer_id": "c1"}, "deny", "default"),
            (A1, "run_sql", {"query": "x"}, {}, "deny", "never.sql_url"),
            (T1, "fetch_url", {"url": "http://x"}, {}, "deny", "never.sql_url"),
            (C1, "get_account", {}, {}, "deny", "default"),  # γεγονός που λείπει => None => false => deny
        ]
        for user, tool, args, ctx, action, rule in cases:
            with self.subTest(user=user["id"], tool=tool, args=args, ctx=ctx):
                d = self.ev(user, tool, args, ctx)
                self.assertEqual((d["action"], d["rule"]), (action, rule))

    def test_deny_overrides_allow(self):
        # ο admin έχει allow για ποσό ≤ 10000 αλλά το hard_limit (deny) νικά πάντα
        d = self.ev(A1, "transfer_funds", {"amount": 20000})
        self.assertEqual((d["action"], d["rule"]), ("deny", "transfer.hard_limit"))
        self.assertEqual(d["reason"], "above the absolute limit")

    def test_unknown_tool_role_and_user(self):
        self.assertEqual(self.ev(C1, "drop_database")["rule"], "security.unknown_tool")
        self.assertEqual(self.ev({"id": "x", "role": "hacker"}, "get_account")["rule"], "security.unknown_role")
        self.assertEqual(self.ev({"role": "admin"}, "get_account")["rule"], "security.invalid_user")
        self.assertEqual(self.ev(None, "get_account")["rule"], "security.invalid_user")
        self.assertEqual(self.ev(A1, "get_account", None)["action"], "allow")  # args=None => {}
        self.assertEqual(self.engine.evaluate(A1, "get_account", "not-a-dict", {})["rule"], "security.invalid_args")

    def test_explain_lists_matched_rules(self):
        e = self.engine.explain(A1, "transfer_funds", {"amount": 20000}, {})
        self.assertEqual(e["action"], "deny")
        self.assertEqual(e["matched_rules"], ["transfer.hard_limit"])
        e2 = self.engine.explain(T1, "get_account", {}, {})
        self.assertEqual(e2["matched_rules"], ["account.read.staff"])
        e3 = self.engine.explain(C1, "get_account", {}, {})
        self.assertEqual((e3["action"], e3["matched_rules"]), ("deny", []))

    def test_any_of_not_and_default_allow_warning(self):
        p = copy.deepcopy(BANK)
        p["rules"].append({"id": "x.any", "tools": ["send_email"], "roles": ["customer"], "effect": "allow",
                           "when": [{"any_of": [[_c("$user.id", "equals", "c9")],
                                                [_c("$args.vip", "is_true"), {"not": _c("$args.blocked", "is_true")}]]}]})
        e = PolicyEngine(p)
        ok = lambda u, a: e.evaluate(u, "send_email", a, {})["action"]  # noqa: E731
        self.assertEqual(ok({"id": "c9", "role": "customer"}, {}), "allow")           # πρώτη ομάδα
        self.assertEqual(ok(C1, {"vip": True}), "allow")                              # δεύτερη ομάδα, not(None=false)=true
        self.assertEqual(ok(C1, {"vip": True, "blocked": True}), "deny")              # not(true)=false
        self.assertEqual(ok(C1, {"vip": False}), "deny")
        self.assertEqual(ok(C1, {}), "deny")

    def test_lazy_context_only_asks_what_it_needs(self):
        ctx = CountingContext({"account_owner_id": "c1", "from_account_owner_id": "c1"})
        self.engine.evaluate(C1, "get_account", {}, ctx)
        self.assertEqual(ctx.calls, ["account_owner_id"])           # τίποτα άλλο
        ctx = CountingContext({"from_account_owner_id": "c2"})
        self.engine.evaluate(C1, "transfer_funds", {"amount": 5000}, ctx)  # αποτυγχάνει στο amount: δεν ρωτά το context
        self.assertEqual(ctx.calls, [])
        ctx = CountingContext({})
        self.engine.evaluate(T1, "send_email", {}, ctx)             # κανόνας χωρίς when => καμία ερώτηση
        self.assertEqual(ctx.calls, [])

    def test_context_errors_fail_closed(self):
        class Boom:
            def get(self, name):
                raise RuntimeError("db down")
        d = self.engine.evaluate(C1, "get_account", {}, Boom())
        self.assertEqual((d["action"], d["rule"]), ("deny", "policy.internal_error"))


class OperatorTests(unittest.TestCase):
    def test_operator_table(self):
        cases = [
            ("equals", 7, "7", True), ("equals", "7", 7, True), ("equals", True, 1, True), ("equals", 7.0, 7, True),
            ("equals", "a", "b", False), ("equals", None, None, False), ("equals", None, "a", False),
            ("not_equals", 1, 2, True), ("not_equals", 1, "1", False), ("not_equals", None, 1, False),
            ("not_equals", 1, None, False),
            ("in", 2, [1, 2], True), ("in", "2", [1, 2], True), ("in", 3, [1, 2], False), ("in", None, [1], False),
            ("in", 1, None, False), ("in", 1, "notalist", False),
            ("not_in", 3, [1, 2], True), ("not_in", 1, [1, 2], False), ("not_in", None, [1], False),
            ("not_in", 1, None, False), ("not_in", 1, [], True),
            ("subset_of", ["a"], ["a", "b"], True), ("subset_of", [], ["a"], True), ("subset_of", ["c"], ["a"], False),
            ("subset_of", None, ["a"], False), ("subset_of", ["a"], None, False), ("subset_of", "a", ["a"], False),
            ("contains", ["a", "b"], "a", True), ("contains", "hello", "ell", True), ("contains", "hello", "z", False),
            ("contains", None, "a", False), ("contains", {"k": 1}, "k", True), ("contains", 5, 5, False),
            ("lt", 1, 2, True), ("lt", 2, 2, False), ("lte", 2, 2, True), ("gt", 3, 2, True), ("gt", "3", "2", True),
            ("gte", 2, 2, True), ("lt", "abc", 2, False), ("lt", True, 2, False), ("gt", 2, False, False),
            ("lt", None, 2, False), ("gte", 2, None, False), ("lt", "1e400", 2, False), ("gt", "nan", 1, False),
            ("is_true", True, None, True), ("is_true", 1, None, True), ("is_true", "true", None, True),
            ("is_true", False, None, False), ("is_true", None, None, False), ("is_true", "yes", None, False),
            ("is_false", False, None, True), ("is_false", 0, None, True), ("is_false", "false", None, True),
            ("is_false", True, None, False), ("is_false", None, None, False),
            ("exists", 0, None, True), ("exists", "", None, True), ("exists", None, None, False),
            ("not_exists", None, None, True), ("not_exists", 0, None, False),
        ]
        for op, a, b, expected in cases:
            with self.subTest(op=op, a=a, b=b):
                self.assertIs(_apply_op(op, a, b), expected)

    def test_none_makes_every_operator_false_except_not_exists(self):
        for op in ("equals", "not_equals", "in", "not_in", "subset_of", "contains", "lt", "lte", "gt", "gte",
                   "is_true", "is_false", "exists"):
            with self.subTest(op=op):
                self.assertFalse(_apply_op(op, None, None))
        self.assertTrue(_apply_op("not_exists", None, None))

    def test_dollar_escape_and_unknown_reference(self):
        p = {"schema": SCHEMA, "roles": ["r"], "untrusted_tools": ["t"], "rules": [
            {"id": "lit", "tools": ["t"], "roles": ["r"], "effect": "allow",
             "when": [_c("$args.x", "equals", "$$price")]}]}
        e = PolicyEngine(p)
        self.assertEqual(e.evaluate({"id": 1, "role": "r"}, "t", {"x": "$price"}, {})["action"], "allow")
        self.assertEqual(e.evaluate({"id": 1, "role": "r"}, "t", {"x": "price"}, {})["action"], "deny")

    def test_never_uses_eval(self):
        import ast
        tree = ast.parse((ROOT / "app" / "policy_engine.py").read_text(encoding="utf-8"))
        called = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        for bad in ("eval", "exec", "compile", "__import__", "open_code"):
            self.assertNotIn(bad, called)  # ο μηχανισμός δεν εκτελεί ποτέ κώδικα από την πολιτική


class RedactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = PolicyEngine(BANK)

    def rd(self, user, tool, result, ctx=None):
        return self.engine.redact(user, tool, {}, result, ctx or {})

    ACCOUNT = {"id": "A1", "owner_id": "c1", "iban": "GR00", "balance": 10, "card_number": "4111"}

    def test_card_number_always_hidden(self):
        for u in (C1, T1, A1):
            with self.subTest(role=u["role"]):
                self.assertEqual(self.rd(u, "get_account", dict(self.ACCOUNT))["card_number"], "[redacted]")

    def test_iban_owner_or_staff(self):
        self.assertEqual(self.rd(C1, "get_account", dict(self.ACCOUNT))["iban"], "GR00")
        self.assertEqual(self.rd(T1, "get_account", dict(self.ACCOUNT))["iban"], "GR00")
        self.assertEqual(self.rd(C2, "get_account", dict(self.ACCOUNT)), {"error": "not found"})  # row filter

    def test_email_only_owner_or_admin(self):
        row = {"customer_id": "c1", "email": "a@b.gr"}
        self.assertEqual(self.rd(C1, "get_customer", dict(row))["email"], "a@b.gr")
        self.assertEqual(self.rd(A1, "get_customer", dict(row))["email"], "a@b.gr")
        self.assertEqual(self.rd(T1, "get_customer", dict(row))["email"], "[redacted]")
        self.assertEqual(self.rd(C2, "get_customer", dict(row))["email"], "[redacted]")

    def test_row_filter_drops_other_customers_transactions(self):
        txs = [{"id": 1, "customer_id": "c1"}, {"id": 2, "customer_id": "c2"}, {"id": 3, "customer_id": "c1"}]
        self.assertEqual([t["id"] for t in self.rd(C1, "list_transactions", txs)], [1, 3])
        self.assertEqual(len(self.rd(T1, "list_transactions", txs)), 3)  # ο teller δεν φιλτράρεται

    def test_row_filter_nested_result_path(self):
        res = {"data": {"transactions": [{"customer_id": "c1"}, {"customer_id": "c2"}], "month": "05"}}
        out = self.rd(C1, "get_statement", res)
        self.assertEqual(out["data"]["transactions"], [{"customer_id": "c1"}])
        self.assertEqual(out["data"]["month"], "05")
        self.assertEqual(len(res["data"]["transactions"]), 2)  # το πρωτότυπο δεν αλλοιώνεται

    def test_missing_result_path_is_harmless(self):
        self.assertEqual(self.rd(C1, "get_statement", {"other": [1]}), {"other": [1]})
        self.assertEqual(self.rd(C1, "get_statement", {"data": "text"}), {"data": "text"})

    def test_single_dict_matching_drop_becomes_not_found(self):
        self.assertEqual(self.rd(C1, "get_account", {"id": "A2", "owner_id": "c2"}), {"error": "not found"})

    def test_weird_shapes_do_not_crash(self):
        for weird in (None, 5, 2.5, True, "text", [], {}, [None, 1, [[{"iban": "x"}]]], {"a": None}, ()):
            with self.subTest(weird=weird):
                self.rd(C1, "list_transactions", weird)
        self.assertIsNone(self.rd(C1, "get_account", None))
        self.assertEqual(self.rd(C1, "get_account", "plain"), "plain")

    def test_nested_and_case_insensitive_hiding(self):
        res = {"accounts": [{"Card_Number": "1", "x": {"card_number": "2", "owner_id": "c9", "iban": "GR"}}]}
        out = self.rd(T1, "anything", res)
        self.assertEqual(out["accounts"][0]["Card_Number"], "[redacted]")
        self.assertEqual(out["accounts"][0]["x"]["card_number"], "[redacted]")
        self.assertEqual(out["accounts"][0]["x"]["iban"], "GR")  # ο teller βλέπει IBAN

    def test_hidden_even_when_value_is_none(self):
        self.assertEqual(self.rd(C1, "get_account", {"owner_id": "c1", "card_number": None})["card_number"], "[redacted]")

    def test_nested_lists_inside_lists_are_walked(self):
        out = self.rd(C1, "x", [[{"card_number": "9"}]])
        self.assertEqual(out, [[{"card_number": "[redacted]"}]])

    def test_failure_hides_everything(self):
        class Boom:
            def get(self, name):
                raise RuntimeError("x")
        p = _mini(redaction_rules={"row_filters": [
            {"tools": ["t"], "result_path": None, "drop_if": [[_c("$item.owner", "not_in", "$ctx.mine")]]}]})
        out = PolicyEngine(p).redact({"id": 1, "role": "a"}, "t", {}, [{"owner": 1}], Boom())
        self.assertEqual(out, "[redacted]")                       # σφάλμα στον resolver => κρύβεται όλο
        self.assertEqual(PolicyEngine(p).redact({"id": 1, "role": "a"}, "t", {}, [{"owner": 1}], {"mine": [2]}),
                         [])                                       # κανονική λειτουργία: το στοιχείο αφαιρείται

    def test_too_deep_result_fails_closed(self):
        deep = cur = {}
        for _ in range(400):
            cur["x"] = {}
            cur = cur["x"]
        self.assertEqual(self.rd(C1, "get_account", deep), "[redacted]")

    def test_tools_and_roles_scoping_of_filters(self):
        txs = [{"customer_id": "c2"}]
        self.assertEqual(self.rd(C1, "list_transactions", txs), [])
        self.assertEqual(self.rd(C1, "some_other_tool", txs), txs)   # φίλτρο μόνο για list_transactions

    def test_input_not_mutated(self):
        res = [{"id": 1, "customer_id": "c2", "card_number": "1"}]
        snapshot = copy.deepcopy(res)
        self.rd(C1, "list_transactions", res)
        self.assertEqual(res, snapshot)


def _mini(**over):
    p = {"schema": SCHEMA, "roles": ["a", "b"], "untrusted_tools": ["t"],
         "rules": [{"id": "r1", "tools": ["t"], "roles": ["a"], "effect": "allow"}]}
    p.update(over)
    return p


def _find(issues, level, path_part):
    return [i for i in issues if i["level"] == level and path_part in i["path"]]


class ValidateTests(unittest.TestCase):
    def test_valid_bank_policy_has_no_errors(self):
        self.assertEqual([i for i in validate_policy(BANK) if i["level"] == "error"], [])

    def test_errors_with_correct_paths(self):
        cases = [
            (_mini(schema="x/9"), "schema"),
            ({"schema": SCHEMA, "rules": []}, "roles"),
            ({"schema": SCHEMA, "roles": ["a"]}, "rules"),
            (_mini(rules=[{"id": "r", "tools": ["t"], "effect": "maybe"}]), "rules[0].effect"),
            (_mini(rules=[{"id": "r", "tools": ["t"], "effect": "allow",
                           "when": [{"left": "$user.id", "op": "same", "right": 1}]}]), "rules[0].when[0].op"),
            (_mini(rules=[{"id": "r", "tools": ["t"], "roles": ["ghost"], "effect": "allow"}]), "rules[0].roles"),
            (_mini(rules=[{"id": "r", "tools": ["t"], "effect": "allow",
                           "when": [{"left": "$foo.id", "op": "equals", "right": 1}]}]), "rules[0].when[0].left"),
            (_mini(rules=[{"id": "r", "tools": ["t"], "effect": "allow",
                           "when": [{"left": "$user.id", "op": "equals"}]}]), "rules[0].when[0].right"),
            (_mini(rules=[{"id": "r", "tools": ["t"], "effect": "allow", "when": "oops"}]), "rules[0].when"),
            (_mini(rules=[{"id": "r", "effect": "allow"}]), "rules[0].tools"),
            (_mini(rules=[{"tools": ["t"], "effect": "allow"}]), "rules[0].id"),
            (_mini(rules=[{"id": "r", "tools": ["t"], "effect": "allow",
                           "when": [{"left": "$row.id", "op": "exists"}]}]), "rules[0].when[0].left"),
            (_mini(redaction_rules={"restricted_fields": [{"fields": ["x"], "visible_if": [{"left": 1}]}]}),
             "redaction_rules.restricted_fields[0].visible_if"),
            (_mini(redaction_rules={"row_filters": [{"result_path": 5, "drop_if": []}]}),
             "redaction_rules.row_filters[0].result_path"),
            (_mini(redaction_rules={"row_filters": [{"drop_if": [[{"left": "$row.x", "op": "exists"}]]}]}),
             "redaction_rules.row_filters[0].drop_if[0][0].left"),
            (_mini(default_action="maybe"), "default_action"),
            (_mini(roles=["a", "a"]), "roles"),
            (_mini(rules=[{"id": "r", "tools": ["t"], "effect": "allow",
                           "when": [{"any_of": [{"left": 1}]}]}]), "rules[0].when[0].any_of"),
            ("not a dict", ""),
        ]
        for policy, path in cases:
            with self.subTest(path=path):
                self.assertTrue(_find(validate_policy(policy), "error", path),
                                f"δεν βρέθηκε error στο {path}: {validate_policy(policy)}")
                with self.assertRaises(ValueError):
                    PolicyEngine(policy) if isinstance(policy, dict) else (_ for _ in ()).throw(ValueError())

    def test_warnings(self):
        w = validate_policy(_mini(untrusted_tools=[], high_risk_tools=["t", "zzz"]))
        self.assertTrue(_find(w, "warning", "untrusted_tools"))
        self.assertTrue(any("zzz" in i["message"] for i in w))
        dup = _mini(rules=[{"id": "r", "tools": ["t"], "roles": ["a"], "effect": "allow"},
                           {"id": "r", "tools": ["t"], "roles": ["b"], "effect": "deny"}])
        self.assertTrue(_find(validate_policy(dup), "warning", "rules[1].id"))
        risky = _mini(high_risk_tools=["t"], rules=[{"id": "r", "tools": ["t"], "roles": ["*"], "effect": "allow"}])
        self.assertTrue(_find(validate_policy(risky), "warning", "rules[0]"))
        no_allow = _mini(high_risk_tools=["t"], rules=[{"id": "r", "tools": ["t"], "roles": ["a"], "effect": "deny"}])
        self.assertTrue(_find(validate_policy(no_allow), "warning", "high_risk_tools"))
        undeclared = _mini(rules=[{"id": "r", "tools": ["t"], "effect": "allow",
                                   "when": [_c("$ctx.mystery", "exists")]}])
        self.assertTrue(any("mystery" in i["message"] for i in validate_policy(undeclared)))
        self.assertTrue(_find(validate_policy(_mini(default_action="allow")), "warning", "default_action"))
        unknown_tool_in_redaction = _mini(redaction_rules={"always_redact_fields": ["x"], "row_filters": [
            {"tools": ["ghost_tool"], "result_path": None, "drop_if": [[_c("$item.a", "exists")]]}]})
        self.assertTrue(any("ghost_tool" in i["message"] for i in validate_policy(unknown_tool_in_redaction)))

    def test_clean_policy_has_no_issues(self):
        self.assertEqual(validate_policy(_mini()), [])


def _lk(sql, params=None, returns="scalar"):
    return _mini(lookups={"owner": {"description": "d", "sql": sql, "params": params or {}, "returns": returns}},
                 rules=[{"id": "r1", "tools": ["t"], "roles": ["a"], "effect": "allow",
                         "when": [_c("$ctx.owner", "exists")]}])


GOOD_SQL = "SELECT owner_id FROM accounts WHERE id = :account_id"
GOOD_PARAMS = {"account_id": "$args.account_id"}


class LookupValidationTests(unittest.TestCase):
    def errors(self, policy):
        return [i for i in validate_policy(policy) if i["level"] == "error"]

    def test_valid_lookup(self):
        self.assertEqual(self.errors(_lk(GOOD_SQL, GOOD_PARAMS)), [])

    def test_update_time_column_is_not_a_false_positive(self):
        sql = "SELECT update_time FROM accounts WHERE id = :account_id"
        self.assertEqual(self.errors(_lk(sql, GOOD_PARAMS)), [])
        self.assertEqual(self.errors(_lk("SELECT created_at, replaced_by FROM t WHERE id = :account_id", GOOD_PARAMS)), [])

    def test_forbidden_constructs(self):
        bad = {
            "semicolon": "SELECT 1 FROM a WHERE id = :account_id;",
            "two statements": "SELECT 1 FROM a WHERE id = :account_id; SELECT 2",
            "drop": "SELECT 1 FROM a WHERE id = :account_id UNION SELECT 1 FROM x -- ",
            "DROP word": "SELECT drop FROM a WHERE id = :account_id",
            "update word": "SELECT 1 FROM a WHERE id = :account_id AND UPDATE = 1",
            "attach": "SELECT 1 FROM a WHERE id = :account_id AND attach = 1",
            "dash comment": "SELECT 1 FROM a WHERE id = :account_id --",
            "block comment": "SELECT 1 FROM a /* x */ WHERE id = :account_id",
            "question mark": "SELECT 1 FROM a WHERE id = ?",
            "percent s": "SELECT 1 FROM a WHERE id = %s",
            "dollar one": "SELECT 1 FROM a WHERE id = $1",
            "not select": "DELETE FROM a WHERE id = :account_id",
            "pragma": "PRAGMA table_info(a)",
            "empty": "   ",
        }
        for name, sql in bad.items():
            with self.subTest(name=name):
                self.assertTrue(self.errors(_lk(sql, GOOD_PARAMS)), name)

    def test_param_placeholder_mismatch(self):
        self.assertTrue(_find(validate_policy(_lk(GOOD_SQL, {})), "error", "lookups.owner.sql"))          # placeholder χωρίς param
        self.assertTrue(_find(validate_policy(_lk(GOOD_SQL, dict(GOOD_PARAMS, extra="$args.x"))), "error",
                              "lookups.owner.params.extra"))                                              # param χωρίς placeholder

    def test_bad_returns_and_bad_references(self):
        self.assertTrue(_find(validate_policy(_lk(GOOD_SQL, GOOD_PARAMS, returns="all")), "error", "returns"))
        for ref in ("$ctx.x", "$row.id", "constant", "$args.a.b", "$args_keys"):
            with self.subTest(ref=ref):
                self.assertTrue(_find(validate_policy(_lk(GOOD_SQL, {"account_id": ref})), "error", "params.account_id"))
        self.assertEqual(self.errors(_lk(GOOD_SQL, {"account_id": "$user.account"})), [])

    def test_unused_lookup_warns_and_strings_do_not_hide_placeholders(self):
        unused = _mini(lookups={"orphan": {"sql": GOOD_SQL, "params": GOOD_PARAMS, "returns": "scalar"}})
        self.assertTrue(_find(validate_policy(unused), "warning", "lookups.orphan"))
        sql = "SELECT 1 FROM a WHERE id = :account_id AND t = 'a:b'"
        self.assertEqual(self.errors(_lk(sql, GOOD_PARAMS)), [])

    def test_engine_does_not_execute_sql(self):
        # ο μηχανισμός δεν έχει καμία σύνδεση με βάση: ένα lookup απλώς επικυρώνεται
        e = PolicyEngine(_lk(GOOD_SQL, GOOD_PARAMS))
        self.assertEqual(e.evaluate({"id": 1, "role": "a"}, "t", {}, {"owner": 5})["action"], "allow")
        self.assertEqual(e.evaluate({"id": 1, "role": "a"}, "t", {}, {})["action"], "deny")


class MatrixTests(unittest.TestCase):
    def test_matrix_known_result(self):
        p = {"schema": SCHEMA, "roles": ["r1", "r2", "r3"], "untrusted_tools": ["u_only"], "rules": [
            {"id": "a", "tools": ["open_tool"], "roles": ["*"], "effect": "allow"},
            {"id": "b", "tools": ["cond_tool"], "roles": ["r1"], "effect": "allow", "when": [_c("$user.id", "exists")]},
            {"id": "c", "tools": ["dead_tool"], "roles": ["*"], "effect": "deny"},
            {"id": "d", "tools": ["dead_tool"], "roles": ["r1"], "effect": "allow"},
            {"id": "e", "tools": ["*"], "roles": ["r3"], "effect": "deny"},
            {"id": "f", "tools": ["mixed"], "roles": ["r2"], "effect": "allow", "when": [_c("$args.x", "exists")]},
            {"id": "g", "tools": ["mixed"], "roles": ["r2"], "effect": "allow"},
        ]}
        m = PolicyEngine(p).matrix()
        self.assertEqual(m["open_tool"], {"r1": "allow", "r2": "allow", "r3": "deny"})
        self.assertEqual(m["cond_tool"], {"r1": "conditional", "r2": "deny", "r3": "deny"})
        self.assertEqual(m["dead_tool"], {"r1": "deny", "r2": "deny", "r3": "deny"})   # deny χωρίς when νικά
        self.assertEqual(m["u_only"], {"r1": "deny", "r2": "deny", "r3": "deny"})      # default deny
        self.assertEqual(m["mixed"], {"r1": "deny", "r2": "allow", "r3": "deny"})      # allow χωρίς when υπερισχύει
        self.assertEqual(sorted(m), ["cond_tool", "dead_tool", "mixed", "open_tool", "u_only"])

    def test_tools_and_roles(self):
        e = PolicyEngine(BANK)
        self.assertEqual(e.roles, ["customer", "teller", "admin"])
        self.assertEqual(e.tools(), sorted(e.tools()))
        self.assertIn("transfer_funds", e.tools())
        self.assertEqual(e.matrix()["transfer_funds"]["customer"], "conditional")
        self.assertEqual(e.matrix()["run_sql"], {"customer": "deny", "teller": "deny", "admin": "deny"})
        self.assertEqual(e.matrix()["send_email"]["teller"], "allow")
        self.assertEqual(e.untrusted_tools, {"read_support_ticket", "list_transactions"})
        self.assertIn("close_account", e.high_risk_tools)


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.policy_path = os.path.join(cls.tmp.name, "bank.policy.json")
        with open(cls.policy_path, "w", encoding="utf-8") as f:
            json.dump(BANK, f, ensure_ascii=False)
        cls.bad_path = os.path.join(cls.tmp.name, "bad.json")
        with open(cls.bad_path, "w", encoding="utf-8") as f:
            json.dump({"schema": "nope"}, f)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_cli(self, how, command, policy=None, stdin=None):
        entry = ["-m", "app.policy_engine"] if how == "module" else [str(ROOT / "app" / "policy_engine.py")]
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        proc = subprocess.run([sys.executable] + entry + [command, "--policy", policy or self.policy_path],
                              input=(stdin or "").encode("utf-8"), capture_output=True, cwd=str(ROOT), env=env)
        return proc.returncode, proc.stdout.decode("utf-8"), proc.stderr.decode("utf-8")

    def test_evaluate_both_entry_points(self):
        req = json.dumps({"user": C1, "tool": "get_account", "args": {},
                          "context": {"account_owner_id": "c1"}})
        deny = json.dumps({"user": C1, "tool": "get_account", "args": {}, "context": {"account_owner_id": "c2"}})
        for how in ("module", "script"):
            with self.subTest(how=how):
                code, out, _ = self.run_cli(how, "evaluate", stdin=req)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out)["action"], "allow")
                code, out, _ = self.run_cli(how, "evaluate", stdin=deny)
                self.assertEqual((code, json.loads(out)["action"]), (0, "deny"))

    def test_redact_cli(self):
        req = json.dumps({"user": C1, "tool": "get_account", "args": {}, "context": {},
                          "result": {"id": "A1", "owner_id": "c1", "card_number": "4111"}})
        for how in ("module", "script"):
            with self.subTest(how=how):
                code, out, _ = self.run_cli(how, "redact", stdin=req)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out)["card_number"], "[redacted]")

    def test_validate_and_matrix_cli(self):
        for how in ("module", "script"):
            with self.subTest(how=how):
                code, out, _ = self.run_cli(how, "validate")
                self.assertEqual(code, 0)
                self.assertIn("[OK]", out)
                code, out, _ = self.run_cli(how, "validate", policy=self.bad_path)
                self.assertEqual(code, 1)
                self.assertIn("[FAIL]", out)
                code, out, _ = self.run_cli(how, "matrix")
                self.assertEqual(code, 0)
                self.assertIn("transfer_funds", out)
                self.assertIn("conditional", out)

    def test_errors_exit_nonzero_and_never_allow(self):
        for how in ("module", "script"):
            with self.subTest(how=how):
                for stdin in ("not json", "[]", json.dumps({"tool": "get_account"}), ""):
                    code, out, _ = self.run_cli(how, "evaluate", stdin=stdin)
                    self.assertNotEqual(code, 0, stdin)
                    self.assertIn("error", json.loads(out))
                    self.assertNotIn('"allow"', out)
                code, out, _ = self.run_cli(how, "evaluate", policy=os.path.join(self.tmp.name, "missing.json"), stdin="{}")
                self.assertNotEqual(code, 0)
                self.assertIn("error", json.loads(out))
                code, out, _ = self.run_cli(how, "evaluate", policy=self.bad_path, stdin="{}")
                self.assertNotEqual(code, 0)
                code, out, _ = self.run_cli(how, "redact", stdin=json.dumps({"user": C1, "tool": "x"}))
                self.assertNotEqual(code, 0)

    def test_greek_text_survives_cli(self):
        p = copy.deepcopy(BANK)
        p["rules"][0]["reason"] = "απενεργοποιημένο για το chatbot"
        path = os.path.join(self.tmp.name, "greek.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(p, f, ensure_ascii=False)
        code, out, _ = self.run_cli("script", "evaluate", policy=path,
                                    stdin=json.dumps({"user": A1, "tool": "run_sql", "args": {}, "context": {}}))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["reason"], "απενεργοποιημένο για το chatbot")


class IndependenceTests(unittest.TestCase):
    """Ο μηχανισμός δεν εξαρτάται από καμία εφαρμογή, βάση ή web framework."""

    def test_source_mentions_no_application_specifics(self):
        import re
        src = (ROOT / "app" / "policy_engine.py").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"(?i)eclass|sqlite|flask|app\.", src), [])

    def test_import_loads_no_framework_or_database_modules(self):
        code = ("import sys; sys.path.insert(0, %r); import app.policy_engine; "
                "print([m for m in ('flask', 'sqlite3', 'werkzeug', 'requests') if m in sys.modules])" % str(ROOT))
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, cwd=str(ROOT)).stdout.decode()
        self.assertEqual(out.strip(), "[]")


if __name__ == "__main__":
    if "--regen-baseline" in sys.argv:
        sys.exit(regen_baseline())
    unittest.main()
