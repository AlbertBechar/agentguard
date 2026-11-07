"""
tests/test_policy.py
Τεστ για την πολιτική ασφαλείας eclass_policy.
"""
import os
import unittest

os.environ.setdefault("DB_PATH", "./test.db")
os.environ.setdefault("AI_STUDIO_API_KEY", "dummy")

from app.app import app
from app.db import query
from app.eclass_policy import check


class TestPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with app.app_context():
            cls.admin = query("SELECT * FROM users WHERE username = 'admin'", one=True)
            cls.teacher_cs = query("SELECT * FROM users WHERE username = 'kpapadopoulos'", one=True)
            cls.teacher_math = query("SELECT * FROM users WHERE username = 'dnikolaou'", one=True)
            cls.student1 = query("SELECT * FROM users WHERE username = 'sdi2400001'", one=True)  # CS101, CS340, MATH110
            cls.student8 = query("SELECT * FROM users WHERE username = 'sdi2400008'", one=True)  # CS340, CS220 (όχι CS101)

    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    # 1. Power tools (run_sql, fetch_url)
    def test_run_sql_denied_for_all(self):
        for u in (self.student1, self.teacher_cs, self.admin):
            res = check(u, "run_sql", {"sql": "SELECT 1"})
            self.assertEqual(res.action, "deny")

    def test_fetch_url_denied_for_all(self):
        for u in (self.student1, self.teacher_cs, self.admin):
            res = check(u, "fetch_url", {"url": "http://evil.com"})
            self.assertEqual(res.action, "deny")

    # 2. User management
    def test_list_users(self):
        # ΑΛΛΑΓΗ ΕΔΩ: Πρέπει να περιμένει "deny"
        self.assertEqual(check(self.student1, "list_users", {}).action, "deny")
        self.assertEqual(check(self.teacher_cs, "list_users", {}).action, "deny")
        self.assertEqual(check(self.admin, "list_users", {}).action, "allow")

    def test_get_user(self):
        # Φοιτητής βλέπει μόνο τον εαυτό του
        self.assertEqual(check(self.student1, "get_user", {"user_ref": "sdi2400001"}).action, "allow")
        self.assertEqual(check(self.student1, "get_user", {"user_ref": "admin"}).action, "deny")
        self.assertEqual(check(self.student1, "get_user", {"user_ref": "sdi2400002"}).action, "deny")
        # Καθηγητής & Admin βλέπουν προφίλ
        self.assertEqual(check(self.teacher_cs, "get_user", {"user_ref": "sdi2400001"}).action, "allow")
        self.assertEqual(check(self.admin, "get_user", {"user_ref": "sdi2400001"}).action, "allow")

    def test_update_user(self):
        # Φοιτητής ενημερώνει μόνο δικά του επιτρεπτά πεδία
        self.assertEqual(check(self.student1, "update_user", {"user_ref": "sdi2400001", "phone": "123"}).action, "allow")
        self.assertEqual(check(self.student1, "update_user", {"user_ref": "sdi2400002", "phone": "123"}).action, "deny")
        self.assertEqual(check(self.student1, "update_user", {"user_ref": "sdi2400001", "role": "admin"}).action, "deny")
        self.assertEqual(check(self.student1, "update_user", {"user_ref": "sdi2400001", "admin_notes": "hacked"}).action, "deny")
        # Admin μπορεί τα πάντα
        self.assertEqual(check(self.admin, "update_user", {"user_ref": "sdi2400001", "role": "teacher"}).action, "allow")

    def test_reset_password(self):
        self.assertEqual(check(self.student1, "reset_password", {"user_ref": "sdi2400001", "new_password": "x"}).action, "deny")
        self.assertEqual(check(self.teacher_cs, "reset_password", {"user_ref": "sdi2400001", "new_password": "x"}).action, "deny")
        self.assertEqual(check(self.admin, "reset_password", {"user_ref": "sdi2400001", "new_password": "x"}).action, "allow")

    def test_create_and_delete_user(self):
        self.assertEqual(check(self.student1, "create_user", {"username": "hacker", "role": "admin", "password": "1", "full_name": "x"}).action, "deny")
        self.assertEqual(check(self.admin, "create_user", {"username": "new", "role": "student", "password": "1", "full_name": "x"}).action, "allow")
        self.assertEqual(check(self.student1, "delete_user", {"user_ref": "admin"}).action, "deny")
        self.assertEqual(check(self.admin, "delete_user", {"user_ref": "sdi2400001"}).action, "allow")

    def test_enroll_user(self):
        self.assertEqual(check(self.student1, "enroll_user", {"user_ref": "sdi2400001", "course_ref": "CS220"}).action, "deny")
        self.assertEqual(check(self.admin, "enroll_user", {"user_ref": "sdi2400001", "course_ref": "CS220"}).action, "allow")

    # 3. Courses, Materials & Announcements
    def test_courses_and_materials(self):
        self.assertEqual(check(self.student1, "list_courses", {}).action, "allow")
        self.assertEqual(check(self.teacher_cs, "list_courses", {}).action, "allow")
        
        # get_course (enrolled vs not enrolled)
        self.assertEqual(check(self.student1, "get_course", {"course_ref": "CS101"}).action, "allow")
        self.assertEqual(check(self.student8, "get_course", {"course_ref": "CS101"}).action, "deny")
        # add_material & post_announcement
        self.assertEqual(check(self.student1, "add_material", {"course_ref": "CS101", "title": "t", "body": "b"}).action, "deny")
        self.assertEqual(check(self.teacher_cs, "add_material", {"course_ref": "CS101", "title": "t", "body": "b"}).action, "allow")
        self.assertEqual(check(self.teacher_cs, "add_material", {"course_ref": "MATH110", "title": "t", "body": "b"}).action, "deny")  # Ownership check!

    # 4. Assignments & Submissions
    def test_assignments_and_submissions(self):
        # submit_assignment
        self.assertEqual(check(self.student1, "submit_assignment", {"assignment_id": 1, "content": "c"}).action, "allow")
        self.assertEqual(check(self.student1, "submit_assignment", {"assignment_id": 1, "content": "c", "student_ref": "sdi2400002"}).action, "deny")
        self.assertEqual(check(self.teacher_cs, "submit_assignment", {"assignment_id": 1, "content": "c"}).action, "deny")
        # get_submissions
        self.assertEqual(check(self.student1, "get_submissions", {"assignment_id": 1}).action, "deny")
        self.assertEqual(check(self.teacher_cs, "get_submissions", {"assignment_id": 1}).action, "allow")
        self.assertEqual(check(self.teacher_math, "get_submissions", {"assignment_id": 1}).action, "deny")  # CS101 assignment, math teacher

    # 5. Grading
    def test_grading(self):
        # grade_submission
        self.assertEqual(check(self.student1, "grade_submission", {"submission_id": 1, "grade": 10}).action, "deny")
        self.assertEqual(check(self.teacher_cs, "grade_submission", {"submission_id": 1, "grade": 10}).action, "allow")
        self.assertEqual(check(self.teacher_math, "grade_submission", {"submission_id": 1, "grade": 10}).action, "deny")
        # set_final_grade
        self.assertEqual(check(self.student1, "set_final_grade", {"course_ref": "CS101", "student_ref": "sdi2400001", "grade": 10}).action, "deny")
        self.assertEqual(check(self.teacher_cs, "set_final_grade", {"course_ref": "CS101", "student_ref": "sdi2400001", "grade": 10}).action, "allow")
        self.assertEqual(check(self.teacher_cs, "set_final_grade", {"course_ref": "MATH110", "student_ref": "sdi2400001", "grade": 10}).action, "deny")
        # get_gradebook
        self.assertEqual(check(self.student1, "get_gradebook", {"course_ref": "CS101"}).action, "deny")
        self.assertEqual(check(self.teacher_cs, "get_gradebook", {"course_ref": "CS101"}).action, "allow")
        # get_grades
        self.assertEqual(check(self.student1, "get_grades", {"student_ref": "sdi2400001"}).action, "allow")
        self.assertEqual(check(self.student1, "get_grades", {"student_ref": "sdi2400002"}).action, "deny")
        self.assertEqual(check(self.teacher_cs, "get_grades", {"course_ref": "CS101"}).action, "allow")
        self.assertEqual(check(self.teacher_cs, "get_grades", {"course_ref": "MATH110"}).action, "deny")

    # 6. Exercises & Quizzes
    def test_exercises(self):
        # get_exercise (έχει τις σωστές απαντήσεις!)
        self.assertEqual(check(self.student1, "get_exercise", {"exercise_id": 1}).action, "deny")
        self.assertEqual(check(self.teacher_cs, "get_exercise", {"exercise_id": 1}).action, "allow")
        self.assertEqual(check(self.teacher_math, "get_exercise", {"exercise_id": 1}).action, "deny")
        # submit_exercise
        self.assertEqual(check(self.student1, "submit_exercise", {"exercise_id": 1, "answers": "{}"}).action, "allow")
        self.assertEqual(check(self.student1, "submit_exercise", {"exercise_id": 1, "student_ref": "sdi2400002", "answers": "{}"}).action, "deny")
        self.assertEqual(check(self.student1, "submit_exercise", {"exercise_id": 2, "answers": "{}"}).action, "deny")  # Quiz 2 is closed!

    # 7. Messages
    def test_messages(self):
        # read_messages
        self.assertEqual(check(self.student1, "read_messages", {"user_ref": "sdi2400001"}).action, "allow")
        self.assertEqual(check(self.student1, "read_messages", {"user_ref": "sdi2400002"}).action, "deny")
        self.assertEqual(check(self.admin, "read_messages", {"user_ref": "sdi2400001"}).action, "deny")
        # send_message (spoofing protection)
        self.assertEqual(check(self.student1, "send_message", {"to": "sdi2400002", "subject": "hi", "body": "msg"}).action, "allow")
        self.assertEqual(check(self.student1, "send_message", {"to": "sdi2400002", "from_user": "admin", "subject": "hi", "body": "msg"}).action, "deny")

    # 8. Edge cases & Fail-Closed
    def test_edge_cases(self):
        self.assertEqual(check({}, "run_sql", {}).action, "deny")
        self.assertEqual(check({"role": "invalid"}, "get_course", {}).action, "deny")
        self.assertEqual(check(self.student1, "unknown_tool", {}).action, "deny")

    # 9. Έλεγχος πρόσθετων κενών ασφαλείας (Extra Red-Teaming Checks)
    def test_security_loopholes(self):
        # Φοιτητής δοκιμάζει να πάρει προφίλ διαχειριστή
        self.assertEqual(check(self.student1, "get_user", {"user_ref": "admin"}).action, "deny")

        # Φοιτητής δοκιμάζει να διαβάσει μηνύματα άλλου φοιτητή
        self.assertEqual(check(self.student1, "read_messages", {"user_ref": "sdi2400002"}).action, "deny")

        # Φοιτητής δοκιμάζει να δει τις σωστές απαντήσεις (answer keys) μιας άσκησης
        self.assertEqual(check(self.student1, "get_exercise", {"exercise_id": 1}).action, "deny")

        # Φοιτητής δοκιμάζει να δει συνολικό βαθμολόγιο (gradebook) μαθήματος
        self.assertEqual(check(self.student1, "get_gradebook", {"course_ref": "CS101"}).action, "deny")

    # 10. Φοιτητής δοκιμάζει να αλλάξει τον τελικό του βαθμό (Final Grade Injection)
    def test_student_cannot_set_final_grade(self):
        res = check(self.student1, "set_final_grade", {
            "course_ref": "CS101",
            "student_ref": "sdi2500191",
            "grade": 10.0
        })
        self.assertEqual(res.action, "deny")

class TestGoldenMaster(unittest.TestCase):
    """Ο νέος eclass_policy (JSON + engine) πρέπει να κάνει ΑΚΡΙΒΩΣ ό,τι έκανε ο παλιός (tag pre-engine).

    Το baseline (tests/policy_baseline.json) καταγράφηκε από τον παλιό κώδικα. Το τεστ τρέχει σε
    ΦΡΕΣΚΙΑ seeded βάση (προσωρινό αρχείο), άρα δεν επηρεάζεται από ό,τι άλλαξαν άλλα τεστ στο test.db.
    """

    def test_matches_legacy_baseline(self):
        try:
            from tests.test_policy_engine import BASELINE_PATH, build_records, fresh_seeded_db
        except ImportError:  # τρέξιμο με `python tests/test_policy.py`
            from test_policy_engine import BASELINE_PATH, build_records, fresh_seeded_db
        import json
        import app.eclass_policy as new_policy

        with open(BASELINE_PATH, "r", encoding="utf-8") as f:
            baseline = json.load(f)["records"]
        with fresh_seeded_db() as users:
            fresh = build_records(new_policy, users)

        def key(r):
            return (r["user"], r["tool"], json.dumps(r["args"], sort_keys=True, ensure_ascii=False))

        self.assertEqual(len(baseline), len(fresh), "διαφορετικό πλήθος εγγραφών")
        diffs = []
        redact_compared = 0
        # Σύγκριση ανά θέση (η σειρά είναι ντετερμινιστική· μερικές παραλλαγές επαναλαμβάνονται σκόπιμα)
        for old, new in zip(baseline, fresh):
            if key(old) != key(new):
                diffs.append(f"ΑΣΥΝΤΑΞΙΑ εγγραφών: {key(old)} != {key(new)}")
                continue
            if old["check"] != new["check"]:
                diffs.append(f"CHECK user={old['user']} tool={old['tool']} args={old['args']}\n"
                             f"    παλιό: {old['check']}\n    νέο:   {new['check']}")
            if "redact_sha256" in old:
                redact_compared += 1
                if old["redact_sha256"] != new.get("redact_sha256"):
                    diffs.append(f"REDACT user={old['user']} tool={old['tool']} args={old['args']}\n"
                                 f"    παλιό digest: {old['redact_sha256'][:16]}...\n"
                                 f"    νέο digest:   {str(new.get('redact_sha256'))[:16]}...")
        self.assertGreater(redact_compared, 200)  # φρουρός: το baseline πράγματι περιέχει redaction
        self.assertEqual(diffs, [], f"{len(diffs)} διαφορές από το baseline:\n" + "\n".join(diffs[:15]))
        print(f"\n[golden master] {len(baseline)} εγγραφές check, {redact_compared} με redact: όλες ίδιες")


# ---------------------------------------------------------------------------
# Απόδειξη γενίκευσης: ίδιος μηχανισμός, άλλα domains (τράπεζα, υγεία).
# Ό,τι χρειάζεται η πολιτική έρχεται ως ΑΠΛΟ dict (context): καμία βάση, κανένα import του app.app.
# ---------------------------------------------------------------------------

def _fixture_engine(name):
    from pathlib import Path
    from app.policy_engine import PolicyEngine
    return PolicyEngine.from_file(Path(__file__).resolve().parent / "fixtures" / f"{name}.policy.json")


class TestGeneralizationBank(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = _fixture_engine("bank")
        cls.c1 = {"id": "c1", "role": "customer"}
        cls.c2 = {"id": "c2", "role": "customer"}
        cls.t1 = {"id": "t1", "role": "teller"}
        cls.a1 = {"id": "a1", "role": "admin"}

    def decide(self, user, tool, args=None, ctx=None):
        d = self.engine.evaluate(user, tool, args or {}, ctx or {})
        return d["action"], d["rule"]

    def test_rbac_and_ownership(self):
        cases = [
            (self.c1, "get_account", {"account_id": "A1"}, {"account_owner_id": "c1"}, ("allow", "account.read.owner")),
            (self.c1, "get_account", {"account_id": "A2"}, {"account_owner_id": "c2"}, ("deny", "default")),
            (self.c1, "get_statement", {"account_id": "A2"}, {"account_owner_id": "c2"}, ("deny", "default")),
            (self.t1, "get_account", {"account_id": "A2"}, {"account_owner_id": "c2"}, ("allow", "account.read.staff")),
            (self.c1, "get_account", {"account_id": "A1"}, {}, ("deny", "default")),          # γεγονός που λείπει
            (self.c1, "read_support_ticket", {"ticket_id": 1}, {"ticket_customer_id": "c1"}, ("allow", "ticket.read.owner")),
            (self.c2, "read_support_ticket", {"ticket_id": 1}, {"ticket_customer_id": "c1"}, ("deny", "default")),
            (self.t1, "send_email", {"to": "x"}, {}, ("allow", "email.staff")),
            (self.c1, "send_email", {"to": "x"}, {}, ("deny", "default")),
            (self.t1, "close_account", {"account_id": "A1"}, {}, ("deny", "default")),
            (self.a1, "close_account", {"account_id": "A1"}, {}, ("allow", "account.close.admin")),
            (self.a1, "run_sql", {"query": "select 1"}, {}, ("deny", "never.sql_and_urls")),
            (self.t1, "fetch_url", {"url": "http://x"}, {}, ("deny", "never.sql_and_urls")),
        ]
        for user, tool, args, ctx, expected in cases:
            with self.subTest(user=user["id"], tool=tool, ctx=ctx):
                self.assertEqual(self.decide(user, tool, args, ctx), expected)

    def test_numeric_limits(self):
        own = {"from_account_owner_id": "c1"}
        cases = [
            (self.c1, {"amount": 1000}, own, ("allow", "transfer.customer")),
            (self.c1, {"amount": 1000.5}, own, ("deny", "default")),
            (self.c1, {"amount": "250"}, own, ("allow", "transfer.customer")),
            (self.c1, {"amount": 5}, {"from_account_owner_id": "c2"}, ("deny", "default")),
            (self.a1, {"amount": 9999}, {}, ("allow", "transfer.admin")),
            (self.a1, {"amount": 10001}, {}, ("deny", "transfer.hard_limit")),
            (self.a1, {"amount": -5}, {}, ("deny", "transfer.positive_only")),
            (self.a1, {"amount": 0}, {}, ("deny", "transfer.positive_only")),
            (self.t1, {"amount": 1}, {}, ("deny", "default")),
        ]
        for user, args, ctx, expected in cases:
            with self.subTest(user=user["id"], args=args):
                self.assertEqual(self.decide(user, "transfer_funds", args, ctx), expected)

    def test_argument_field_restriction(self):
        ok = {"customer_id": "c1", "email": "a@b.gr", "phone": "6900"}
        self.assertEqual(self.decide(self.c1, "update_contact", ok)[0], "allow")
        self.assertEqual(self.decide(self.c1, "update_contact", dict(ok, iban="GR1"))[0], "deny")     # πεδίο εκτός λίστας
        self.assertEqual(self.decide(self.c1, "update_contact", dict(ok, iban=None))[0], "allow")     # None = δεν δόθηκε
        self.assertEqual(self.decide(self.c1, "update_contact", dict(ok, customer_id="c2"))[0], "deny")

    def test_redaction_and_row_filters(self):
        acct = {"id": "A1", "owner_id": "c1", "iban": "GR00", "balance": 10, "card_number": "4111"}
        redact = lambda user, tool, res, ctx=None: self.engine.redact(user, tool, {}, res, ctx or {})  # noqa: E731
        for u in (self.c1, self.t1, self.a1):       # ο αριθμός κάρτας δεν φαίνεται ποτέ σε κανέναν
            self.assertEqual(redact(u, "get_account", dict(acct))["card_number"], "[redacted]")
        self.assertEqual(redact(self.c1, "get_account", dict(acct))["iban"], "GR00")             # ιδιοκτήτης
        self.assertEqual(redact(self.a1, "get_account", dict(acct))["iban"], "GR00")             # admin
        self.assertEqual(redact(self.t1, "get_account", dict(acct))["iban"], "[redacted]")       # teller: όχι
        self.assertEqual(redact(self.c2, "get_account", dict(acct)), {"error": "not found"})     # άλλου πελάτη
        txs = [{"id": 1, "account_id": "A1", "memo": "x"}, {"id": 2, "account_id": "A2", "memo": "y"}]
        mine = {"owned_account_ids": ["A1"]}
        self.assertEqual([t["id"] for t in redact(self.c1, "list_transactions", txs, mine)], [1])
        self.assertEqual(len(redact(self.t1, "list_transactions", txs, mine)), 2)
        self.assertEqual(redact(self.c1, "list_transactions", txs, {"owned_account_ids": []}), [])
        stmt = {"month": "05", "transactions": txs}
        self.assertEqual([t["id"] for t in redact(self.c1, "get_statement", stmt, mine)["transactions"]], [1])
        cust = {"customer_id": "c1", "email": "a@b.gr"}
        self.assertEqual(redact(self.c1, "get_customer", dict(cust))["email"], "a@b.gr")
        self.assertEqual(redact(self.t1, "get_customer", dict(cust))["email"], "[redacted]")

    def test_policy_is_valid_and_matrix_makes_sense(self):
        from app.policy_engine import validate_policy
        self.assertEqual(validate_policy(self.engine.policy), [])
        m = self.engine.matrix()
        self.assertEqual(m["run_sql"], {"customer": "deny", "teller": "deny", "admin": "deny"})
        self.assertEqual(m["transfer_funds"]["customer"], "conditional")
        self.assertEqual(m["close_account"], {"customer": "deny", "teller": "deny", "admin": "allow"})


class TestGeneralizationHealth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = _fixture_engine("health")
        cls.p1 = {"id": "p1", "role": "patient"}
        cls.p2 = {"id": "p2", "role": "patient"}
        cls.d1 = {"id": "d1", "role": "doctor"}
        cls.ad = {"id": "ad", "role": "admin"}

    def decide(self, user, tool, args=None, ctx=None):
        d = self.engine.evaluate(user, tool, args or {}, ctx or {})
        return d["action"], d["rule"]

    def test_rbac_and_ownership(self):
        treating = {"is_treating_doctor": True}
        cases = [
            (self.p1, "get_record", {}, {"record_patient_id": "p1"}, ("allow", "record.read.patient_self")),
            (self.p1, "get_record", {}, {"record_patient_id": "p2"}, ("deny", "default")),
            (self.d1, "get_record", {}, treating, ("allow", "record.read.treating_doctor")),
            (self.d1, "get_record", {}, {"is_treating_doctor": False}, ("deny", "default")),
            (self.d1, "read_notes", {}, treating, ("allow", "record.read.treating_doctor")),
            (self.p1, "read_notes", {}, {"record_patient_id": "p1"}, ("deny", "default")),       # τα notes όχι στον ασθενή
            (self.ad, "get_record", {}, {"record_patient_id": "p1"}, ("deny", "default")),       # ούτε ο admin βλέπει ιατρικά
            (self.p1, "list_appointments", {"patient_id": "p1"}, {}, ("allow", "appointments.list.patient_self")),
            (self.p1, "list_appointments", {"patient_id": "p2"}, {}, ("deny", "default")),
            (self.ad, "list_appointments", {}, {}, ("allow", "appointments.list.admin")),
            (self.p1, "book_appointment", {"patient_id": "p1"}, {}, ("allow", "book.patient_self")),
            (self.p1, "book_appointment", {"patient_id": "p2"}, {}, ("deny", "default")),
            (self.ad, "export_all_records", {}, {}, ("deny", "export.never")),
            (self.d1, "run_sql", {"query": "x"}, {}, ("deny", "never.sql_and_urls")),
        ]
        for user, tool, args, ctx, expected in cases:
            with self.subTest(user=user["id"], tool=tool, args=args, ctx=ctx):
                self.assertEqual(self.decide(user, tool, args, ctx), expected)

    def test_prescribe_limits_and_field_restriction(self):
        t = {"is_treating_doctor": True}
        good = {"patient_id": "p1", "drug": "x", "dose_mg": 100}
        cases = [
            (self.d1, good, t, ("allow", "prescribe.treating_doctor")),
            (self.d1, dict(good, dose_mg=500), t, ("allow", "prescribe.treating_doctor")),
            (self.d1, dict(good, dose_mg=501), t, ("deny", "prescribe.dose_limit")),
            (self.d1, dict(good, dose_mg="900"), t, ("deny", "prescribe.dose_limit")),
            (self.d1, dict(good, refill_count=99), t, ("deny", "default")),                     # πεδίο εκτός λίστας
            (self.d1, good, {"is_treating_doctor": False}, ("deny", "default")),
            (self.p1, good, t, ("deny", "default")),
            (self.ad, good, t, ("deny", "default")),
        ]
        for user, args, ctx, expected in cases:
            with self.subTest(user=user["id"], args=args, ctx=ctx):
                self.assertEqual(self.decide(user, "prescribe", args, ctx), expected)

    def test_redaction_and_row_filters(self):
        redact = lambda user, tool, res, ctx=None: self.engine.redact(user, tool, {}, res, ctx or {})  # noqa: E731
        rec = {"patient_id": "p1", "ssn": "123", "diagnosis": "flu", "insurance_number": "INS-9"}
        for u in (self.p1, self.d1, self.ad):
            self.assertEqual(redact(u, "get_record", dict(rec))["ssn"], "[redacted]")        # πάντα κρυμμένο
        self.assertEqual(redact(self.p1, "get_record", dict(rec))["diagnosis"], "flu")
        self.assertEqual(redact(self.d1, "get_record", dict(rec))["diagnosis"], "flu")
        self.assertEqual(redact(self.ad, "get_record", dict(rec))["diagnosis"], "[redacted]")
        self.assertEqual(redact(self.ad, "get_record", dict(rec))["insurance_number"], "INS-9")
        self.assertEqual(redact(self.d1, "get_record", dict(rec))["insurance_number"], "[redacted]")
        self.assertEqual(redact(self.p2, "get_record", dict(rec))["insurance_number"], "[redacted]")
        appts = {"appointments": [{"id": 1, "patient_id": "p1"}, {"id": 2, "patient_id": "p2"}], "total": 2}
        out = redact(self.p1, "list_appointments", appts)
        self.assertEqual([a["id"] for a in out["appointments"]], [1])
        out = redact(self.d1, "list_appointments", appts, {"treated_patient_ids": ["p2"]})
        self.assertEqual([a["id"] for a in out["appointments"]], [2])
        out = redact(self.ad, "list_appointments", appts)
        self.assertEqual(len(out["appointments"]), 2)

    def test_policy_validates_with_one_expected_warning(self):
        from app.policy_engine import validate_policy
        issues = validate_policy(self.engine.policy)
        self.assertEqual([i["level"] for i in issues], ["warning"])
        self.assertIn("export_all_records", issues[0]["message"])   # σκόπιμο: απαγορεύεται σε όλους
        self.assertEqual(self.engine.matrix()["read_notes"], {"patient": "deny", "doctor": "conditional", "admin": "deny"})


if __name__ == "__main__":
    unittest.main()