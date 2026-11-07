import os
import unittest

# Πριν από κάθε import της εφαρμογής: δοκιμαστική βάση και ψεύτικο κλειδί.
os.environ.setdefault("DB_PATH", "./test.db")
os.environ.setdefault("AI_STUDIO_API_KEY", "dummy")

from app.app import app  # noqa: E402
from app import guard  # noqa: E402
from app.db import query  # noqa: E402
from app.guard_types import Decision, TurnContext  # noqa: E402

TEST_USER_ID = 999  # δεν υπάρχει τέτοιος χρήστης, οπότε δεν πειράζουμε κανέναν αληθινό


class TaintStorageTest(unittest.TestCase):

    def test_set_read_clear_taint(self):
        with app.app_context():
            guard._clear_taint(TEST_USER_ID)                  # ξεκινάμε καθαρά
            self.assertFalse(guard._is_tainted(TEST_USER_ID))

            guard._set_tainted(TEST_USER_ID)
            self.assertTrue(guard._is_tainted(TEST_USER_ID))

            guard._clear_taint(TEST_USER_ID)
            self.assertFalse(guard._is_tainted(TEST_USER_ID))

    def test_log_event_writes_row(self):
        with app.app_context():
            guard._log_event(TEST_USER_ID, "grade_submission", {"submission_id": 1, "grade": 10},
                             "deny", reason="student cannot change grades", rule="grades.write.teacher_only")
            row = query("SELECT * FROM guard_events WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                        (TEST_USER_ID,), one=True)
            self.assertEqual(row["tool"], "grade_submission")
            self.assertEqual(row["action"], "deny")
            self.assertEqual(row["tainted"], 0)


if __name__ == "__main__":
    unittest.main()

"""
Οι γραμμές os.environ λένε στην εφαρμογή να χρησιμοποιήσει μια δοκιμαστική βάση ./test.db και όχι την αληθινή. Μπαίνουν πριν από τα imports, γιατί η εφαρμογή διαβάζει το DB_PATH τη στιγμή που φορτώνει.
Το with app.app_context(): χρειάζεται γιατί οι query/execute βρίσκουν τη βάση μέσα από το Flask.
Το πρώτο τεστ κάνει τον κύκλο καθαρό → μολυσμένο → καθαρό. Το δεύτερο ελέγχει ότι η _log_event γράφει πράγματι γραμμή στη βάση. Το assertTrue/assertEqual κάνει το τεστ να αποτύχει αν το αποτέλεσμα είναι λάθος.
"""

# --------------------------------------------------------------------------- ψεύτικα modules

class FakePolicy:
    UNTRUSTED_TOOLS = {"read_forum"}
    HIGH_RISK_TOOLS = {"grade_submission"}

    def __init__(self, action="allow", explode=False):
        self.action = action
        self.explode = explode

    def check(self, user, tool, args, ctx):
        if self.explode:
            raise RuntimeError("policy bug")
        return Decision(self.action, reason="fake reason", rule="fake.rule")

    def redact(self, user, tool, args, result):
        return result


class FakeSanitizer:
    def sanitize_result(self, tool, result, source):
        return result, [], 0.5


class FakeApprovals:
    def __init__(self):
        self.created = []

    def create_pending(self, user, tool, args, reason):
        self.created.append((tool, args))
        return 42


class FakeTool:
    """Ψεύτικο call_tool: θυμάται αν εκτελέστηκε."""
    def __init__(self):
        self.calls = []

    def __call__(self, user, name, args):
        self.calls.append(name)
        print(f"    [fake tool executed: {name}]")
        return {"ok": True}


USER = {"id": TEST_USER_ID, "username": "tester", "role": "teacher"}


class GuardTest(unittest.TestCase):

    def setUp(self):
        self.ctx_manager = app.app_context()
        self.ctx_manager.push()
        guard._clear_taint(TEST_USER_ID)
        self.tool = FakeTool()
        self.approvals = FakeApprovals()

    def tearDown(self):
        guard._clear_taint(TEST_USER_ID)
        self.ctx_manager.pop()

    def make_guard(self, policy):
        return guard.Guard(policy, FakeSanitizer(), self.approvals)

    def test_a_deny_does_not_run_tool(self):
        g = self.make_guard(FakePolicy("deny"))
        ctx = g.new_turn(USER, "set everyone to 10")
        result = g.run_tool(ctx, self.tool, USER, "grade_submission", {"submission_id": 1, "grade": 10})
        self.assertEqual(result, {"error": "blocked by policy: fake reason"})
        self.assertEqual(self.tool.calls, [])

    def test_b_untrusted_tool_taints_and_persists(self):
        g = self.make_guard(FakePolicy("allow"))
        ctx = g.new_turn(USER, "read the forum")
        self.assertFalse(ctx.tainted)
        g.run_tool(ctx, self.tool, USER, "read_forum", {"course_ref": "CS340"})
        self.assertEqual(self.tool.calls, ["read_forum"])
        self.assertTrue(ctx.tainted)
        self.assertTrue(guard._is_tainted(TEST_USER_ID))

    def test_c_high_risk_after_taint_needs_approval(self):
        g = self.make_guard(FakePolicy("allow"))
        ctx = g.new_turn(USER, "read the forum, then grade")
        g.run_tool(ctx, self.tool, USER, "read_forum", {"course_ref": "CS340"})
        result = g.run_tool(ctx, self.tool, USER, "grade_submission", {"submission_id": 1, "grade": 10})
        self.assertEqual(result["status"], "approval_required")
        self.assertEqual(result["approval_id"], 42)
        self.assertEqual(self.tool.calls, ["read_forum"])  # το grade_submission ΔΕΝ εκτελέστηκε
        self.assertEqual(len(self.approvals.created), 1)

    def test_d_policy_exception_fails_closed(self):
        g = self.make_guard(FakePolicy(explode=True))
        ctx = g.new_turn(USER, "anything")
        result = g.run_tool(ctx, self.tool, USER, "grade_submission", {"submission_id": 1, "grade": 10})
        self.assertEqual(result, {"error": "blocked by guard: internal error"})
        self.assertEqual(self.tool.calls, [])

    def test_e_taint_survives_new_turn_and_clears(self):
        g = self.make_guard(FakePolicy("allow"))
        ctx = g.new_turn(USER, "read the forum")
        g.run_tool(ctx, self.tool, USER, "read_forum", {"course_ref": "CS340"})
        next_ctx = g.new_turn(USER, "now grade it")           # νέο μήνυμα, νέο ctx
        self.assertTrue(next_ctx.tainted)
        g.clear_taint(TEST_USER_ID)
        self.assertFalse(g.new_turn(USER, "after Clear").tainted)

"""
Τα Fake... είναι «ηθοποιοί» στη θέση των modules των P2, P3, P4. Το FakePolicy("deny") λέει πάντα όχι, και το FakePolicy(explode=True) σκάει επίτηδες.
Το FakeTool θυμάται αν εκτελέστηκε (self.calls). Έτσι ελέγχουμε ότι στο μπλόκο και στην έγκριση το εργαλείο δεν έτρεξε.
Τα 5 τεστ (a έως e) είναι ακριβώς οι 5 περιπτώσεις του done-check του εγγράφου σας.
"""