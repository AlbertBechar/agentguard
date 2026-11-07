import os
import sys
import unittest
from unittest import mock

# Πριν από κάθε import της εφαρμογής: δοκιμαστική βάση και ψεύτικο κλειδί.
os.environ.setdefault("DB_PATH", "./test.db")
os.environ.setdefault("AI_STUDIO_API_KEY", "dummy")

from app.app import app  # noqa: E402
from app import approvals  # noqa: E402
from app.db import execute, query  # noqa: E402
from app.guard_types import Decision  # noqa: E402
import app as app_pkg  # noqa: E402  (το package app/, για να βάλουμε την ψεύτικη πολιτική)


def _user(username):
    return query("SELECT * FROM users WHERE username = ?", (username,), one=True)


class PendingTest(unittest.TestCase):

    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()
        approvals.ensure_tables()
        execute("DELETE FROM guard_approvals")  # κάθε τεστ ξεκινά με άδειο πίνακα
        self.teacher = _user("kpapadopoulos")
        self.student = _user("sdi2400001")
        self.admin = _user("admin")

    def tearDown(self):
        self.ctx.pop()

    def test_create_returns_id(self):
        aid = approvals.create_pending(self.teacher, "grade_submission", {"submission_id": 1, "grade": 10}, "tainted")
        self.assertIsInstance(aid, int)
        row = query("SELECT * FROM guard_approvals WHERE id = ?", (aid,), one=True)
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["user_id"], self.teacher["id"])

    def test_duplicate_returns_same_id(self):
        a1 = approvals.create_pending(self.teacher, "grade_submission", {"submission_id": 1, "grade": 10}, "r")
        # ίδια ορίσματα με άλλη σειρά κλειδιών -> ίδιο αίτημα
        a2 = approvals.create_pending(self.teacher, "grade_submission", {"grade": 10, "submission_id": 1}, "r")
        self.assertEqual(a1, a2)
        a3 = approvals.create_pending(self.teacher, "grade_submission", {"submission_id": 1, "grade": 9}, "r")
        self.assertNotEqual(a1, a3)

    def test_list_pending_visibility(self):
        aid = approvals.create_pending(self.teacher, "send_message", {"to": "sdi2400002", "body": "hi"}, "r")

        mine = approvals.list_pending(self.teacher)
        self.assertEqual([p["id"] for p in mine], [aid])
        self.assertEqual(mine[0]["args"], {"to": "sdi2400002", "body": "hi"})  # ήδη dict

        self.assertEqual(approvals.list_pending(self.student), [])           # άλλος μη-admin: τίποτα
        self.assertIn(aid, [p["id"] for p in approvals.list_pending(self.admin)])  # admin: όλα


class FakePolicy:
    """Ψεύτικο eclass_policy: επιστρέφει ό,τι του πούμε, χωρίς να χρειάζεται το αρχείο του P2."""
    def __init__(self, action="allow", reason=""):
        self.action, self.reason = action, reason

    def check(self, user, tool, args, ctx):
        return Decision(self.action, self.reason, "fake.rule")


class ResolveTest(unittest.TestCase):

    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()
        approvals.ensure_tables()
        execute("DELETE FROM guard_approvals")
        self.teacher = _user("kpapadopoulos")
        self.student = _user("sdi2400001")
        self.admin = _user("admin")
        self.args = {"submission_id": 1, "grade": 10}
        self.aid = approvals.create_pending(self.teacher, "grade_submission", self.args, "tainted")
        # Ψεύτικο εργαλείο: μετράμε πόσες φορές καλείται, δεν αλλάζει τίποτα στη βάση.
        self.fake_tool = mock.Mock(return_value={"ok": True})
        self._patches = [mock.patch("app.approvals.call_tool", self.fake_tool)]
        self.use_policy(FakePolicy("allow"))
        for p in self._patches:
            p.start()

    def use_policy(self, policy):
        # Βάζουμε την ψεύτικη πολιτική στη θέση του app.eclass_policy (είτε υπάρχει το αρχείο είτε όχι).
        self._patches += [mock.patch.dict(sys.modules, {"app.eclass_policy": policy}),
                          mock.patch.object(app_pkg, "eclass_policy", policy, create=True)]

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        self.ctx.pop()

    def status(self):
        return query("SELECT status FROM guard_approvals WHERE id = ?", (self.aid,), one=True)["status"]

    def test_a_owner_approves_runs_once(self):
        out = approvals.resolve(self.aid, self.teacher, True)
        self.assertEqual(out, {"status": "approved", "result": {"ok": True}})
        self.fake_tool.assert_called_once()
        user_arg, tool_arg, args_arg = self.fake_tool.call_args.args
        self.assertEqual((user_arg["id"], tool_arg, args_arg), (self.teacher["id"], "grade_submission", self.args))
        self.assertEqual(self.status(), "approved")

    def test_b_other_student_gets_permission_error(self):
        with self.assertRaises(PermissionError):
            approvals.resolve(self.aid, self.student, True)
        self.fake_tool.assert_not_called()
        self.assertEqual(self.status(), "pending")  # παραμένει για τον σωστό άνθρωπο

    def test_c_reject_does_not_run(self):
        out = approvals.resolve(self.aid, self.teacher, False)
        self.assertEqual(out["status"], "rejected")
        self.fake_tool.assert_not_called()
        self.assertEqual(self.status(), "rejected")

    def test_d_double_approve_runs_once(self):
        approvals.resolve(self.aid, self.teacher, True)
        out = approvals.resolve(self.aid, self.teacher, True)
        self.assertEqual(out, {"status": "failed", "result": "not found or already resolved"})
        self.assertEqual(self.fake_tool.call_count, 1)

    def test_e_policy_deny_at_approval_fails(self):
        for p in self._patches[1:]:   # αλλάζουμε την πολιτική σε deny
            p.stop()
        self._patches = self._patches[:1]
        self.use_policy(FakePolicy("deny", "student cannot change grades"))
        for p in self._patches[1:]:
            p.start()
        out = approvals.resolve(self.aid, self.teacher, True)
        self.assertEqual(out["status"], "failed")
        self.assertIn("policy", out["result"])
        self.fake_tool.assert_not_called()
        self.assertEqual(self.status(), "failed")

    def test_f_admin_can_approve(self):
        out = approvals.resolve(self.aid, self.admin, True)
        self.assertEqual(out["status"], "approved")
        self.assertEqual(self.fake_tool.call_args.args[0]["id"], self.teacher["id"])  # τρέχει ως ο αιτών

    def test_g_missing_id(self):
        self.assertEqual(approvals.resolve(999999, self.admin, True)["status"], "failed")


class GuardPageTest(unittest.TestCase):
    """Η σελίδα /guard με τον Flask test client (ένας «ψεύτικος browser»)."""

    @classmethod
    def setUpClass(cls):
        # Προσωρινό register ΜΟΝΟ για τα τεστ. Το πραγματικό το κάνει ο P1 στο app.py.
        if "guard" not in app.blueprints:
            from app.guard_ui import bp
            app.register_blueprint(bp)

    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()
        approvals.ensure_tables()
        execute("DELETE FROM guard_approvals")
        self.teacher = _user("kpapadopoulos")
        self.student = _user("sdi2400001")
        self.client = app.test_client()
        self.fake_tool = mock.Mock(return_value={"ok": True})
        self._patches = [mock.patch("app.approvals.call_tool", self.fake_tool),
                         mock.patch.dict(sys.modules, {"app.eclass_policy": FakePolicy("allow")}),
                         mock.patch.object(app_pkg, "eclass_policy", FakePolicy("allow"), create=True)]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        self.ctx.pop()

    def login_as(self, user):
        # Γράφουμε κατευθείαν στο session (το cookie σύνδεσης), αντί να περάσουμε από τη φόρμα login.
        with self.client.session_transaction() as s:
            s["user_id"] = user["id"]

    def test_not_logged_in_redirects(self):
        r = self.client.get("/guard")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
        self.assertEqual(self.client.get("/guard/api/pending").status_code, 401)

    def test_owner_sees_request(self):
        aid = approvals.create_pending(self.teacher, "grade_submission", {"submission_id": 7, "grade": 10}, "tainted")
        self.login_as(self.teacher)
        html = self.client.get("/guard").get_data(as_text=True)
        self.assertIn(f"#{aid}", html)
        self.assertIn("grade_submission", html)
        self.assertIn(f"/guard/approve/{aid}", html)
        api = self.client.get("/guard/api/pending").get_json()
        self.assertEqual(api["count"], 1)

    def test_other_student_does_not_see_it(self):
        approvals.create_pending(self.teacher, "grade_submission", {"submission_id": 7, "grade": 10}, "tainted")
        self.login_as(self.student)
        html = self.client.get("/guard").get_data(as_text=True)
        self.assertNotIn("grade_submission", html)

    def test_approve_by_other_user_is_403(self):
        aid = approvals.create_pending(self.teacher, "grade_submission", {"submission_id": 7, "grade": 10}, "tainted")
        self.login_as(self.student)
        r = self.client.post(f"/guard/approve/{aid}")
        self.assertEqual(r.status_code, 403)
        self.fake_tool.assert_not_called()

    def test_owner_approve_runs_and_redirects(self):
        aid = approvals.create_pending(self.teacher, "grade_submission", {"submission_id": 7, "grade": 10}, "tainted")
        self.login_as(self.teacher)
        r = self.client.post(f"/guard/approve/{aid}", follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn(f"Αίτημα #{aid}: approved", r.get_data(as_text=True))
        self.fake_tool.assert_called_once()

    def test_cross_site_post_is_blocked(self):
        aid = approvals.create_pending(self.teacher, "grade_submission", {"submission_id": 7, "grade": 10}, "tainted")
        self.login_as(self.teacher)
        r = self.client.post(f"/guard/approve/{aid}", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(r.status_code, 403)
        self.fake_tool.assert_not_called()

    def test_args_are_escaped(self):
        approvals.create_pending(self.teacher, "send_message", {"body": "<script>alert(1)</script>"}, "tainted")
        self.login_as(self.teacher)
        html = self.client.get("/guard").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)


class GuardIntegrationTest(unittest.TestCase):
    """Ο πραγματικός Guard του P1 + το πραγματικό approvals.py (ψεύτικα μόνο policy/sanitizer/εργαλείο)."""

    class Policy(FakePolicy):
        UNTRUSTED_TOOLS = {"read_forum"}
        HIGH_RISK_TOOLS = {"grade_submission"}

        def redact(self, user, tool, args, result):
            return result

    def setUp(self):
        self.ctx = app.app_context()
        self.ctx.push()
        approvals.ensure_tables()
        execute("DELETE FROM guard_approvals")
        self.teacher = _user("kpapadopoulos")
        self.fake_tool = mock.Mock(return_value={"ok": True})
        self._patches = [mock.patch("app.approvals.call_tool", self.fake_tool),
                         mock.patch.dict(sys.modules, {"app.eclass_policy": self.Policy()}),
                         mock.patch.object(app_pkg, "eclass_policy", self.Policy(), create=True)]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        from app import guard
        guard._clear_taint(self.teacher["id"])
        self.ctx.pop()

    def test_tainted_high_risk_goes_to_approvals_then_runs_on_approve(self):
        from app import guard
        g_ = guard.Guard(self.Policy(), mock.Mock(), approvals)   # ΑΛΗΘΙΝΟ approvals module
        turn = guard.TurnContext(user=self.teacher, user_message="βάλε 10", tainted=True)
        guard_tool = mock.Mock()  # το call_tool που δίνει ο Guard: δεν πρέπει να κληθεί

        out = g_.run_tool(turn, guard_tool, self.teacher, "grade_submission", {"submission_id": 7, "grade": 10})

        self.assertEqual(out["status"], "approval_required")
        guard_tool.assert_not_called()
        pending = approvals.list_pending(self.teacher)
        self.assertEqual([p["id"] for p in pending], [out["approval_id"]])

        res = approvals.resolve(out["approval_id"], self.teacher, True)
        self.assertEqual(res["status"], "approved")
        self.fake_tool.assert_called_once()


if __name__ == "__main__":
    unittest.main()
