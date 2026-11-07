import os
import unittest

# Πριν από κάθε import της εφαρμογής: δοκιμαστική βάση και ψεύτικο κλειδί.
os.environ.setdefault("DB_PATH", "./test.db")
os.environ.setdefault("AI_STUDIO_API_KEY", "dummy")

from app.app import app  # noqa: E402
from app import approvals  # noqa: E402
from app.db import execute, query  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
