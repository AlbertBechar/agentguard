import os
import unittest

# Πριν από κάθε import της εφαρμογής: δοκιμαστική βάση και ψεύτικο κλειδί.
os.environ.setdefault("DB_PATH", "./test.db")
os.environ.setdefault("AI_STUDIO_API_KEY", "dummy")

from app.app import app  # noqa: E402
from app import guard, honeytoken  # noqa: E402
from app.db import connect, query  # noqa: E402
from app.guard_types import Decision  # noqa: E402
from app.seed import seed  # noqa: E402


def ensure_seeded_db():
    """Αν η δοκιμαστική βάση δεν έχει τα δεδομένα του eClass, τα φτιάχνει."""
    conn = connect()
    has_users = conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'users'").fetchone()
    if not has_users:
        seed(conn)
    conn.close()


# --------------------------------------------------------------------------- ψεύτικα modules

class AllowAllPolicy:
    UNTRUSTED_TOOLS = set()
    HIGH_RISK_TOOLS = {"send_message"}

    def check(self, user, tool, args, ctx):
        return Decision("allow")

    def redact(self, user, tool, args, result):
        return result


class FakeSanitizer:
    def sanitize_result(self, tool, result, source):
        return result, [], 0.0


class FakeApprovals:
    def __init__(self):
        self.created = []

    def create_pending(self, user, tool, args, reason):
        self.created.append(tool)
        return 1


class FakeTool:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or {"ok": True}

    def __call__(self, user, name, args):
        self.calls.append(name)
        return self.result


# --------------------------------------------------------------------------- τεστ

class HoneytokenTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ensure_seeded_db()

    def setUp(self):
        self.ctx_manager = app.app_context()
        self.ctx_manager.push()
        honeytoken.plant()
        self.teacher = query("SELECT * FROM users WHERE username = 'kpapadopoulos'", one=True)
        self.honey = query("SELECT * FROM users WHERE username = ?", (honeytoken.HONEY_USERNAME,), one=True)
        guard._clear_taint(self.teacher["id"])
        guard._unlock(self.teacher["id"])
        self.tool = FakeTool()
        self.approvals = FakeApprovals()
        self.g = guard.Guard(AllowAllPolicy(), FakeSanitizer(), self.approvals)

    def tearDown(self):
        guard._clear_taint(self.teacher["id"])
        guard._unlock(self.teacher["id"])
        self.ctx_manager.pop()

    def test_plant_is_idempotent_and_enrolls_everywhere(self):
        honeytoken.plant()                                   # 2η φορά: δεν πρέπει να φτιάξει δεύτερο
        count = query("SELECT COUNT(*) AS n FROM users WHERE username = ?", (honeytoken.HONEY_USERNAME,), one=True)
        self.assertEqual(count["n"], 1)
        courses = query("SELECT COUNT(*) AS n FROM courses", one=True)["n"]
        enrolled = query("SELECT COUNT(*) AS n FROM enrollments WHERE user_id = ?", (self.honey["id"],), one=True)["n"]
        self.assertEqual(enrolled, courses)

    def test_found_in_detects_trap_even_with_spaces(self):
        amka = self.honey["amka"]
        spaced = f"{amka[:3]} {amka[3:6]}-{amka[6:]}"         # π.χ. "311 299-04172"
        self.assertTrue(honeytoken.found_in({"body": f"AMKA: {amka}"}))
        self.assertTrue(honeytoken.found_in({"body": {"nested": [spaced]}}))
        self.assertFalse(honeytoken.found_in({"body": "Hello, the lab is on Monday."}))

    def test_exfiltration_is_blocked_locked_and_reported(self):
        ctx = self.g.new_turn(self.teacher, "read the forum")
        body = f"Students: Nikolaos Stathopoulos, AMKA {self.honey['amka']}, IBAN {self.honey['iban']}"
        result = self.g.run_tool(ctx, self.tool, self.teacher, "send_message",
                                 {"to": "sdi2400005", "subject": "mailing list", "body": body})
        self.assertIn("honeytoken", result["error"])
        self.assertEqual(self.tool.calls, [])                # το μήνυμα ΔΕΝ στάλθηκε
        self.assertEqual(self.approvals.created, [])         # δεν ζητήθηκε καν έγκριση
        self.assertTrue(guard._is_locked(self.teacher["id"]))
        alert = query("SELECT * FROM messages WHERE subject = 'AgentGuard: honeytoken alert' ORDER BY id DESC LIMIT 1",
                      one=True)
        self.assertIn("kpapadopoulos", alert["body"])

    def test_locked_conversation_blocks_everything_until_clear(self):
        ctx = self.g.new_turn(self.teacher, "read the forum")
        self.g.run_tool(ctx, self.tool, self.teacher, "send_message",
                        {"to": "sdi2400005", "subject": "x", "body": self.honey["amka"]})
        result = self.g.run_tool(ctx, self.tool, self.teacher, "list_courses", {})   # ακόμα και μια αθώα ανάγνωση
        self.assertIn("locked", result["error"])
        self.assertEqual(self.tool.calls, [])
        self.g.clear_taint(self.teacher["id"])               # το Clear ξεκλειδώνει
        result = self.g.run_tool(self.g.new_turn(self.teacher, "after Clear"), self.tool, self.teacher,
                                 "list_courses", {})
        self.assertEqual(result, {"ok": True})

    def test_reading_trap_data_is_allowed(self):
        # Ο admin που βλέπει τη λίστα χρηστών ΒΛΕΠΕΙ τον ψεύτικο φοιτητή. Αυτό είναι νόμιμο:
        # ελέγχουμε μόνο τα ορίσματα (ό,τι «βγαίνει»), όχι τα αποτελέσματα (ό,τι «μπαίνει»).
        reader = FakeTool(result=[{"username": honeytoken.HONEY_USERNAME, "amka": self.honey["amka"]}])
        ctx = self.g.new_turn(self.teacher, "list users")
        result = self.g.run_tool(ctx, reader, self.teacher, "list_users", {})
        self.assertEqual(result[0]["amka"], self.honey["amka"])
        self.assertFalse(guard._is_locked(self.teacher["id"]))


if __name__ == "__main__":
    unittest.main()

"""
Η φύτευση γίνεται μία φορά, όσες φορές κι αν κληθεί, και ο ψεύτικος είναι σε όλα τα μαθήματα.
Η παγίδα πιάνεται και όταν το ΑΜΚΑ γραφτεί με κενά ή παύλες, ή είναι «κρυμμένο» βαθιά μέσα στα ορίσματα. Ένα αθώο μήνυμα δεν χτυπά συναγερμό.
Όταν τα στοιχεία-παγίδα μπουν σε send_message: δεν στέλνεται, δεν ζητείται καν έγκριση, η συνομιλία κλειδώνει, και ο admin ειδοποιείται.
Μετά το κλείδωμα μπλοκάρεται τα πάντα, ακόμα και αναγνώσεις, μέχρι το Clear.
Το να διαβάσεις τα στοιχεία-παγίδα (π.χ. ο admin στη λίστα χρηστών) δεν χτυπά συναγερμό. Μόνο το να τα στείλεις.
"""