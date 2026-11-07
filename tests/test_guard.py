import os
import unittest

# Πριν από κάθε import της εφαρμογής: δοκιμαστική βάση και ψεύτικο κλειδί.
os.environ.setdefault("DB_PATH", "./test.db")
os.environ.setdefault("AI_STUDIO_API_KEY", "dummy")

from app.app import app  # noqa: E402
from app import guard  # noqa: E402
from app.db import query  # noqa: E402

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