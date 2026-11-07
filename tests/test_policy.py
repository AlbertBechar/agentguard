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

if __name__ == "__main__":
    unittest.main()