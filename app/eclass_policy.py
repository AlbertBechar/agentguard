"""
app/eclass_policy.py
Ρόλος P2: Πολιτική ασφάλειας, έλεγχος πρόσβασης (RBAC/Ownership) και redaction.
"""
from app.db import query
from app.guard_types import Decision
from app.tools import _find_course, _find_user

# Εργαλεία που επιστρέφουν περιεχόμενο από άλλους (πιθανό source για Indirect Prompt Injection) -> Taint = True.
UNTRUSTED_TOOLS = {
    "read_forum", "get_course", "get_submissions", "read_messages",
    "get_exercise_attempts", "list_assignments", "get_exercise", "fetch_url"
}

# Κρίσιμα εργαλεία τροποποίησης κατάστασης/δεδομένων -> Απαιτούν έγκριση αν tainted.
HIGH_RISK_TOOLS = {
    "update_user", "reset_password", "create_user", "delete_user", "enroll_user",
    "grade_submission", "set_final_grade", "set_component_grade", "publish_grades",
    "send_message", "add_material", "post_announcement"
}


# ---------------------------------------------------------------------------
# Βοηθητικές Συναρτήσεις Ελέγχου Ιδιοκτησίας (Ownership Helpers)
# ---------------------------------------------------------------------------

def _is_enrolled(user_id: int, course_id: int) -> bool:
    """Επιστρέφει True αν ο φοιτητής είναι εγγεγραμμένος στο μάθημα."""
    row = query(
        "SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?",
        (user_id, course_id),
        one=True,
    )
    return row is not None


def _is_course_teacher(user_id: int, course_id: int) -> bool:
    """Επιστρέφει True αν ο καθηγητής διδάσκει το μάθημα."""
    row = query(
        "SELECT 1 FROM courses WHERE id = ? AND teacher_id = ?",
        (course_id, user_id),
        one=True,
    )
    return row is not None


def _has_course_access(user: dict, course_id: int) -> bool:
    """Ελέγχει αν ο χρήστης έχει νόμιμη πρόσβαση στο μάθημα βάσει ρόλου."""
    role = user.get("role")
    if role == "admin":
        return True
    if role == "teacher":
        return _is_course_teacher(user["id"], course_id)
    if role == "student":
        return _is_enrolled(user["id"], course_id)
    return False


def _resolve_course(course_ref) -> dict | None:
    """Επιλύει το course_ref σε εγγραφή μαθήματος."""
    if course_ref is None:
        return None
    try:
        return _find_course(course_ref)
    except Exception:
        return None


def _resolve_user(user_ref) -> dict | None:
    """Επιλύει το user_ref σε εγγραφή χρήστη."""
    if user_ref is None:
        return None
    try:
        return _find_user(user_ref)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Κανόνες ανά Εργαλείο / Ομάδα Εργαλείων
# ---------------------------------------------------------------------------

def _check_power_tools(user: dict, tool: str, args: dict) -> Decision:
    # run_sql και fetch_url απαγορεύονται αυστηρά σε όλους μέσω chatbot
    return Decision("deny", reason=f"{tool} is forbidden via chatbot", rule="power_tools.deny_all")


def _check_users(user: dict, tool: str, args: dict) -> Decision:
    role = user.get("role")

    if tool == "list_users":
        if role == "admin":
            return Decision("allow")
        return Decision("deny", reason="Only admin can list all users", rule="users.list.admin_only")

    if tool == "get_user":
        target = _resolve_user(args.get("user_ref"))
        if not target:
            return Decision("deny", reason="User not found", rule="users.get.not_found")
        if role in ("admin", "teacher") or target["id"] == user["id"]:
            return Decision("allow")
        return Decision("deny", reason="Students can only view their own profile", rule="users.get.self_only")

    if tool == "update_user":
        target = _resolve_user(args.get("user_ref"))
        if not target:
            return Decision("deny", reason="User not found", rule="users.update.not_found")
        if role == "admin":
            return Decision("allow")
        # Φοιτητές και καθηγητές επιτρέπεται να αλλάξουν μόνο το δικό τους προφίλ
        if target["id"] != user["id"]:
            return Decision("deny", reason="Cannot update other users", rule="users.update.self_only")
        # Απαγορεύεται σε μη-admin να αλλάξουν role, admin_notes, iban
        disallowed = {"role", "admin_notes", "iban"}
        if any(args.get(field) is not None for field in disallowed):
            return Decision("deny", reason="Cannot modify restricted fields", rule="users.update.restricted_fields")
        return Decision("allow")

    if tool == "reset_password":
        if role == "admin":
            return Decision("allow")
        return Decision("deny", reason="Password reset via chatbot is admin-only", rule="users.reset_pw.admin_only")

    if tool in ("create_user", "delete_user"):
        if role == "admin":
            return Decision("allow")
        return Decision("deny", reason=f"Only admin can {tool}", rule="users.manage.admin_only")

    if tool == "enroll_user":
        if role == "admin":
            return Decision("allow")
        return Decision("deny", reason="Only admin can enroll users", rule="courses.enroll.admin_only")

    return Decision("deny", reason="Unknown user operation", rule="users.unknown")


def _check_courses_and_content(user: dict, tool: str, args: dict) -> Decision:
    role = user.get("role")

    if tool == "list_courses":
        # ΠΛΕΟΝ ΕΠΙΤΡΕΠΕΤΑΙ ΣΕ ΟΛΟΥΣ. Η redact θα κόψει τα μαθήματα που δεν έχει εγγραφεί.
        return Decision("allow")

    course = _resolve_course(args.get("course_ref"))
    if not course:
        return Decision("deny", reason="Course not found", rule="courses.not_found")

    
    has_access = _has_course_access(user, course["id"])

    if tool in ("get_course", "read_forum", "post_forum", "list_assignments", "list_exercises"):
        if has_access:
            return Decision("allow")
        return Decision("deny", reason="Access denied: not enrolled or teaching this course", rule="courses.access_denied")

    if tool in ("add_material", "post_announcement"):
        if role == "admin" or (role == "teacher" and _is_course_teacher(user["id"], course["id"])):
            return Decision("allow")
        return Decision("deny", reason="Only course teachers or admin can add materials/announcements", rule="courses.teacher_only")

    return Decision("deny", reason="Unknown course operation", rule="courses.unknown")


def _check_assignments_and_grades(user: dict, tool: str, args: dict) -> Decision:
    role = user.get("role")

    if tool == "submit_assignment":

        # Μόνο φοιτητές επιτρέπεται να υποβάλλουν εργασίες
        if user.get("role") != "student":
            return Decision("deny", reason="Only students can submit assignments", rule="assignments.submit.student_only")

        student_ref = args.get("student_ref")
        target_student = _resolve_user(student_ref) if student_ref else user
        if not target_student or target_student["id"] != user["id"]:
            return Decision("deny", reason="Cannot submit assignment for another student", rule="assignments.submit.self_only")

        # Εύρεση του μαθήματος της εργασίας
        assignment_id = args.get("assignment_id")
        row = query("SELECT course_id FROM assignments WHERE id = ?", (assignment_id,), one=True)
        if not row or not _has_course_access(user, row["course_id"]):
            return Decision("deny", reason="Not enrolled in the course for this assignment", rule="assignments.submit.access_denied")
        return Decision("allow")

    if tool == "get_submissions":
        assignment_id = args.get("assignment_id")
        row = query("SELECT course_id FROM assignments WHERE id = ?", (assignment_id,), one=True)
        if not row:
            return Decision("deny", reason="Assignment not found", rule="assignments.not_found")
        if role == "admin" or (role == "teacher" and _is_course_teacher(user["id"], row["course_id"])):
            return Decision("allow")
        return Decision("deny", reason="Only course teachers can view all submissions", rule="assignments.submissions.teacher_only")

    if tool == "grade_submission":
        submission_id = args.get("submission_id")
        row = query(
            "SELECT a.course_id FROM submissions s JOIN assignments a ON a.id = s.assignment_id WHERE s.id = ?",
            (submission_id,),
            one=True,
        )
        if not row:
            return Decision("deny", reason="Submission not found", rule="submissions.not_found")
        if role == "admin" or (role == "teacher" and _is_course_teacher(user["id"], row["course_id"])):
            return Decision("allow")
        return Decision("deny", reason="Cannot grade submission for course you do not teach", rule="grades.write.teacher_only")

    if tool in ("set_final_grade", "set_component_grade", "publish_grades", "get_gradebook"):
        course = _resolve_course(args.get("course_ref"))
        if not course:
            return Decision("deny", reason="Course not found", rule="grades.course_not_found")
        if role == "admin" or (role == "teacher" and _is_course_teacher(user["id"], course["id"])):
            return Decision("allow")
        return Decision("deny", reason="Teacher access required for this course's gradebook", rule="grades.manage.teacher_only")

    if tool == "get_grades":
        student_ref = args.get("student_ref")
        target_student = _resolve_user(student_ref) if student_ref else None

        if role == "student":
            # Ο φοιτητής πρέπει ρητά να βλέπει μόνο τον εαυτό του
            if target_student and target_student["id"] != user["id"]:
                return Decision("deny", reason="Students can only view their own grades", rule="grades.read.self_only")
            if not target_student and student_ref is not None:
                return Decision("deny", reason="Student not found", rule="grades.read.not_found")
            return Decision("allow")

        if role == "teacher":
            course = _resolve_course(args.get("course_ref"))
            if course and not _is_course_teacher(user["id"], course["id"]):
                return Decision("deny", reason="Cannot view grades for course you do not teach", rule="grades.read.teacher_course")
            return Decision("allow")

        if role == "admin":
            return Decision("allow")

    return Decision("deny", reason="Unknown grade operation", rule="grades.unknown")


def _check_exercises(user: dict, tool: str, args: dict) -> Decision:
    role = user.get("role")
    exercise_id = args.get("exercise_id")
    ex = query("SELECT * FROM exercises WHERE id = ?", (exercise_id,), one=True) if exercise_id else None

    if not ex:
        return Decision("deny", reason="Exercise not found", rule="exercises.not_found")

    course_id = ex["course_id"]

    if tool == "get_exercise":
        # Περιέχει τις σωστές απαντήσεις -> Ποτέ σε φοιτητές
        if role == "admin" or (role == "teacher" and _is_course_teacher(user["id"], course_id)):
            return Decision("allow")
        return Decision("deny", reason="Students cannot inspect full exercise with answer keys", rule="exercises.answers.teacher_only")

    if tool == "get_exercise_attempts":
        if role == "admin" or (role == "teacher" and _is_course_teacher(user["id"], course_id)):
            return Decision("allow")
        return Decision("deny", reason="Only course teachers can inspect exercise attempts", rule="exercises.attempts.teacher_only")

    if tool == "submit_exercise":
        if role != "student":
            return Decision("deny", reason="Only students submit exercises", rule="exercises.submit.student_only")
        student_ref = args.get("student_ref")
        target_student = _resolve_user(student_ref) if student_ref else user
        if not target_student or target_student["id"] != user["id"]:
            return Decision("deny", reason="Cannot submit exercise on behalf of others", rule="exercises.submit.self_only")
        if not _is_enrolled(user["id"], course_id):
            return Decision("deny", reason="Not enrolled in the course for this exercise", rule="exercises.submit.not_enrolled")
        if not ex["is_open"]:
            return Decision("deny", reason="Cannot submit to closed exercise", rule="exercises.submit.closed")
        return Decision("allow")

    return Decision("deny", reason="Unknown exercise operation", rule="exercises.unknown")


def _check_messages(user: dict, tool: str, args: dict) -> Decision:
    if tool == "read_messages":
        user_ref = args.get("user_ref")
        target = _resolve_user(user_ref) if user_ref else user
        if not target or target["id"] != user["id"]:
            return Decision("deny", reason="Users can only read their own private messages", rule="messages.read.self_only")
        return Decision("allow")

    if tool == "send_message":
        from_user = args.get("from_user")
        sender = _resolve_user(from_user) if from_user else user
        if not sender or sender["id"] != user["id"]:
            return Decision("deny", reason="Cannot forge sender in messages", rule="messages.send.spoofing_denied")
        return Decision("allow")

    return Decision("deny", reason="Unknown message operation", rule="messages.unknown")


# ---------------------------------------------------------------------------
# Κεντρικό Registry & Entry Point
# ---------------------------------------------------------------------------

_ROUTERS = {
    "run_sql": _check_power_tools,
    "fetch_url": _check_power_tools,
    "list_users": _check_users,
    "get_user": _check_users,
    "update_user": _check_users,
    "reset_password": _check_users,
    "create_user": _check_users,
    "delete_user": _check_users,
    "enroll_user": _check_users,
    "list_courses": _check_courses_and_content,
    "get_course": _check_courses_and_content,
    "read_forum": _check_courses_and_content,
    "post_forum": _check_courses_and_content,
    "add_material": _check_courses_and_content,
    "post_announcement": _check_courses_and_content,
    "list_assignments": _check_courses_and_content,
    "get_submissions": _check_assignments_and_grades,
    "submit_assignment": _check_assignments_and_grades,
    "grade_submission": _check_assignments_and_grades,
    "get_grades": _check_assignments_and_grades,
    "set_final_grade": _check_assignments_and_grades,
    "get_gradebook": _check_assignments_and_grades,
    "set_component_grade": _check_assignments_and_grades,
    "publish_grades": _check_assignments_and_grades,
    "list_exercises": _check_courses_and_content,
    "get_exercise": _check_exercises,
    "get_exercise_attempts": _check_exercises,
    "submit_exercise": _check_exercises,
    "read_messages": _check_messages,
    "send_message": _check_messages,
}


def check(user: dict, tool: str, args: dict, ctx=None) -> Decision:
    """
    Ελέγχει αν επιτρέπεται η κλήση του εργαλείου από τον συγκεκριμένο χρήστη.
    Επιστρέφει Decision(action="allow") ή Decision(action="deny", reason=..., rule=...).
    """
    if not isinstance(user, dict) or "role" not in user or "id" not in user:
        return Decision("deny", reason="Invalid user context", rule="security.invalid_user")

    if user.get("role") not in ("student", "teacher", "admin"):
        return Decision("deny", reason="Unknown role", rule="security.unknown_role")

    handler = _ROUTERS.get(tool)
    if not handler:
        return Decision("deny", reason=f"Unknown tool: {tool}", rule="security.unknown_tool")

    try:
        return handler(user, tool, args or {})
    except Exception as e:
        # Fail-closed: αν κάτι αποτύχει στον υπολογισμό, μπλοκάρουμε την ενέργεια
        return Decision("deny", reason=f"Policy check internal error: {e}", rule="security.fail_closed")

    # Redaction (Λογοκρισία Ευαίσθητων Δεδομένων)
# ---------------------------------------------------------------------------

# Ευαίσθητα πεδία που πρέπει να κρύβονται ανάλογα με τον ρόλο και την ιδιοκτησία
RESTRICTED_FIELDS = {
    "password_hash",
    "admin_notes",
    "amka",
    "iban",
    "id_card",
}

PERSONAL_FIELDS = {
    "phone",
    "address",
    "date_of_birth",
    "father_name",
}

def _redact_dict(user: dict, item: dict) -> dict | None:
    """Εφαρμόζει κανόνες redaction σε ένα λεξικό (π.χ. προφίλ χρήστη, βαθμού, ή μαθήματος)."""
    if not isinstance(item, dict):
        return item

    role = user.get("role")
    user_id = user.get("id")

    # 1. Διαγραφή αδημοσίευτων βαθμών (Διόρθωση leak)
    # Το κάνουμε string για να πιάσουμε το 0, το "0" και το False (λόγω SQLite)
    if role == "student" and "published" in item:
        if str(item["published"]).lower() in ("0", "false"):
            return None

    # 2. Φιλτράρισμα λίστας μαθημάτων (Διόρθωση list_courses)
    # Αναγνωρίζουμε ότι το λεξικό είναι μάθημα αν έχει id και enrollment_key
    if role == "student" and "enrollment_key" in item and "id" in item:
        if not _is_enrolled(user_id, item["id"]):
            return None

    target_id = item.get("id") or item.get("user_id") or item.get("student_id")
    is_self = (target_id is not None and target_id == user_id)

    redacted = dict(item)
    for key in list(redacted.keys()):
        # 3. Κρύβουμε το κλειδί εγγραφής μαθήματος από τους φοιτητές
        if key == "enrollment_key" and role == "student":
            redacted[key] = "[redacted]"

        elif key in RESTRICTED_FIELDS:
            if role == "admin":
                if key == "password_hash":
                    redacted[key] = "[redacted]"
            else:
                redacted[key] = "[redacted]"

        elif key in PERSONAL_FIELDS:
            if role != "admin" and not is_self:
                if role == "teacher" and key == "phone":
                    pass
                else:
                    redacted[key] = "[redacted]"

    for k, v in redacted.items():
        if isinstance(v, dict):
            redacted[k] = _redact_dict(user, v)
        elif isinstance(v, list):
            cleaned = [_redact_dict(user, x) if isinstance(x, dict) else x for x in v]
            redacted[k] = [x for x in cleaned if x is not None]

    return redacted

def redact(user: dict, tool: str, args: dict, result):
    """
    Κεντρική συνάρτηση redaction. Περιορίζει την προβολή ευαίσθητων πεδίων 
    και φιλτράρει μη εγκεκριμένα αντικείμενα (π.χ. αδημοσίευτους βαθμούς).
    """
    if result is None or isinstance(result, (str, int, float, bool)):
        return result

    try:
        if isinstance(result, list):
            cleaned = [_redact_dict(user, item) if isinstance(item, dict) else item for item in result]
            return [x for x in cleaned if x is not None]
        elif isinstance(result, dict):
            return _redact_dict(user, result)
    except Exception:
        pass

    return result