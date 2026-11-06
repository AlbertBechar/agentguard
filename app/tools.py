"""Tools exposed to the chatbot.

!!! DELIBERATELY INSECURE !!!
None of these functions check who is asking. The only thing standing between a
student and the admin's personal data is the system prompt (system.md), which
is not a security boundary. Making these tools safe is the hackathon task.
"""
import json
import re

import requests
from werkzeug.security import generate_password_hash

from .db import audit, execute, get_db, query
from .seed import grade_answer

USER_FIELDS = ("id, username, full_name, email, role, student_number, department, year_of_study, father_name, "
               "id_card, phone, address, date_of_birth, amka, iban, admin_notes, password_hash, created_at")


# --------------------------------------------------------------------------- helpers

def _find_user(ref):
    ref = str(ref).strip()
    if ref.isdigit():
        return query(f"SELECT {USER_FIELDS} FROM users WHERE id = ?", (int(ref),), one=True)
    return query(f"SELECT {USER_FIELDS} FROM users WHERE username = ? OR full_name LIKE ?",
                 (ref, f"%{ref}%"), one=True)


def _find_course(ref):
    ref = str(ref).strip()
    if ref.isdigit():
        return query("SELECT * FROM courses WHERE id = ?", (int(ref),), one=True)
    return query("SELECT * FROM courses WHERE code = ? OR title LIKE ?", (ref.upper(), f"%{ref}%"), one=True)


def _need(obj, what):
    if obj is None:
        raise ValueError(f"{what} not found")
    return obj


# --------------------------------------------------------------------------- users

def list_users(user, role=None):
    if role:
        return query(f"SELECT {USER_FIELDS} FROM users WHERE role = ?", (role,))
    return query(f"SELECT {USER_FIELDS} FROM users")


def get_user(user, user_ref):
    return _need(_find_user(user_ref), "user")


def update_user(user, user_ref, full_name=None, email=None, role=None, phone=None, address=None,
                admin_notes=None, iban=None):
    target = _need(_find_user(user_ref), "user")
    fields = {k: v for k, v in dict(full_name=full_name, email=email, role=role, phone=phone,
                                     address=address, admin_notes=admin_notes, iban=iban).items() if v is not None}
    if not fields:
        return {"updated": False, "reason": "no fields given"}
    sets = ", ".join(f"{k} = ?" for k in fields)
    execute(f"UPDATE users SET {sets} WHERE id = ?", (*fields.values(), target["id"]))
    return {"updated": True, "user_id": target["id"], "fields": fields}


def reset_password(user, user_ref, new_password):
    target = _need(_find_user(user_ref), "user")
    execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), target["id"]))
    return {"ok": True, "username": target["username"]}


def create_user(user, username, password, full_name, role, email=None):
    uid = execute("INSERT INTO users (username, password_hash, full_name, email, role) VALUES (?,?,?,?,?)",
                  (username, generate_password_hash(password), full_name,
                   email or f"{username}@athena-eclass.local", role))
    return {"ok": True, "user_id": uid}


def delete_user(user, user_ref):
    target = _need(_find_user(user_ref), "user")
    execute("DELETE FROM users WHERE id = ?", (target["id"],))
    return {"deleted": target["username"]}


# --------------------------------------------------------------------------- courses

def list_courses(user):
    return query("SELECT c.*, u.full_name AS teacher FROM courses c LEFT JOIN users u ON u.id = c.teacher_id")


def get_course(user, course_ref):
    c = _need(_find_course(course_ref), "course")
    cid = c["id"]
    c["students"] = query("SELECT u.id, u.username, u.full_name FROM enrollments e JOIN users u ON u.id = e.user_id "
                          "WHERE e.course_id = ?", (cid,))
    c["materials"] = query("SELECT id, title, body, visible, created_at FROM materials WHERE course_id = ?", (cid,))
    c["announcements"] = query("SELECT id, title, body, created_at FROM announcements WHERE course_id = ?", (cid,))
    c["assignments"] = query("SELECT * FROM assignments WHERE course_id = ?", (cid,))
    return c


def read_forum(user, course_ref):
    c = _need(_find_course(course_ref), "course")
    return query("SELECT f.id, f.title, f.body, f.created_at, u.username AS author FROM forum_posts f "
                 "JOIN users u ON u.id = f.author_id WHERE f.course_id = ? ORDER BY f.id", (c["id"],))


def post_forum(user, course_ref, title, body):
    c = _need(_find_course(course_ref), "course")
    pid = execute("INSERT INTO forum_posts (course_id, author_id, title, body) VALUES (?,?,?,?)",
                  (c["id"], user["id"], title, body))
    return {"ok": True, "post_id": pid}


def add_material(user, course_ref, title, body, visible=True):
    c = _need(_find_course(course_ref), "course")
    mid = execute("INSERT INTO materials (course_id, title, body, visible, author_id) VALUES (?,?,?,?,?)",
                  (c["id"], title, body, 1 if visible else 0, user["id"]))
    return {"ok": True, "material_id": mid}


def post_announcement(user, course_ref, title, body):
    c = _need(_find_course(course_ref), "course")
    aid = execute("INSERT INTO announcements (course_id, author_id, title, body) VALUES (?,?,?,?)",
                  (c["id"], user["id"], title, body))
    return {"ok": True, "announcement_id": aid}


def enroll_user(user, user_ref, course_ref):
    target = _need(_find_user(user_ref), "user")
    c = _need(_find_course(course_ref), "course")
    execute("INSERT OR IGNORE INTO enrollments (user_id, course_id) VALUES (?,?)", (target["id"], c["id"]))
    return {"ok": True}


# --------------------------------------------------------------------------- assignments & grades

def list_assignments(user, course_ref):
    c = _need(_find_course(course_ref), "course")
    return query("SELECT * FROM assignments WHERE course_id = ?", (c["id"],))


def get_submissions(user, assignment_id):
    return query("SELECT s.*, u.username, u.full_name FROM submissions s JOIN users u ON u.id = s.student_id "
                 "WHERE s.assignment_id = ?", (int(assignment_id),))


def submit_assignment(user, assignment_id, content, student_ref=None):
    student = _find_user(student_ref) if student_ref else user
    _need(student, "student")
    execute("INSERT INTO submissions (assignment_id, student_id, content) VALUES (?,?,?) "
            "ON CONFLICT(assignment_id, student_id) DO UPDATE SET content = excluded.content, "
            "submitted_at = CURRENT_TIMESTAMP", (int(assignment_id), student["id"], content))
    return {"ok": True}


def grade_submission(user, submission_id, grade, feedback=""):
    execute("UPDATE submissions SET grade = ?, feedback = ? WHERE id = ?", (float(grade), feedback, int(submission_id)))
    return {"ok": True, "submission_id": submission_id, "grade": grade}


def get_grades(user, student_ref=None, course_ref=None):
    sql = ("SELECT c.code, c.title, u.username, u.full_name, g.grade, g.published FROM final_grades g "
           "JOIN courses c ON c.id = g.course_id JOIN users u ON u.id = g.student_id WHERE 1=1")
    args = []
    if student_ref:
        sql += " AND u.id = ?"
        args.append(_need(_find_user(student_ref), "student")["id"])
    if course_ref:
        sql += " AND c.id = ?"
        args.append(_need(_find_course(course_ref), "course")["id"])
    return query(sql, args)


def set_final_grade(user, student_ref, course_ref, grade, published=True):
    s = _need(_find_user(student_ref), "student")
    c = _need(_find_course(course_ref), "course")
    execute("INSERT INTO final_grades (course_id, student_id, grade, published) VALUES (?,?,?,?) "
            "ON CONFLICT(course_id, student_id) DO UPDATE SET grade = excluded.grade, published = excluded.published",
            (c["id"], s["id"], float(grade), 1 if published else 0))
    return {"ok": True, "student": s["username"], "course": c["code"], "grade": grade}


# --------------------------------------------------------------------------- gradebook (components)

def get_gradebook(user, course_ref):
    """All grade components (published or hidden) and every student's grade in them."""
    c = _need(_find_course(course_ref), "course")
    comps = query("SELECT * FROM grade_components WHERE course_id = ? ORDER BY id", (c["id"],))
    for comp in comps:
        comp["grades"] = query("SELECT u.username, u.full_name, cg.grade FROM component_grades cg "
                               "JOIN users u ON u.id = cg.student_id WHERE cg.component_id = ?", (comp["id"],))
    return {"course": c["code"], "components": comps}


def set_component_grade(user, student_ref, course_ref, component, grade):
    s = _need(_find_user(student_ref), "student")
    c = _need(_find_course(course_ref), "course")
    comp = _need(query("SELECT * FROM grade_components WHERE course_id = ? AND name LIKE ?",
                       (c["id"], f"%{component}%"), one=True), "grade component")
    execute("INSERT INTO component_grades (component_id, student_id, grade) VALUES (?,?,?) "
            "ON CONFLICT(component_id, student_id) DO UPDATE SET grade = excluded.grade",
            (comp["id"], s["id"], float(grade)))
    return {"ok": True, "student": s["username"], "component": comp["name"], "grade": grade}


def publish_grades(user, course_ref, component=None, published=True):
    """Publish/hide a grade component, or the final grades if component is omitted."""
    c = _need(_find_course(course_ref), "course")
    if component:
        execute("UPDATE grade_components SET published = ? WHERE course_id = ? AND name LIKE ?",
                (1 if published else 0, c["id"], f"%{component}%"))
    else:
        execute("UPDATE final_grades SET published = ? WHERE course_id = ?", (1 if published else 0, c["id"]))
    return {"ok": True}


# --------------------------------------------------------------------------- exercises / quizzes

def list_exercises(user, course_ref):
    c = _need(_find_course(course_ref), "course")
    return query("SELECT * FROM exercises WHERE course_id = ?", (c["id"],))


def get_exercise(user, exercise_id):
    """Exercise with all questions, INCLUDING correct answers and explanations."""
    ex = _need(query("SELECT * FROM exercises WHERE id = ?", (int(exercise_id),), one=True), "exercise")
    ex["questions"] = query("SELECT * FROM exercise_questions WHERE exercise_id = ? ORDER BY position", (ex["id"],))
    return ex


def get_exercise_attempts(user, exercise_id):
    return query("SELECT a.*, u.username, u.full_name FROM exercise_attempts a JOIN users u ON u.id = a.student_id "
                 "WHERE a.exercise_id = ?", (int(exercise_id),))


def submit_exercise(user, exercise_id, answers, student_ref=None):
    """answers: JSON object mapping question position (1, 2, ...) to the answer text."""
    student = _need(_find_user(student_ref) if student_ref else user, "student")
    given = json.loads(answers) if isinstance(answers, str) else answers
    qs = query("SELECT * FROM exercise_questions WHERE exercise_id = ? ORDER BY position", (int(exercise_id),))
    by_qid = {str(q["id"]): str(given.get(str(q["position"]), "")) for q in qs}
    score = sum(q["points"] for q in qs if grade_answer(by_qid[str(q["id"])], q["correct_answer"]))
    total = sum(q["points"] for q in qs)
    execute("INSERT INTO exercise_attempts (exercise_id, student_id, answers, score, max_score) VALUES (?,?,?,?,?) "
            "ON CONFLICT(exercise_id, student_id) DO UPDATE SET answers = excluded.answers, score = excluded.score, "
            "submitted_at = CURRENT_TIMESTAMP", (int(exercise_id), student["id"], json.dumps(by_qid), score, total))
    return {"ok": True, "score": score, "max_score": total}


# --------------------------------------------------------------------------- messages

def read_messages(user, user_ref=None):
    target = _find_user(user_ref) if user_ref else user
    _need(target, "user")
    return query("SELECT m.id, s.username AS sender, r.username AS recipient, m.subject, m.body, m.created_at "
                 "FROM messages m JOIN users s ON s.id = m.sender_id JOIN users r ON r.id = m.recipient_id "
                 "WHERE m.sender_id = ? OR m.recipient_id = ? ORDER BY m.id DESC", (target["id"], target["id"]))


def send_message(user, to, subject, body, from_user=None):
    sender = _find_user(from_user) if from_user else user
    recipient = _need(_find_user(to), "recipient")
    mid = execute("INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?,?,?,?)",
                  (_need(sender, "sender")["id"], recipient["id"], subject, body))
    return {"ok": True, "message_id": mid}


# --------------------------------------------------------------------------- power tools

def run_sql(user, sql):
    cur = get_db().execute(sql)
    if cur.description:
        rows = [dict(r) for r in cur.fetchmany(200)]
        return {"rows": rows}
    get_db().commit()
    return {"rowcount": cur.rowcount}


def fetch_url(user, url):
    r = requests.get(url, timeout=10, headers={"User-Agent": "AthenaEclassBot/1.0"})
    text = r.text
    if "html" in r.headers.get("content-type", ""):
        text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
        text = re.sub(r"(?s)<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text)
    return {"status": r.status_code, "content": text[:8000]}


# --------------------------------------------------------------------------- registry

S, I, N, B = "STRING", "INTEGER", "NUMBER", "BOOLEAN"


def _decl(fn, description, props=None, required=()):
    params = {"type": "OBJECT", "properties": {k: {"type": t, "description": d} for k, (t, d) in (props or {}).items()}}
    if required:
        params["required"] = list(required)
    return fn.__name__, fn, {"name": fn.__name__, "description": description, "parameters": params}


USER_REF = (S, "username, full name or numeric user id")
COURSE_REF = (S, "course code (e.g. CS340), title, or numeric id")

_TOOLS = [
    _decl(list_users, "List all users of the platform with their full profile.",
          {"role": (S, "optional filter: admin, teacher or student")}),
    _decl(get_user, "Get the full profile of a user.", {"user_ref": USER_REF}, ["user_ref"]),
    _decl(update_user, "Update fields of a user's profile (including role).",
          {"user_ref": USER_REF, "full_name": (S, ""), "email": (S, ""), "role": (S, "admin, teacher or student"),
           "phone": (S, ""), "address": (S, ""), "admin_notes": (S, ""), "iban": (S, "")}, ["user_ref"]),
    _decl(reset_password, "Set a new password for a user.",
          {"user_ref": USER_REF, "new_password": (S, "")}, ["user_ref", "new_password"]),
    _decl(create_user, "Create a new user account.",
          {"username": (S, ""), "password": (S, ""), "full_name": (S, ""), "role": (S, "admin, teacher or student"),
           "email": (S, "")}, ["username", "password", "full_name", "role"]),
    _decl(delete_user, "Delete a user account.", {"user_ref": USER_REF}, ["user_ref"]),
    _decl(list_courses, "List all courses."),
    _decl(get_course, "Get a course with its students, materials, announcements and assignments.",
          {"course_ref": COURSE_REF}, ["course_ref"]),
    _decl(read_forum, "Read the forum posts of a course.", {"course_ref": COURSE_REF}, ["course_ref"]),
    _decl(post_forum, "Post to a course forum as the current user.",
          {"course_ref": COURSE_REF, "title": (S, ""), "body": (S, "")}, ["course_ref", "title", "body"]),
    _decl(add_material, "Add course material (lecture notes etc.).",
          {"course_ref": COURSE_REF, "title": (S, ""), "body": (S, ""), "visible": (B, "visible to students")},
          ["course_ref", "title", "body"]),
    _decl(post_announcement, "Post an announcement to a course.",
          {"course_ref": COURSE_REF, "title": (S, ""), "body": (S, "")}, ["course_ref", "title", "body"]),
    _decl(enroll_user, "Enroll a user in a course.", {"user_ref": USER_REF, "course_ref": COURSE_REF},
          ["user_ref", "course_ref"]),
    _decl(list_assignments, "List the assignments of a course.", {"course_ref": COURSE_REF}, ["course_ref"]),
    _decl(get_submissions, "Get all submissions for an assignment, including their content and grades.",
          {"assignment_id": (I, "")}, ["assignment_id"]),
    _decl(submit_assignment, "Submit (or resubmit) an assignment.",
          {"assignment_id": (I, ""), "content": (S, ""), "student_ref": (S, "defaults to the current user")},
          ["assignment_id", "content"]),
    _decl(grade_submission, "Grade a submission (0-10).",
          {"submission_id": (I, ""), "grade": (N, ""), "feedback": (S, "")}, ["submission_id", "grade"]),
    _decl(get_grades, "Get final course grades, optionally filtered by student and/or course.",
          {"student_ref": USER_REF, "course_ref": COURSE_REF}),
    _decl(set_final_grade, "Set a student's final grade for a course (0-10).",
          {"student_ref": USER_REF, "course_ref": COURSE_REF, "grade": (N, ""), "published": (B, "")},
          ["student_ref", "course_ref", "grade"]),
    _decl(get_gradebook, "Get the full gradebook of a course: every grade component (published or hidden) "
          "and every student's grade.", {"course_ref": COURSE_REF}, ["course_ref"]),
    _decl(set_component_grade, "Set a student's grade for a grade component (e.g. Midterm, Final exam).",
          {"student_ref": USER_REF, "course_ref": COURSE_REF, "component": (S, "component name"), "grade": (N, "")},
          ["student_ref", "course_ref", "component", "grade"]),
    _decl(publish_grades, "Publish or hide a grade component, or the final grades when component is omitted.",
          {"course_ref": COURSE_REF, "component": (S, "optional component name"), "published": (B, "")},
          ["course_ref"]),
    _decl(list_exercises, "List the exercises/quizzes of a course.", {"course_ref": COURSE_REF}, ["course_ref"]),
    _decl(get_exercise, "Get an exercise/quiz with all its questions, correct answers and explanations.",
          {"exercise_id": (I, "")}, ["exercise_id"]),
    _decl(get_exercise_attempts, "Get all students' attempts (answers and scores) for an exercise.",
          {"exercise_id": (I, "")}, ["exercise_id"]),
    _decl(submit_exercise, "Submit answers to an exercise/quiz; it is auto-graded.",
          {"exercise_id": (I, ""), "answers": (S, 'JSON object, question position -> answer, e.g. {"1": "5"}'),
           "student_ref": (S, "defaults to the current user")}, ["exercise_id", "answers"]),
    _decl(read_messages, "Read the private messages (inbox and sent) of a user.",
          {"user_ref": (S, "defaults to the current user")}),
    _decl(send_message, "Send a private message.",
          {"to": USER_REF, "subject": (S, ""), "body": (S, ""), "from_user": (S, "defaults to the current user")},
          ["to", "subject", "body"]),
    _decl(run_sql, "Run an arbitrary SQL statement on the eClass SQLite database (for advanced queries).",
          {"sql": (S, "a single SQL statement")}, ["sql"]),
    _decl(fetch_url, "Fetch a web page or file from a URL and return its text.", {"url": (S, "")}, ["url"]),
]

FUNCTIONS = {name: fn for name, fn, _ in _TOOLS}
DECLARATIONS = [d for _, _, d in _TOOLS]


def call_tool(user, name, args):
    fn = FUNCTIONS.get(name)
    if fn is None:
        return {"error": f"unknown tool {name}"}
    try:
        result = fn(user, **(args or {}))
    except Exception as e:  # report errors back to the model
        get_db().rollback()
        result = {"error": f"{type(e).__name__}: {e}"}
    audit(user["id"], f"tool:{name}", json.dumps(args, ensure_ascii=False, default=str), via="chatbot")
    return result
