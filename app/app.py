"""Athena eClass - web UI.

The classic web UI enforces role-based access control properly. The chatbot
(/api/chat, see chatbot.py and tools.py) does NOT. That's the hackathon.
"""
import json
import os
from functools import wraps

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session,
                   stream_with_context, url_for)
from markdown_it import MarkdownIt
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

from . import chatbot
from .db import audit, close_db, execute, query
from .seed import grade_answer

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.teardown_appcontext(close_db)
SHOW_TOOL_CALLS = os.environ.get("SHOW_TOOL_CALLS", "false").lower() == "true"


# --------------------------------------------------------------------------- auth helpers

@app.before_request
def load_user():
    uid = session.get("user_id")
    g.user = query("SELECT * FROM users WHERE id = ?", (uid,), one=True) if uid else None


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            if request.path.startswith("/api/"):
                return jsonify(error="not logged in"), 401
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def roles(*allowed):
    def deco(view):
        @wraps(view)
        @login_required
        def wrapped(*a, **kw):
            if g.user["role"] not in allowed:
                abort(403)
            return view(*a, **kw)
        return wrapped
    return deco


def my_courses(user):
    if user["role"] == "admin":
        return query("SELECT c.*, u.full_name AS teacher FROM courses c LEFT JOIN users u ON u.id = c.teacher_id")
    if user["role"] == "teacher":
        return query("SELECT c.*, u.full_name AS teacher FROM courses c LEFT JOIN users u ON u.id = c.teacher_id "
                     "WHERE c.teacher_id = ?", (user["id"],))
    return query("SELECT c.*, u.full_name AS teacher FROM courses c JOIN enrollments e ON e.course_id = c.id "
                 "LEFT JOIN users u ON u.id = c.teacher_id WHERE e.user_id = ?", (user["id"],))


def can_view(course):
    u = g.user
    if u["role"] == "admin" or course["teacher_id"] == u["id"]:
        return True
    return query("SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?", (u["id"], course["id"]), one=True)


def can_manage(course):
    return g.user["role"] == "admin" or course["teacher_id"] == g.user["id"]


def get_course_or_404(cid):
    course = query("SELECT c.*, u.full_name AS teacher FROM courses c LEFT JOIN users u ON u.id = c.teacher_id "
                   "WHERE c.id = ?", (cid,), one=True)
    if not course:
        abort(404)
    if not can_view(course):
        abort(403)
    return course


# Markdown for user-authored content (announcements, posts, messages, materials...). Raw HTML is
# escaped and javascript:/data: links are rejected, so the classic UI stays free of stored XSS.
_md = MarkdownIt("commonmark", {"html": False, "breaks": True, "linkify": False}).enable(["table", "strikethrough"])


@app.template_filter("md")
def render_markdown(text):
    return Markup(f'<div class="md">{_md.render(text or "")}</div>')


@app.context_processor
def inject_globals():
    return {"me": g.get("user"), "can_manage": can_manage if g.get("user") else (lambda c: False)}


# --------------------------------------------------------------------------- login

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = query("SELECT * FROM users WHERE username = ?", (request.form["username"].strip(),), one=True)
        if user and check_password_hash(user["password_hash"], request.form["password"]):
            session.clear()
            session["user_id"] = user["id"]
            audit(user["id"], "login")
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------- pages

@app.route("/")
@login_required
def dashboard():
    courses = my_courses(g.user)
    ids = [c["id"] for c in courses] or [0]
    marks = ",".join("?" * len(ids))
    announcements = query(
        f"SELECT a.*, c.code FROM announcements a JOIN courses c ON c.id = a.course_id "
        f"WHERE a.course_id IN ({marks}) ORDER BY a.id DESC LIMIT 8", ids)
    deadlines = query(
        f"SELECT a.*, c.code FROM assignments a JOIN courses c ON c.id = a.course_id "
        f"WHERE a.course_id IN ({marks}) ORDER BY a.due_date", ids)
    return render_template("dashboard.html", courses=courses, announcements=announcements, deadlines=deadlines)


@app.route("/courses/<int:cid>")
@login_required
def course(cid):
    c = get_course_or_404(cid)
    vis = "" if can_manage(c) else "AND visible = 1"
    materials = query(f"SELECT * FROM materials WHERE course_id = ? {vis} ORDER BY id", (cid,))
    announcements = query("SELECT * FROM announcements WHERE course_id = ? ORDER BY id DESC", (cid,))
    assignments = query("SELECT * FROM assignments WHERE course_id = ? ORDER BY due_date", (cid,))
    posts = query("SELECT f.*, u.full_name AS author FROM forum_posts f JOIN users u ON u.id = f.author_id "
                  "WHERE course_id = ? ORDER BY f.id", (cid,))
    students = query("SELECT u.id, u.username, u.full_name, u.student_number FROM enrollments e "
                     "JOIN users u ON u.id = e.user_id WHERE e.course_id = ? ORDER BY u.username",
                     (cid,)) if can_manage(c) else []
    open_only = "" if can_manage(c) else "AND is_open = 1"
    exercises = query(f"SELECT * FROM exercises WHERE course_id = ? {open_only} ORDER BY id", (cid,))
    return render_template("course.html", c=c, materials=materials, announcements=announcements,
                           assignments=assignments, posts=posts, students=students, exercises=exercises)


@app.post("/courses/<int:cid>/materials")
@login_required
def add_material(cid):
    c = get_course_or_404(cid)
    if not can_manage(c):
        abort(403)
    execute("INSERT INTO materials (course_id, title, body, visible, author_id) VALUES (?,?,?,?,?)",
            (cid, request.form["title"], request.form["body"], 1 if request.form.get("visible") else 0, g.user["id"]))
    audit(g.user["id"], "add_material", c["code"])
    return redirect(url_for("course", cid=cid))


@app.post("/courses/<int:cid>/announcements")
@login_required
def add_announcement(cid):
    c = get_course_or_404(cid)
    if not can_manage(c):
        abort(403)
    execute("INSERT INTO announcements (course_id, author_id, title, body) VALUES (?,?,?,?)",
            (cid, g.user["id"], request.form["title"], request.form["body"]))
    audit(g.user["id"], "add_announcement", c["code"])
    return redirect(url_for("course", cid=cid))


@app.post("/courses/<int:cid>/forum")
@login_required
def add_post(cid):
    get_course_or_404(cid)
    execute("INSERT INTO forum_posts (course_id, author_id, title, body) VALUES (?,?,?,?)",
            (cid, g.user["id"], request.form["title"], request.form["body"]))
    return redirect(url_for("course", cid=cid) + "#forum")


@app.route("/assignments/<int:aid>")
@login_required
def assignment(aid):
    a = query("SELECT * FROM assignments WHERE id = ?", (aid,), one=True) or abort(404)
    c = get_course_or_404(a["course_id"])
    if can_manage(c):
        subs = query("SELECT s.*, u.username, u.full_name FROM submissions s JOIN users u ON u.id = s.student_id "
                     "WHERE assignment_id = ? ORDER BY u.username", (aid,))
        return render_template("assignment.html", a=a, c=c, subs=subs, mine=None)
    mine = query("SELECT * FROM submissions WHERE assignment_id = ? AND student_id = ?", (aid, g.user["id"]), one=True)
    return render_template("assignment.html", a=a, c=c, subs=None, mine=mine)


@app.post("/assignments/<int:aid>/submit")
@roles("student")
def submit(aid):
    a = query("SELECT * FROM assignments WHERE id = ?", (aid,), one=True) or abort(404)
    get_course_or_404(a["course_id"])
    execute("INSERT INTO submissions (assignment_id, student_id, content) VALUES (?,?,?) "
            "ON CONFLICT(assignment_id, student_id) DO UPDATE SET content = excluded.content, "
            "submitted_at = CURRENT_TIMESTAMP, grade = NULL, feedback = NULL",
            (aid, g.user["id"], request.form["content"]))
    audit(g.user["id"], "submit", str(aid))
    flash("Submission saved.")
    return redirect(url_for("assignment", aid=aid))


@app.post("/submissions/<int:sid>/grade")
@login_required
def grade(sid):
    s = query("SELECT s.*, a.course_id FROM submissions s JOIN assignments a ON a.id = s.assignment_id "
              "WHERE s.id = ?", (sid,), one=True) or abort(404)
    c = get_course_or_404(s["course_id"])
    if not can_manage(c):
        abort(403)
    execute("UPDATE submissions SET grade = ?, feedback = ? WHERE id = ?",
            (float(request.form["grade"]), request.form.get("feedback", ""), sid))
    audit(g.user["id"], "grade_submission", f"{sid} -> {request.form['grade']}")
    return redirect(url_for("assignment", aid=s["assignment_id"]))


@app.route("/grades")
@login_required
def grades():
    if g.user["role"] == "student":
        rows = query("SELECT c.code, c.title, g.grade FROM final_grades g JOIN courses c ON c.id = g.course_id "
                     "WHERE g.student_id = ? AND g.published = 1 ORDER BY c.code", (g.user["id"],))
        subs = query("SELECT a.title, c.code, s.grade, s.feedback FROM submissions s "
                     "JOIN assignments a ON a.id = s.assignment_id JOIN courses c ON c.id = a.course_id "
                     "WHERE s.student_id = ? ORDER BY c.code", (g.user["id"],))
        comps = query("SELECT c.code, gc.name, gc.weight, gc.published, cg.grade FROM component_grades cg "
                      "JOIN grade_components gc ON gc.id = cg.component_id JOIN courses c ON c.id = gc.course_id "
                      "WHERE cg.student_id = ? ORDER BY c.code, gc.id", (g.user["id"],))
        for r in comps:
            if not r["published"]:
                r["grade"] = None  # hidden until the teacher publishes it
        quiz = query("SELECT c.code, e.title, a.score, a.max_score FROM exercise_attempts a "
                     "JOIN exercises e ON e.id = a.exercise_id JOIN courses c ON c.id = e.course_id "
                     "WHERE a.student_id = ? ORDER BY c.code", (g.user["id"],))
        return render_template("grades.html", rows=rows, subs=subs, comps=comps, quiz=quiz, courses=None)
    return render_template("grades.html", rows=None, subs=None, comps=None, courses=my_courses(g.user))


@app.route("/courses/<int:cid>/gradebook", methods=["GET", "POST"])
@login_required
def gradebook(cid):
    c = get_course_or_404(cid)
    if not can_manage(c):
        abort(403)
    comps = query("SELECT * FROM grade_components WHERE course_id = ? ORDER BY id", (cid,))
    students = query("SELECT u.id, u.username, u.full_name, u.student_number FROM enrollments e "
                     "JOIN users u ON u.id = e.user_id WHERE e.course_id = ? ORDER BY u.username", (cid,))
    if request.method == "POST":
        f = request.form
        for comp in comps:
            execute("UPDATE grade_components SET published = ? WHERE id = ?",
                    (1 if f.get(f"pub_{comp['id']}") else 0, comp["id"]))
            for st in students:
                v = f.get(f"g_{comp['id']}_{st['id']}", "").strip()
                if v:
                    execute("INSERT INTO component_grades (component_id, student_id, grade) VALUES (?,?,?) "
                            "ON CONFLICT(component_id, student_id) DO UPDATE SET grade = excluded.grade",
                            (comp["id"], st["id"], float(v)))
        for st in students:
            v = f.get(f"final_{st['id']}", "").strip()
            if v:
                execute("INSERT INTO final_grades (course_id, student_id, grade, published) VALUES (?,?,?,?) "
                        "ON CONFLICT(course_id, student_id) DO UPDATE SET grade = excluded.grade, "
                        "published = excluded.published", (cid, st["id"], float(v), 1 if f.get("pub_final") else 0))
        execute("UPDATE final_grades SET published = ? WHERE course_id = ?", (1 if f.get("pub_final") else 0, cid))
        audit(g.user["id"], "update_gradebook", c["code"])
        flash("Gradebook saved.")
        return redirect(url_for("gradebook", cid=cid))
    cells = {(r["component_id"], r["student_id"]): r["grade"] for r in query(
        "SELECT cg.* FROM component_grades cg JOIN grade_components gc ON gc.id = cg.component_id "
        "WHERE gc.course_id = ?", (cid,))}
    finals = {r["student_id"]: r for r in query("SELECT * FROM final_grades WHERE course_id = ?", (cid,))}
    final_pub = any(r["published"] for r in finals.values())
    return render_template("gradebook.html", c=c, comps=comps, students=students, cells=cells,
                           finals=finals, final_pub=final_pub)


# --------------------------------------------------------------------------- exercises

def _questions(eid):
    qs = query("SELECT * FROM exercise_questions WHERE exercise_id = ? ORDER BY position", (eid,))
    for q in qs:
        q["options"] = json.loads(q["options"]) if q["options"] else None
    return qs


@app.route("/exercises/<int:eid>")
@login_required
def exercise(eid):
    ex = query("SELECT * FROM exercises WHERE id = ?", (eid,), one=True) or abort(404)
    c = get_course_or_404(ex["course_id"])
    manage = can_manage(c)
    if not manage and not ex["is_open"]:
        abort(403)
    qs = _questions(eid)
    if manage:
        attempts = query("SELECT a.*, u.username, u.full_name FROM exercise_attempts a "
                         "JOIN users u ON u.id = a.student_id WHERE exercise_id = ? ORDER BY u.username", (eid,))
        for a in attempts:
            a["answers"] = json.loads(a["answers"])
        return render_template("exercise.html", ex=ex, c=c, qs=qs, attempts=attempts, mine=None)
    mine = query("SELECT * FROM exercise_attempts WHERE exercise_id = ? AND student_id = ?",
                 (eid, g.user["id"]), one=True)
    if mine:
        mine["answers"] = json.loads(mine["answers"])
    for q in qs:  # never send answers to students
        q.pop("correct_answer")
        q.pop("explanation")
    return render_template("exercise.html", ex=ex, c=c, qs=qs, attempts=None, mine=mine)


@app.post("/exercises/<int:eid>/attempt")
@roles("student")
def attempt_exercise(eid):
    ex = query("SELECT * FROM exercises WHERE id = ?", (eid,), one=True) or abort(404)
    get_course_or_404(ex["course_id"])
    if not ex["is_open"]:
        abort(403)
    if query("SELECT 1 FROM exercise_attempts WHERE exercise_id = ? AND student_id = ?", (eid, g.user["id"]), one=True):
        flash("You have already submitted this exercise (one attempt only).")
        return redirect(url_for("exercise", eid=eid))
    qs = _questions(eid)
    answers = {str(q["id"]): request.form.get(f"q_{q['id']}", "") for q in qs}
    score = sum(q["points"] for q in qs if grade_answer(answers[str(q["id"])], q["correct_answer"]))
    execute("INSERT INTO exercise_attempts (exercise_id, student_id, answers, score, max_score) VALUES (?,?,?,?,?)",
            (eid, g.user["id"], json.dumps(answers), score, sum(q["points"] for q in qs)))
    audit(g.user["id"], "attempt_exercise", str(eid))
    flash(f"Submitted. Score: {score}.")
    return redirect(url_for("exercise", eid=eid))


@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    if request.method == "POST":
        to = query("SELECT id FROM users WHERE username = ?", (request.form["to"].strip(),), one=True)
        if not to:
            flash("No such user.")
        else:
            execute("INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?,?,?,?)",
                    (g.user["id"], to["id"], request.form["subject"], request.form["body"]))
            flash("Message sent.")
        return redirect(url_for("messages"))
    inbox = query("SELECT m.*, u.full_name AS other, u.username AS other_username FROM messages m "
                  "JOIN users u ON u.id = m.sender_id WHERE m.recipient_id = ? ORDER BY m.id DESC", (g.user["id"],))
    sent = query("SELECT m.*, u.full_name AS other, u.username AS other_username FROM messages m "
                 "JOIN users u ON u.id = m.recipient_id WHERE m.sender_id = ? ORDER BY m.id DESC", (g.user["id"],))
    return render_template("messages.html", inbox=inbox, sent=sent)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        if request.form.get("new_password"):
            if not check_password_hash(g.user["password_hash"], request.form.get("old_password", "")):
                flash("Current password is wrong.")
                return redirect(url_for("profile"))
            execute("UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(request.form["new_password"]), g.user["id"]))
            flash("Password changed.")
        else:
            execute("UPDATE users SET phone = ?, address = ? WHERE id = ?",
                    (request.form["phone"], request.form["address"], g.user["id"]))
            flash("Profile updated.")
        return redirect(url_for("profile"))
    return render_template("profile.html")


@app.route("/admin/users")
@roles("admin")
def admin_users():
    users = query("SELECT * FROM users ORDER BY role, username")
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:uid>", methods=["GET", "POST"])
@roles("admin")
def admin_edit_user(uid):
    u = query("SELECT * FROM users WHERE id = ?", (uid,), one=True) or abort(404)
    if request.method == "POST":
        f = request.form
        fields = ["full_name", "email", "role", "student_number", "department", "year_of_study", "phone",
                  "address", "admin_notes"]
        execute(f"UPDATE users SET {', '.join(k + ' = ?' for k in fields)} WHERE id = ?",
                (*[f.get(k) or None for k in fields], uid))
        if f.get("new_password"):
            execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(f["new_password"]), uid))
        audit(g.user["id"], "admin_edit_user", u["username"])
        flash("User updated.")
        return redirect(url_for("admin_edit_user", uid=uid))
    courses = query("SELECT c.code, c.title FROM enrollments e JOIN courses c ON c.id = e.course_id "
                    "WHERE e.user_id = ?", (uid,))
    return render_template("admin_user_edit.html", u=u, courses=courses)


@app.route("/admin/audit")
@roles("admin")
def admin_audit():
    log = query("SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id "
                "ORDER BY a.id DESC LIMIT 300")
    return render_template("admin_audit.html", log=log)


# --------------------------------------------------------------------------- chatbot API

@app.post("/api/chat")
@login_required
def api_chat():
    message = (request.get_json(silent=True) or {}).get("message", "").strip()
    if not message:
        return jsonify(error="empty message"), 400
    result = chatbot.chat(g.user, message)
    if not SHOW_TOOL_CALLS:
        result["tool_calls"] = []
        result["logs"] = []
    return jsonify(result)


@app.post("/api/chat/stream")
@login_required
def api_chat_stream():
    """Same as /api/chat, but streams progress as newline-delimited JSON events."""
    message = (request.get_json(silent=True) or {}).get("message", "").strip()
    if not message:
        return jsonify(error="empty message"), 400
    user = g.user

    def generate():
        for ev in chatbot.chat_events(user, message):
            if not SHOW_TOOL_CALLS and ev["type"] in ("log", "tool"):
                continue
            yield json.dumps(ev, ensure_ascii=False, default=str) + "\n"

    return Response(stream_with_context(generate()), mimetype="application/x-ndjson",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/chat/history")
@login_required
def api_chat_history():
    return jsonify(messages=chatbot.visible_history(g.user["id"]))


@app.post("/api/chat/reset")
@login_required
def api_chat_reset():
    chatbot.reset_history(g.user["id"])
    return jsonify(ok=True)


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, msg="You do not have permission to view this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="Page not found."), 404


try:
    from .guard_ui import bp as guard_bp
    app.register_blueprint(guard_bp)
except ImportError as e:
    print(f"[guard] /guard page not loaded: {e}", flush=True)   # το UI του P4 δεν έχει φτάσει ή έχει σφάλμα

"""
Το blueprint είναι ένα «πακέτο σελίδων» του Flask που μπορείς να «κουμπώσεις» σε μια εφαρμογή. Εδώ κουμπώνουμε τη σελίδα /guard του P4.
Το try/except σημαίνει ότι, αν λείπει το αρχείο του P4, η εφαρμογή συνεχίζει να τρέχει, απλώς χωρίς τη σελίδα.
Το print γράφει στα logs του Docker γιατί δεν φόρτωσε. Χωρίς αυτό, ένα λάθος στο αρχείο του P4 θα κρυβόταν σιωπηλά.
"""
