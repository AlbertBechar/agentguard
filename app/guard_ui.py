"""Η σελίδα /guard: ο άνθρωπος βλέπει και εγκρίνει/απορρίπτει τα αιτήματα του Guard.

Το blueprint το κάνει register ο P1 στο app.py. Το AI δεν έχει εργαλείο που να φτάνει εδώ.
"""
import json
import sqlite3
from functools import wraps

from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, url_for

from . import approvals
from .db import query

bp = Blueprint("guard", __name__)


def _login_required(view):
    """Δικός μας έλεγχος login (όχι από το app.py, για να μην έχουμε κυκλικό import)."""
    @wraps(view)
    def wrapped(*a, **kw):
        if g.get("user") is None:
            if request.path.startswith("/guard/api/"):
                return jsonify(error="not logged in"), 401
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def _same_origin_only():
    """Προστασία από cross-site: ένα POST πρέπει να έρχεται από δική μας σελίδα.
    Ο browser βάζει μόνος του το Sec-Fetch-Site· μια ξένη σελίδα δεν μπορεί να το αλλάξει."""
    if request.headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
        abort(403)


def _recent_events(user):
    """Τα τελευταία 50 γεγονότα του Guard. None αν ο πίνακας δεν υπάρχει ακόμα."""
    sql = ("SELECT e.*, u.username FROM guard_events e LEFT JOIN users u ON u.id = e.user_id ")
    try:
        if user["role"] == "admin":
            return query(sql + "ORDER BY e.id DESC LIMIT 50")
        return query(sql + "WHERE e.user_id = ? ORDER BY e.id DESC LIMIT 50", (user["id"],))
    except sqlite3.OperationalError:  # "no such table: guard_events"
        return None


def _pretty(args):
    return json.dumps(args, indent=2, ensure_ascii=False, default=str)


@bp.get("/guard")
@_login_required
def page():
    pending = approvals.list_pending(g.user)
    for p in pending:
        p["args_pretty"] = _pretty(p["args"])
    return render_template("guard.html", pending=pending, events=_recent_events(g.user))


def _resolve_and_redirect(approval_id, approve):
    _same_origin_only()
    try:
        out = approvals.resolve(approval_id, g.user, approve)
    except PermissionError:
        abort(403)
    result = out["result"]
    if not isinstance(result, str):
        result = json.dumps(result, ensure_ascii=False, default=str)
    flash(f"Αίτημα #{approval_id}: {out['status']} — {result[:300]}")
    return redirect(url_for("guard.page"))


@bp.post("/guard/approve/<int:approval_id>")
@_login_required
def approve(approval_id):
    return _resolve_and_redirect(approval_id, True)


@bp.post("/guard/reject/<int:approval_id>")
@_login_required
def reject(approval_id):
    return _resolve_and_redirect(approval_id, False)


@bp.get("/guard/api/pending")
@_login_required
def api_pending():
    pending = approvals.list_pending(g.user)
    return jsonify(count=len(pending), pending=pending)
