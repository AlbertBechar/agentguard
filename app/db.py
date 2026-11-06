import os
import sqlite3

from flask import g

DB_PATH = os.environ.get("DB_PATH", "/data/eclass.db")


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = [dict(r) for r in cur.fetchall()]
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid


def audit(actor_id, action, details="", via="web"):
    execute(
        "INSERT INTO audit_log (actor_id, via, action, details) VALUES (?, ?, ?, ?)",
        (actor_id, via, action, details[:2000]),
    )
