"""
agentguard/lookups.py -- τα «γεγονότα» της πολιτικής ($ctx.*) από τη βάση της εταιρίας, ΧΩΡΙΣ κώδικα από την εταιρία.

Η πολιτική περιέχει `lookups` (ένα SELECT ανά γεγονός). Εδώ:
  * sqlite_readonly(path)  : σύνδεση ΜΟΝΟ ΓΙΑ ΑΝΑΓΝΩΣΗ (file:...?mode=ro)·
  * LookupContext          : .get(name) τρέχει το SQL κατά παραγγελία (lazy, cache ανά κλήση) με ΕΠΩΝΥΜΕΣ παραμέτρους.
Ασφάλεια (βλ. 5.2 του εγγράφου): (α) στατικός έλεγχος του SQL ΠΡΙΝ την εκτέλεση (ίδιοι κανόνες 2.1β: καλούμε τη
validate_policy του Engine)· (β) read-only σύνδεση + PRAGMA query_only· (γ) όριο 1000 γραμμών· (δ) οι τιμές μπαίνουν
ΜΟΝΟ ως παράμετροι, ποτέ μέσα στο κείμενο του SQL· (ε) οποιοδήποτε σφάλμα => None και finding `lookup_error`
(ποτέ exception προς τα έξω): ένα γεγονός που λείπει κάνει τους κανόνες να δίνουν false => deny.

ΣΗΜΑΝΤΙΚΟ: η σύνδεση `db` που δίνεται στον Guard πρέπει να είναι αποκλειστικά δική του (το query_only την κάνει
read-only για όλους). Δοκιμασμένο ΜΟΝΟ σε sqlite3. Για άλλες βάσεις: read-only χρήστης + context_resolver.
Ο μετατροπέας paramstyle (qmark/format/pyformat) είναι δοκιμασμένος μόνο σε επίπεδο κειμένου, όχι σε πραγματικό driver.
"""
from __future__ import annotations

import re
import sqlite3
import sys

from app.policy_engine import SCHEMA, validate_policy

MAX_ROWS = 1000
_TOKEN = re.compile(r"'(?:[^']|'')*'|(?<![:\w]):([A-Za-z_][A-Za-z0-9_]*)")
_REF = re.compile(r"^\$(user|args)\.([A-Za-z_][A-Za-z0-9_]*)$")


def sqlite_readonly(path) -> sqlite3.Connection:
    """Σύνδεση ΜΟΝΟ ΓΙΑ ΑΝΑΓΝΩΣΗ στη βάση `path` (μπορεί να χρησιμοποιηθεί από πολλά νήματα του sidecar)."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def convert_paramstyle(sql: str, params: dict, style: str):
    """Μετατρέπει τα `:όνομα` στο paramstyle του driver. Επιστρέφει (sql, δεσμευμένες_τιμές).

    named => :όνομα (dict) · qmark => ? (tuple) · format => %s (tuple) · pyformat => %(όνομα)s (dict).
    Τα `:όνομα` μέσα σε κείμενο ('...') δεν είναι παράμετροι. Δοκιμασμένο μόνο σε επίπεδο κειμένου.
    """
    if style not in ("named", "qmark", "format", "pyformat"):
        raise ValueError(f"unsupported paramstyle {style!r}")
    if style in ("format", "pyformat"):
        sql = sql.replace("%", "%%")  # τα κυριολεκτικά % (π.χ. LIKE '%x') δεν πρέπει να διαβαστούν ως placeholders
    order: list[str] = []

    def repl(m):
        name = m.group(1)
        if name is None:
            return m.group(0)
        if name not in params:
            raise KeyError(name)
        order.append(name)
        return {"named": f":{name}", "qmark": "?", "format": "%s", "pyformat": f"%({name})s"}[style]

    out = _TOKEN.sub(repl, sql)
    if style in ("qmark", "format"):
        return out, tuple(params[n] for n in order)
    return out, {n: params[n] for n in dict.fromkeys(order)}


def driver_paramstyle(db) -> str:
    mod_name = type(db).__module__.split(".")[0]
    if mod_name == "sqlite3":
        return "named"
    mod = sys.modules.get(mod_name)
    style = getattr(mod, "paramstyle", "named")
    return style if style in ("named", "qmark", "format", "pyformat") else "named"


def _dig(source, field):
    return source.get(field) if isinstance(source, dict) else None


class LookupContext:
    """Δίνει `.get(name)` για τα γεγονότα που έχουν lookup. Δεν πετά ποτέ exception."""

    def __init__(self, lookups, db, user, tool, args, findings: list | None = None, paramstyle: str | None = None):
        self.lookups = lookups if isinstance(lookups, dict) else {}
        self.db = db
        self.user = user if isinstance(user, dict) else {}
        self.args = args if isinstance(args, dict) else {}
        self.findings = findings if findings is not None else []
        self.paramstyle = paramstyle
        self._cache: dict = {}
        self._readonly_set = False

    def has(self, name) -> bool:
        return name in self.lookups

    def _fail(self, name, message):
        self.findings.append({"type": "lookup_error", "lookup": name, "error": str(message)[:200]})
        return None

    @staticmethod
    def static_errors(name, lookup) -> list[str]:
        """Ξανακάνει τον στατικό έλεγχο ασφαλείας του SQL (ίδιοι κανόνες 2.1β) με τη validate_policy του Engine."""
        mini = {"schema": SCHEMA, "roles": ["r"], "rules": [{"id": "x", "tools": ["t"], "roles": ["r"], "effect": "allow"}],
                "lookups": {name: lookup}}
        return [f'{v["path"]}: {v["message"]}' for v in validate_policy(mini)
                if v["level"] == "error" and v["path"].startswith("lookups")]

    def get(self, name):
        if name in self._cache:
            return self._cache[name]
        try:
            value = self._resolve(name)
        except Exception as e:  # noqa: BLE001 - ποτέ exception προς τα έξω
            value = self._fail(name, f"{type(e).__name__}: {e}")
        self._cache[name] = value
        return value

    def _resolve(self, name):
        lk = self.lookups.get(name)
        if lk is None:
            return None
        if not isinstance(lk, dict):
            return self._fail(name, "invalid lookup definition")
        problems = self.static_errors(name, lk)
        if problems:
            return self._fail(name, "rejected by the static check: " + problems[0])  # ΔΕΝ εκτελείται
        values = {}
        for pname, ref in (lk.get("params") or {}).items():
            m = _REF.match(ref) if isinstance(ref, str) else None
            if not m:
                return self._fail(name, f"invalid parameter reference for {pname}")
            v = _dig(self.user if m.group(1) == "user" else self.args, m.group(2))
            if v is None:
                return None  # τιμή που λείπει => το lookup δεν τρέχει => None => οι κανόνες που το χρειάζονται δίνουν false
            if isinstance(v, (dict, list, tuple, set, bytes)):
                return self._fail(name, f"parameter {pname} has an unsupported type")
            values[pname] = v
        if self.db is None:
            return self._fail(name, "no database connection was given to the Guard")
        if not self._readonly_set and isinstance(self.db, sqlite3.Connection):
            self.db.execute("PRAGMA query_only = ON")
            self._readonly_set = True
        sql, bound = convert_paramstyle(lk["sql"], values, self.paramstyle or driver_paramstyle(self.db))
        cur = self.db.cursor()
        try:
            cur.execute(sql, bound)
            returns = lk["returns"]
            if returns == "scalar":
                row = cur.fetchone()
                return None if row is None else row[0]
            if returns == "exists":
                return cur.fetchone() is not None
            if returns == "list":
                return [r[0] for r in cur.fetchmany(MAX_ROWS)]
            row = cur.fetchone()
            if row is None:
                return None
            cols = [d[0] for d in cur.description]
            return {c: row[i] for i, c in enumerate(cols)}
        finally:
            cur.close()
