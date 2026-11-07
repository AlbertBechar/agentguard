"""
copilot/dbschema.py -- το σχήμα της βάσης της εταιρίας (ΜΟΝΟ CREATE TABLE, ποτέ δεδομένα).

* sanitize_schema: δέχεται μόνο CREATE TABLE/INDEX. Οτιδήποτε άλλο (INSERT, SELECT, UPDATE...) απορρίπτεται,
  ώστε να μη φτάσουν ποτέ δεδομένα πελατών στο LLM. Τα σχόλια αφαιρούνται (μπορεί να κρύβουν οδηγίες/δεδομένα).
* SchemaInfo: πίνακες/στήλες + (αν φορτώνεται σε sqlite3 στη μνήμη) δυνατότητα EXPLAIN για έλεγχο των lookups.
"""
from __future__ import annotations

import re
import sqlite3

MAX_SCHEMA_CHARS = 100_000
_CREATE_OK = re.compile(r"^\s*CREATE\s+(?:UNIQUE\s+)?(?:TABLE|INDEX)\b", re.I)
_COMMENTS = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
_PLACEHOLDER = re.compile(r"(?<![:\w]):([A-Za-z_][A-Za-z0-9_]*)")


class SchemaError(ValueError):
    """Το db_schema δεν είναι έγκυρο «μόνο σχήμα»."""


def sanitize_schema(text) -> str:
    """Επιστρέφει καθαρό κείμενο με μόνο CREATE TABLE/INDEX. Αλλιώς SchemaError (fail-closed)."""
    if not isinstance(text, str):
        raise SchemaError("Το db_schema πρέπει να είναι κείμενο με εντολές CREATE TABLE.")
    if len(text) > MAX_SCHEMA_CHARS:
        raise SchemaError("Το db_schema είναι υπερβολικά μεγάλο.")
    cleaned = _COMMENTS.sub(" ", text)
    statements = [s.strip() for s in cleaned.split(";") if s.strip()]
    if not statements:
        raise SchemaError("Το db_schema είναι κενό.")
    for s in statements:
        if not _CREATE_OK.match(s):
            first = " ".join(s.split())[:40]
            raise SchemaError("Το db_schema πρέπει να περιέχει ΜΟΝΟ CREATE TABLE (ποτέ δεδομένα)· "
                              f"βρέθηκε: «{first}…»")
    return ";\n".join(statements) + ";"


class SchemaInfo:
    """Πίνακες και στήλες του σχήματος· .loaded = True αν φορτώθηκε σε sqlite3 στη μνήμη."""

    def __init__(self, schema_text: str | None):
        self.text = schema_text
        self.tables: dict[str, list[str]] = {}
        self.loaded = False
        self.error: str | None = None
        self._conn: sqlite3.Connection | None = None
        if not schema_text:
            return
        try:
            conn = sqlite3.connect(":memory:")
            conn.executescript(schema_text)  # ασφαλές: ο sanitize_schema επιτρέπει μόνο CREATE
            for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
                self.tables[name] = [r[1] for r in conn.execute(f'PRAGMA table_info("{name}")').fetchall()]
            conn.execute("PRAGMA query_only = ON")
            self._conn, self.loaded = conn, True
        except sqlite3.Error as e:
            self.error = str(e)
            for m in re.finditer(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?(\w+)[`\"\]]?\s*\((.*?)\)\s*(?:;|$)",
                                 schema_text, re.I | re.S):
                cols = [c.strip().split()[0].strip('`"[]') for c in re.split(r",\s*(?![^()]*\))", m.group(2))
                        if c.strip() and not re.match(r"(?i)\s*(primary|foreign|unique|check|constraint)\b", c)]
                self.tables[m.group(1)] = cols

    def lower_tables(self) -> dict[str, set]:
        return {t.lower(): {c.lower() for c in cols} for t, cols in self.tables.items()}

    def explain(self, sql: str) -> str | None:
        """None αν το SQL περνά EXPLAIN (με δοκιμαστικές παραμέτρους), αλλιώς το μήνυμα σφάλματος."""
        if self._conn is None:
            return "το σχήμα δεν φορτώθηκε σε sqlite3"
        params = {name: "x" for name in _PLACEHOLDER.findall(re.sub(r"'(?:[^']|'')*'", "''", sql))}
        try:
            self._conn.execute("EXPLAIN " + sql, params).fetchall()
        except sqlite3.Error as e:
            return str(e)
        return None

    def owner_columns(self) -> list[str]:
        """Στήλες που μοιάζουν με «ιδιοκτήτη» (owner_id, user_id, customer_id...) ως «πίνακας.στήλη»."""
        pat = re.compile(r"^(owner|user|customer|client|patient|student|member|author|created_by|account_holder)(_id)?$", re.I)
        return [f"{t}.{c}" for t, cols in self.tables.items() for c in cols if pat.match(c)]
