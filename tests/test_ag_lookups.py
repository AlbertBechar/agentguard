"""Τεστ για agentguard/lookups.py: γεγονότα από τη βάση χωρίς κώδικα, μόνο ανάγνωση, χωρίς SQL injection."""
from __future__ import annotations

import copy
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard import Guard, LookupContext, sqlite_readonly  # noqa: E402
from agentguard.lookups import convert_paramstyle, driver_paramstyle  # noqa: E402
from examples.demobank.app import DemoBankApp  # noqa: E402

REF = json.loads((ROOT / "examples" / "demobank" / "policy.reference.json").read_text(encoding="utf-8"))


def lk(sql, params=None, returns="scalar", description="d"):
    return {"description": description, "sql": sql, "params": params if params is not None else {}, "returns": returns}


class FakeCursor:
    def __init__(self, db):
        self.db = db
        self.description = [("id",)]

    def execute(self, sql, params=()):
        self.db.executed.append((sql, params))

    def fetchone(self):
        return (7,)

    def fetchmany(self, n):
        return [(i,) for i in range(min(n, 5))]

    def close(self):
        pass


class FakeDB:
    """Ψεύτικη «βάση» που μετρά τα SQL που εκτελούνται (δεν είναι sqlite3)."""

    def __init__(self):
        self.executed = []

    def cursor(self):
        return FakeCursor(self)


def make_db():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""CREATE TABLE accounts (id TEXT PRIMARY KEY, owner_id TEXT, balance REAL);
                          INSERT INTO accounts VALUES ('A1','c1',10),('A2','c2',20),('A3','c1',30);
                          CREATE TABLE big (n INTEGER);""")
    conn.executemany("INSERT INTO big VALUES (?)", [(i,) for i in range(1500)])
    conn.commit()
    return conn


def ctx(lookups, db, user=None, args=None, findings=None, **kw):
    return LookupContext(lookups, db, user or {"id": "c1", "role": "customer"}, "t", args or {}, findings if findings is not None else [], **kw)


class ReturnsTests(unittest.TestCase):
    def setUp(self):
        self.db = make_db()

    def test_scalar(self):
        c = ctx({"owner": lk("SELECT owner_id FROM accounts WHERE id = :a", {"a": "$args.account_id"})}, self.db, args={"account_id": "A2"})
        self.assertEqual(c.get("owner"), "c2")
        self.assertIsNone(ctx({"owner": lk("SELECT owner_id FROM accounts WHERE id = :a", {"a": "$args.account_id"})}, self.db, args={"account_id": "NOPE"}).get("owner"))

    def test_list(self):
        c = ctx({"mine": lk("SELECT id FROM accounts WHERE owner_id = :u ORDER BY id", {"u": "$user.id"}, "list")}, self.db)
        self.assertEqual(c.get("mine"), ["A1", "A3"])
        self.assertEqual(ctx({"mine": lk("SELECT id FROM accounts WHERE owner_id = :u", {"u": "$user.id"}, "list")}, self.db, user={"id": "nobody"}).get("mine"), [])

    def test_row(self):
        c = ctx({"acc": lk("SELECT id, owner_id, balance FROM accounts WHERE id = :a", {"a": "$args.account_id"}, "row")}, self.db, args={"account_id": "A1"})
        self.assertEqual(c.get("acc"), {"id": "A1", "owner_id": "c1", "balance": 10.0})
        self.assertIsNone(ctx({"acc": lk("SELECT id FROM accounts WHERE id = :a", {"a": "$args.account_id"}, "row")}, self.db, args={"account_id": "x"}).get("acc"))

    def test_exists(self):
        d = {"has": lk("SELECT 1 FROM accounts WHERE id = :a", {"a": "$args.account_id"}, "exists")}
        self.assertIs(ctx(d, self.db, args={"account_id": "A1"}).get("has"), True)
        self.assertIs(ctx(d, self.db, args={"account_id": "ZZ"}).get("has"), False)

    def test_row_limit_is_1000(self):
        c = ctx({"all": lk("SELECT n FROM big", {}, "list")}, self.db)
        self.assertEqual(len(c.get("all")), 1000)

    def test_unknown_lookup_name_and_params_from_user_and_args(self):
        c = ctx({"x": lk("SELECT balance FROM accounts WHERE id = :a AND owner_id = :u", {"a": "$args.account_id", "u": "$user.id"})}, self.db, args={"account_id": "A1"})
        self.assertEqual(c.get("x"), 10.0)
        self.assertIsNone(c.get("not_a_lookup"))
        self.assertTrue(c.has("x") and not c.has("y"))


class SafetyTests(unittest.TestCase):
    def test_none_parameter_means_no_sql_is_run(self):
        db = FakeDB()
        c = ctx({"o": lk("SELECT owner_id FROM accounts WHERE id = :a", {"a": "$args.account_id"})}, db, args={})
        self.assertIsNone(c.get("o"))
        self.assertEqual(db.executed, [])
        self.assertEqual(c.findings, [])                                  # δεν είναι σφάλμα, απλώς λείπει το γεγονός
        c2 = ctx({"o": lk("SELECT owner_id FROM accounts WHERE id = :a", {"a": "$user.missing"})}, db)
        self.assertIsNone(c2.get("o"))
        self.assertEqual(db.executed, [])

    def test_dangerous_sql_is_rejected_before_execution(self):
        bad = {"semicolon": "SELECT 1 FROM accounts; DROP TABLE accounts", "drop": "DROP TABLE accounts",
               "update": "UPDATE accounts SET balance = 0", "dash comment": "SELECT 1 FROM accounts -- x",
               "block comment": "SELECT /* x */ 1 FROM accounts", "attach": "SELECT 1 FROM accounts WHERE attach = 1",
               "question mark": "SELECT 1 FROM accounts WHERE id = ?", "pragma": "PRAGMA table_info(accounts)",
               "insert": "INSERT INTO accounts VALUES ('Z','z',1)"}
        for name, sql in bad.items():
            with self.subTest(name=name):
                db = FakeDB()
                c = ctx({"x": lk(sql, {})}, db)
                self.assertIsNone(c.get("x"))
                self.assertEqual(db.executed, [], name)                   # ΠΟΤΕ δεν έφτασε στη βάση
                self.assertEqual(c.findings[0]["type"], "lookup_error")
                self.assertIn("static check", c.findings[0]["error"])

    def test_write_attempt_fails_on_the_read_only_connection_even_if_the_validator_is_bypassed(self):
        app = DemoBankApp()
        ro = app.readonly_connection()
        evil = {"w": lk("UPDATE accounts SET balance = 0", {})}
        with mock.patch.object(LookupContext, "static_errors", return_value=[]):     # «παραβίαση του validator»
            c = ctx(evil, ro)
            self.assertIsNone(c.get("w"))
        self.assertEqual(c.findings[0]["type"], "lookup_error")
        self.assertEqual(app.snapshot()["balances"]["A1"], 5000.0)                  # η βάση ΔΕΝ άλλαξε
        app.close()

    def test_write_attempt_fails_on_an_in_memory_connection_via_query_only(self):
        db = make_db()
        with mock.patch.object(LookupContext, "static_errors", return_value=[]):
            c = ctx({"w": lk("DELETE FROM accounts", {})}, db)
            self.assertIsNone(c.get("w"))
        self.assertEqual(db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 3)
        self.assertEqual(c.findings[0]["type"], "lookup_error")

    def test_sql_injection_in_a_parameter_value_does_not_change_the_query(self):
        db = make_db()
        for payload in ("' OR 1=1 --", "A1' OR '1'='1", "x'; DROP TABLE accounts; --", "A1 OR 1=1"):
            with self.subTest(payload=payload):
                d = {"owner": lk("SELECT owner_id FROM accounts WHERE id = :a", {"a": "$args.account_id"}),
                     "all": lk("SELECT id FROM accounts WHERE owner_id = :a", {"a": "$args.account_id"}, "list")}
                c = ctx(d, db, args={"account_id": payload})
                self.assertIsNone(c.get("owner"))
                self.assertEqual(c.get("all"), [])                           # δεν «ανοίγει» όλους τους λογαριασμούς
        self.assertEqual(db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 3)

    def test_database_error_gives_none_and_a_finding_without_raising(self):
        c = ctx({"x": lk("SELECT owner_id FROM no_such_table WHERE id = :a", {"a": "$args.account_id"})}, make_db(), args={"account_id": "A1"})
        self.assertIsNone(c.get("x"))
        self.assertEqual(len(c.findings), 1)
        self.assertEqual((c.findings[0]["type"], c.findings[0]["lookup"]), ("lookup_error", "x"))
        self.assertNotIn("A1", json.dumps(c.findings))                        # τιμές παραμέτρων δεν καταγράφονται

    def test_bad_definitions_never_raise(self):
        db = make_db()
        for name, definition in {"not a dict": "SELECT 1", "bad ref": lk("SELECT 1 FROM accounts WHERE id = :a", {"a": "$ctx.x"}),
                                 "missing sql": {"params": {}, "returns": "scalar"}, "bad returns": lk("SELECT 1 FROM accounts", {}, "everything")}.items():
            with self.subTest(name=name):
                c = ctx({"x": definition}, db)
                self.assertIsNone(c.get("x"))
                self.assertTrue(c.findings)

    def test_unsupported_parameter_types_and_missing_connection(self):
        d = {"x": lk("SELECT 1 FROM accounts WHERE id = :a", {"a": "$args.v"})}
        c = ctx(d, make_db(), args={"v": {"nested": 1}})
        self.assertIsNone(c.get("x"))
        self.assertIn("unsupported type", c.findings[0]["error"])
        c2 = ctx(d, None, args={"v": "A1"})
        self.assertIsNone(c2.get("x"))
        self.assertIn("no database connection", c2.findings[0]["error"])

    def test_result_is_cached_per_call(self):
        db = FakeDB()
        c = ctx({"x": lk("SELECT id FROM accounts WHERE id = :a", {"a": "$args.account_id"})}, db, args={"account_id": "A1"}, paramstyle="qmark")
        self.assertEqual((c.get("x"), c.get("x"), c.get("x")), (7, 7, 7))
        self.assertEqual(len(db.executed), 1)

    def test_sqlite_readonly_helper(self):
        app = DemoBankApp()
        ro = sqlite_readonly(app.path)
        self.assertEqual(ro.execute("SELECT owner_id FROM accounts WHERE id = 'A1'").fetchone()[0], "c1")
        with self.assertRaises(sqlite3.OperationalError):
            ro.execute("DELETE FROM accounts")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(sqlite3.OperationalError):
                sqlite_readonly(Path(tmp) / "missing.db")                      # δεν δημιουργεί βάση
        app.close()


class ParamstyleTests(unittest.TestCase):
    SQL = "SELECT x FROM t WHERE a = :a AND b = :b AND c = ':literal' AND a2 = :a"

    def test_qmark(self):
        sql, bound = convert_paramstyle(self.SQL, {"a": 1, "b": 2}, "qmark")
        self.assertEqual(sql, "SELECT x FROM t WHERE a = ? AND b = ? AND c = ':literal' AND a2 = ?")
        self.assertEqual(bound, (1, 2, 1))

    def test_format_and_percent_escaping(self):
        sql, bound = convert_paramstyle("SELECT 1 WHERE n LIKE '%x%' AND a = :a", {"a": "v"}, "format")
        self.assertEqual(sql, "SELECT 1 WHERE n LIKE '%%x%%' AND a = %s")
        self.assertEqual(bound, ("v",))

    def test_pyformat_and_named(self):
        sql, bound = convert_paramstyle(self.SQL, {"a": 1, "b": 2}, "pyformat")
        self.assertIn("a = %(a)s AND b = %(b)s", sql)
        self.assertEqual(bound, {"a": 1, "b": 2})
        sql, bound = convert_paramstyle(self.SQL, {"a": 1, "b": 2}, "named")
        self.assertEqual(sql, self.SQL)
        self.assertEqual(bound, {"a": 1, "b": 2})

    def test_errors_and_driver_detection(self):
        with self.assertRaises(KeyError):
            convert_paramstyle("SELECT :missing", {}, "qmark")
        with self.assertRaises(ValueError):
            convert_paramstyle("SELECT 1", {}, "numeric")
        self.assertEqual(driver_paramstyle(sqlite3.connect(":memory:")), "named")
        self.assertEqual(driver_paramstyle(object()), "named")


class DemoBankScenarioTests(unittest.TestCase):
    def test_foreign_account_is_denied_with_a_real_lookup_in_sqlite(self):
        app = DemoBankApp()
        g = Guard.from_policy(REF, db=app.readonly_connection(), audit_path=None)
        call = g.wrap(app.call_tool)
        c1 = {"id": "c1", "role": "customer"}
        self.assertEqual(call("s", c1, "get_account", {"account_id": "A2"})["status"], "denied")      # ξένος
        self.assertEqual(call("s", c1, "get_account", {"account_id": "A3"})["status"], "ok")          # δικός του, δεύτερος λογαριασμός
        tx = call("s", c1, "list_transactions", {"account_id": "A1"})
        self.assertEqual(tx["status"], "ok")
        self.assertTrue(all(t["account_id"] == "A1" for t in tx["result"]))
        self.assertEqual(call("s", c1, "transfer_funds", {"from_account": "A2", "to_account": "A9", "amount": 10})["status"], "denied")
        self.assertEqual(app.snapshot()["balances"]["A2"], 20000.0)                                   # τίποτα δεν μετακινήθηκε
        app.close()

    def test_lookup_findings_reach_the_guard_output_and_audit(self):
        app = DemoBankApp()
        broken = copy.deepcopy(REF)
        broken["lookups"]["account_owner_id"]["sql"] = "SELECT owner_id FROM ghost_table WHERE id = :account_id"
        g = Guard.from_policy(broken, db=app.readonly_connection(), audit_path=None)
        out = g.call("s", {"id": "c1", "role": "customer"}, "get_account", {"account_id": "A1"}, app.call_tool)
        self.assertEqual(out["status"], "denied")                                    # γεγονός που λείπει => deny
        self.assertEqual([f["type"] for f in out["findings"]], ["lookup_error"])
        self.assertEqual(g.audit_events()[0]["findings"], ["lookup_error"])
        app.close()


if __name__ == "__main__":
    unittest.main()
