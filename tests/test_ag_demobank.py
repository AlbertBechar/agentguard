"""Τεστ για το DemoBank (examples/demobank): η εφαρμογή, η reference πολιτική και τα gold σενάρια."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard.scenarios import load_scenarios, run_scenarios  # noqa: E402
from app.policy_engine import PolicyEngine, validate_policy  # noqa: E402
from examples.demobank.app import DemoBankApp, make_db  # noqa: E402

DEMO = ROOT / "examples" / "demobank"
POLICY = json.loads((DEMO / "policy.reference.json").read_text(encoding="utf-8"))
C1 = {"id": "c1", "role": "customer"}


class AppTests(unittest.TestCase):
    def setUp(self):
        self.app = DemoBankApp()

    def tearDown(self):
        self.app.close()

    def test_app_is_deliberately_unprotected(self):
        # ο πελάτης c1 διαβάζει λογαριασμό του c2 ΜΕ τον αριθμό κάρτας: δεν υπάρχει κανένας έλεγχος
        acc = self.app.call_tool(C1, "get_account", {"account_id": "A2"})
        self.assertEqual((acc["owner_id"], acc["card_number"]), ("c2", "4222222222222222"))
        before = self.app.snapshot()["balances"]
        self.app.call_tool(C1, "transfer_funds", {"from_account": "A2", "to_account": "A9", "amount": 100})
        after = self.app.snapshot()["balances"]
        self.assertEqual((before["A2"] - after["A2"], after["A9"] - before["A9"]), (100, 100))
        self.app.call_tool(C1, "update_contact", {"customer_id": "c2", "email": "evil@evil.example"})
        self.assertEqual(self.app.snapshot()["users"]["c2"]["email"], "evil@evil.example")
        self.app.call_tool(C1, "run_sql", {"query": "UPDATE users SET role = 'admin' WHERE id = 'c1'"})
        self.assertEqual(self.app.snapshot()["users"]["c1"]["role"], "admin")
        self.app.call_tool(C1, "send_email", {"to": "x@evil.example", "subject": "s", "body": "b"})
        self.assertEqual(self.app.outbox[0]["to"], "x@evil.example")
        self.app.call_tool(C1, "fetch_url", {"url": "http://evil.example"})
        self.assertEqual(self.app.fetched, ["http://evil.example"])
        self.app.call_tool(C1, "close_account", {"account_id": "A4"})
        self.assertNotIn("A4", self.app.snapshot()["balances"])

    def test_all_ten_tools_work_and_errors_become_results(self):
        names = [t["name"] for t in json.loads((DEMO / "tools.json").read_text(encoding="utf-8"))]
        self.assertEqual(len(names), 10)
        self.assertEqual(self.app.call_tool(C1, "list_transactions", {"account_id": "A1"})[0]["account_id"], "A1")
        st = self.app.call_tool(C1, "get_statement", {"account_id": "A1", "month": "2026-10"})
        self.assertEqual(st["total"], round(sum(t["amount"] for t in st["transactions"]), 2))
        self.assertIn("log in", self.app.call_tool(C1, "read_support_ticket", {"ticket_id": "T1"})["text"])
        self.assertIn("error", self.app.call_tool(C1, "get_account", {"account_id": "nope"}))
        self.assertIn("error", self.app.call_tool(C1, "no_such_tool", {}))
        self.assertIn("error", self.app.call_tool(C1, "_private", {}))
        self.assertIn("error", self.app.call_tool(C1, "get_account", {"bad_arg": 1}))

    def test_plant_and_readonly_connection_and_make_db_modes(self):
        self.app.plant(memo={"account_id": "A1", "memo": "PLANTED"}, ticket={"id": "T9", "customer_id": "c1", "text": "evil"})
        self.assertIn("PLANTED", [t["memo"] for t in self.app.call_tool(C1, "list_transactions", {"account_id": "A1"})])
        self.assertEqual(self.app.call_tool(C1, "read_support_ticket", {"ticket_id": "T9"})["text"], "evil")
        ro = self.app.readonly_connection()
        self.assertEqual(ro.execute("SELECT owner_id FROM accounts WHERE id = 'A1'").fetchone()[0], "c1")
        with self.assertRaises(Exception):
            ro.execute("UPDATE accounts SET balance = 0")
        mem = make_db(":memory:")
        self.assertEqual(mem.execute("SELECT COUNT(*) FROM users").fetchone()[0], 5)
        mem.close()

    def test_schema_file_is_the_one_of_the_spec(self):
        sql = (DEMO / "db_schema.sql").read_text(encoding="utf-8")
        for table in ("users", "accounts", "transactions", "tickets"):
            self.assertIn(f"CREATE TABLE {table}", sql)
        text = (DEMO / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("Κανένας ρόλος δεν επιτρέπεται να τρέχει run_sql ή fetch_url.", text)
        self.assertEqual(len(text.strip().splitlines()), 5)


class ReferencePolicyTests(unittest.TestCase):
    def test_reference_policy_is_valid_and_uses_lookups_without_a_resolver(self):
        self.assertEqual([v for v in validate_policy(POLICY) if v["level"] == "error"], [])
        self.assertEqual(set(POLICY["lookups"]), {"account_owner_id", "from_account_owner_id", "ticket_customer_id", "owned_account_ids"})
        self.assertTrue(any(r["when"][0]["op"] == "lte" for r in POLICY["rules"] if r["id"].startswith("transfer.")))
        warnings = [v["message"] for v in validate_policy(POLICY)]
        self.assertTrue(all("run_sql" in m or "fetch_url" in m for m in warnings))   # μόνο οι σκόπιμα κλειστοί

    def test_gold_scenarios_shape(self):
        sc = load_scenarios(DEMO / "scenarios.gold.json")
        kinds = Counter(s["id"][0] for s in sc)
        self.assertGreaterEqual(len(sc), 36)
        self.assertGreaterEqual(kinds["N"], 10)   # κανονικές χρήσεις
        self.assertGreaterEqual(kinds["D"], 14)   # παραβιάσεις
        self.assertGreaterEqual(kinds["R"], 6)    # redaction
        self.assertGreaterEqual(kinds["B"], 6)    # όρια
        self.assertEqual(len({s["id"] for s in sc}), len(sc))
        for s in sc:
            self.assertIn(s["kind"], ("authorize", "redact"))
            if s["id"][0] == "N":
                self.assertEqual(s["expect"], "allow")
            if s["id"][0] == "D":
                self.assertEqual(s["expect"], "deny")

    def test_reference_policy_passes_the_gold_scenarios(self):
        sc = load_scenarios(DEMO / "scenarios.gold.json")
        rep = run_scenarios(PolicyEngine(POLICY), sc)
        self.assertGreaterEqual(rep["passed"] / rep["total"], 0.95)
        self.assertEqual(rep["failed"], [])

    def test_gold_scenarios_catch_a_broken_policy(self):
        sc = load_scenarios(DEMO / "scenarios.gold.json")

        def broken(mutate):
            p = copy.deepcopy(POLICY)
            mutate(p)
            return run_scenarios(PolicyEngine(p), sc)
        r = broken(lambda p: [x.pop("when") for x in p["rules"] if x["id"] == "account.read.customer_own"])
        self.assertTrue({"D01", "D02", "D03"} <= {f["id"] for f in r["failed"]})
        r = broken(lambda p: p["redaction_rules"].update(always_redact_fields=[]))
        self.assertTrue({"R01", "R02", "R03"} <= {f["id"] for f in r["failed"]})
        r = broken(lambda p: [x.update(when=[{"left": "$args.amount", "op": "lte", "right": 1001}]) for x in p["rules"] if x["id"] == "transfer.customer_own_up_to_1000"])
        self.assertIn("B02", {f["id"] for f in r["failed"]})


if __name__ == "__main__":
    unittest.main()
