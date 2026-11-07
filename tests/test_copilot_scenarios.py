"""Τεστ για copilot/scenarios.py (σενάρια-απαιτήσεις και εκτέλεσή τους)."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.policy_engine import PolicyEngine  # noqa: E402
from copilot.llm import FakeLLM, LLMError  # noqa: E402
from copilot.scenarios import (MIN_LLM_SCENARIOS, generate_scenarios, matrix_scenarios, run_scenarios,  # noqa: E402
                               to_file_object, validate_scenario)
from copilot.tooldefs import load_tools  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "copilot"
ENGINE = PolicyEngine.from_file(ROOT / "tests" / "fixtures" / "bank.policy.json")
LLM_SCENARIOS = json.loads((FIX / "demobank.llm_scenarios.json").read_text(encoding="utf-8"))
ROLES = ["customer", "teller", "admin"]
TOOLS = load_tools(FIX / "demobank.tools.list.json")
NAMES = {t["name"] for t in TOOLS}
INTAKE = {"company": "DemoBank", "agent": "bot", "language": "el", "requirements": "REQ TEXT", "roles": ROLES,
          "tools": TOOLS, "context_attributes": {"account_owner_id": "owner of args.account_id"}, "db_schema": None}
DEC = {"roles": ROLES, "qa": [{"id": "q1", "text": "Επιτρέπεται το run_sql;", "answer": "Όχι, σε κανέναν"}]}


class RunTests(unittest.TestCase):
    def test_gold_style_scenarios_pass_on_the_bank_policy(self):
        report = run_scenarios(ENGINE, [dict(s, source="llm") for s in LLM_SCENARIOS["scenarios"]])
        self.assertEqual((report["total"], report["passed"], report["failed"]), (19, 19, []))
        self.assertEqual(report["by_source"], {"llm": {"total": 19, "passed": 19}})

    def test_wrong_context_makes_a_scenario_fail_with_a_reason(self):
        sc = copy.deepcopy(LLM_SCENARIOS["scenarios"][1])          # S02: ο πελάτης βλέπει τον δικό του λογαριασμό
        sc["context"] = {"account_owner_id": "someone_else"}       # λάθος γεγονός => ο μηχανισμός δίνει deny
        report = run_scenarios(ENGINE, [sc])
        self.assertEqual((report["passed"], len(report["failed"])), (0, 1))
        f = report["failed"][0]
        self.assertEqual((f["expected"], f["actual"]), ("allow", "deny"))
        self.assertIn("αναμενόταν allow", f["reason"])

    def test_redact_scenarios_pass_and_fail_correctly(self):
        base = next(s for s in LLM_SCENARIOS["scenarios"] if s["id"] == "S17")
        self.assertTrue(run_scenarios(ENGINE, [base])["results"][0]["ok"])
        wrong_hidden = dict(base, expect_hidden=["balance"])        # το balance φαίνεται, άρα αποτυγχάνει
        r = run_scenarios(ENGINE, [wrong_hidden])["results"][0]
        self.assertFalse(r["ok"])
        self.assertIn("balance", r["reason"])
        wrong_visible = dict(base, expect_visible=["card_number"])  # το card_number είναι κρυμμένο
        r = run_scenarios(ENGINE, [wrong_visible])["results"][0]
        self.assertFalse(r["ok"])
        self.assertIn("card_number", r["reason"])
        owner = next(s for s in LLM_SCENARIOS["scenarios"] if s["id"] == "S19")
        self.assertTrue(run_scenarios(ENGINE, [owner])["results"][0]["ok"])

    def test_redact_hidden_works_when_field_is_absent_and_for_nested_lists(self):
        sc = {"id": "R1", "kind": "redact", "user": {"id": "c2", "role": "customer"}, "tool": "get_account", "args": {},
              "context": {}, "result": {"id": "A1", "owner_id": "c1", "iban": "GR"}, "expect_hidden": ["iban"], "source": "llm"}
        self.assertTrue(run_scenarios(ENGINE, [sc])["results"][0]["ok"])   # row filter αφαιρεί όλη την εγγραφή
        nested = {"id": "R2", "kind": "redact", "user": {"id": "t1", "role": "teller"}, "tool": "list_transactions",
                  "args": {}, "context": {}, "result": [{"account_id": "A1", "card_number": "1"}, {"account_id": "A2", "card_number": "2"}],
                  "expect_hidden": ["card_number"], "expect_visible": ["account_id"], "source": "llm"}
        self.assertTrue(run_scenarios(ENGINE, [nested])["results"][0]["ok"])

    def test_a_broken_scenario_does_not_stop_the_others(self):
        good = LLM_SCENARIOS["scenarios"][0]
        broken = {"id": "B", "kind": "authorize", "user": {"id": "x", "role": "customer"}}  # λείπουν tool και expect
        report = run_scenarios(ENGINE, [broken, good])
        self.assertEqual((report["total"], report["passed"]), (2, 1))
        self.assertIn("σφάλμα εκτέλεσης", report["failed"][0]["reason"])

    def test_empty_list(self):
        self.assertEqual(run_scenarios(ENGINE, []), {"total": 0, "passed": 0, "failed": [], "results": [], "by_source": {}})


class ValidationTests(unittest.TestCase):
    def test_validate_scenario_cases(self):
        ok = LLM_SCENARIOS["scenarios"][0]
        self.assertIsNone(validate_scenario(ok, ROLES, NAMES))
        bad = [
            ("not a dict", "αντικείμενο"),
            (dict(ok, kind="weird"), "kind"),
            (dict(ok, user={"id": "x"}), "role"),
            (dict(ok, user={"id": "x", "role": "hacker"}), "άγνωστος ρόλος"),
            (dict(ok, tool="drop_db"), "άγνωστο εργαλείο"),
            (dict(ok, args="x"), "args"),
            (dict(ok, expect="maybe"), "expect"),
            ({"kind": "redact", "user": ok["user"], "tool": "get_account", "expect_hidden": ["a"]}, "result"),
            ({"kind": "redact", "user": ok["user"], "tool": "get_account", "result": {"a": 1}}, "expect_hidden"),
            ({"kind": "redact", "user": ok["user"], "tool": "get_account", "result": {"a": 1}, "expect_visible": ["zzz"]}, "υπάρχει"),
        ]
        for sc, fragment in bad:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, validate_scenario(sc, ROLES, NAMES))


class GenerateTests(unittest.TestCase):
    def test_llm_scenarios_plus_matrix_scenarios(self):
        matrix = ENGINE.matrix()
        res = generate_scenarios(INTAKE, DEC, FakeLLM([LLM_SCENARIOS]), matrix)
        llm = [s for s in res["scenarios"] if s["source"] == "llm"]
        det = [s for s in res["scenarios"] if s["source"] == "matrix"]
        self.assertEqual(len(llm), 19)
        self.assertGreaterEqual(len(llm), MIN_LLM_SCENARIOS)
        deny_cells = sum(1 for per in matrix.values() for label in per.values() if label == "deny")
        self.assertEqual(len(det), deny_cells)
        self.assertEqual(len({s["id"] for s in res["scenarios"]}), len(res["scenarios"]))   # μοναδικά id
        report = run_scenarios(ENGINE, res["scenarios"])
        self.assertEqual(report["failed"], [])
        self.assertEqual(set(report["by_source"]), {"llm", "matrix"})

    def test_scenarios_come_from_requirements_not_from_the_policy(self):
        llm = FakeLLM([LLM_SCENARIOS])
        generate_scenarios(INTAKE, DEC, llm, ENGINE.matrix())
        sent = llm.sent[0]["system"] + llm.sent[0]["user"]
        self.assertIn("REQ TEXT", sent)
        self.assertIn("Όχι, σε κανέναν", sent)                       # οι απαντήσεις του ανθρώπου
        self.assertNotIn("account.read.owner", sent)                 # κανένας κανόνας/id του policy
        self.assertNotIn("transfer.hard_limit", sent)
        self.assertNotIn('"rules"', sent)

    def test_without_llm_only_matrix_scenarios(self):
        res = generate_scenarios(INTAKE, DEC, None, ENGINE.matrix())
        self.assertTrue(res["scenarios"])
        self.assertEqual({s["source"] for s in res["scenarios"]}, {"matrix"})
        self.assertEqual(res["issues"], [])

    def test_invalid_scenarios_are_dropped_with_an_issue(self):
        data = {"scenarios": LLM_SCENARIOS["scenarios"][:3] + [{"kind": "authorize"}, {"id": "Z", "kind": "x"}]}
        res = generate_scenarios(INTAKE, DEC, FakeLLM([data]), None)
        self.assertEqual(len(res["scenarios"]), 3)
        self.assertEqual(sum(1 for i in res["issues"] if i["code"] == "scenario.invalid"), 2)
        self.assertTrue(any(i["code"] == "scenario.few" for i in res["issues"]))

    def test_duplicate_ids_are_renumbered(self):
        sc = copy.deepcopy(LLM_SCENARIOS["scenarios"][:2])
        sc[1]["id"] = sc[0]["id"]
        res = generate_scenarios(INTAKE, DEC, FakeLLM([{"scenarios": sc}]), None)
        self.assertEqual(len({s["id"] for s in res["scenarios"]}), 2)

    def test_llm_failure_is_tolerated(self):
        for llm in (FakeLLM([LLMError("down")]), FakeLLM(["not json"]), FakeLLM([{"scenarios": "nope"}]), FakeLLM([])):
            with self.subTest():
                res = generate_scenarios(INTAKE, DEC, llm, ENGINE.matrix())
                self.assertEqual({s["source"] for s in res["scenarios"]}, {"matrix"})
                self.assertTrue(any(i["code"] == "scenario.llm_error" for i in res["issues"]))

    def test_matrix_scenarios_and_file_format(self):
        sc = matrix_scenarios({"t": {"a": "deny", "b": "allow", "c": "conditional"}})
        self.assertEqual(len(sc), 1)
        self.assertEqual((sc[0]["user"]["role"], sc[0]["expect"], sc[0]["context"]), ("a", "deny", {}))
        obj = to_file_object(sc)
        self.assertEqual(obj["schema"], "agentguard-scenarios/1")
        self.assertNotIn("source", obj["scenarios"][0])
        json.dumps(obj)  # JSON-serializable


if __name__ == "__main__":
    unittest.main()
