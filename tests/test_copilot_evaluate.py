"""Τεστ για copilot/evaluate.py (μετρητικό): score, run_once, offline, lookups_stats, αναφορά και CLI."""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from copilot import evaluate as ev  # noqa: E402
from copilot.llm import FakeLLM  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "copilot"
GOLD = ev.load_gold()
REFERENCE = json.loads((ROOT / "examples" / "demobank" / "policy.reference.json").read_text(encoding="utf-8"))
GOOD = json.loads((FIX / "demobank.llm_response.json").read_text(encoding="utf-8"))
SCENARIOS = json.loads((FIX / "demobank.llm_scenarios.json").read_text(encoding="utf-8"))


def fake():
    return FakeLLM([{"questions": []}, GOOD, SCENARIOS])


class ScoreTests(unittest.TestCase):
    def test_reference_policy_scores_full_marks(self):
        r = ev.score(REFERENCE, GOLD)
        self.assertEqual((r["passed"], r["total"], r["failures"]), (51, 51, []))

    def test_invalid_and_empty_policies_score_zero_without_crashing(self):
        for bad in ({}, {"schema": "nope"}, None, "string", {"schema": "agentguard-policy/1", "roles": ["x"], "rules": [{"id": "r"}]}):
            r = ev.score(bad, GOLD)
            self.assertEqual((r["passed"], r["total"]), (0, 51))
            self.assertIn("invalid", r)

    def test_a_broken_policy_lists_its_failures(self):
        import copy
        p = copy.deepcopy(REFERENCE)
        p["redaction_rules"]["always_redact_fields"] = []
        r = ev.score(p, GOLD)
        self.assertLess(r["passed"], 51)
        self.assertTrue({"R01", "R02", "R03"} <= {f["id"] for f in r["failures"]})
        self.assertTrue(all(f["reason"] for f in r["failures"]))

    def test_gold_file_is_the_one_written_by_the_human(self):
        self.assertEqual(len(GOLD), 51)
        self.assertEqual(GOLD[0]["id"], "N01")


class LookupStatsTests(unittest.TestCase):
    def test_counts_valid_lookups_and_stubs(self):
        s = ev.lookups_stats(REFERENCE, ["account_owner_id", "from_account_owner_id", "ticket_customer_id"], [])
        self.assertEqual((s["provided"], s["valid_lookups"], s["stub_needed"]), (3, 3, []))

    def test_lookup_with_an_error_issue_does_not_count(self):
        issues = [{"level": "error", "code": "lookup.table_missing", "lookup": "account_owner_id", "message": "x"}]
        s = ev.lookups_stats(REFERENCE, ["account_owner_id", "ticket_customer_id"], issues)
        self.assertEqual((s["valid_lookups"], s["provided_without_lookup"]), (1, ["account_owner_id"]))

    def test_missing_lookup_means_stub_needed(self):
        import copy
        p = copy.deepcopy(REFERENCE)
        del p["lookups"]["ticket_customer_id"]
        s = ev.lookups_stats(p, ["account_owner_id", "ticket_customer_id"], [])
        self.assertEqual((s["valid_lookups"], s["stub_needed"]), (1, ["ticket_customer_id"]))


class RunTests(unittest.TestCase):
    def test_run_once_with_a_faithful_fake_llm(self):
        r = ev.run_once(fake(), GOLD)
        self.assertEqual((r["source"], r["model"], r["attempts"]), ("llm", "fake", 1))
        for key in ("first_draft", "llm_before_floor", "after_floor"):
            self.assertEqual(r[key]["total"], 51)
        self.assertEqual(r["lookups"]["valid_lookups"], 3)
        self.assertEqual(r["lookups"]["stub_needed"], [])
        self.assertEqual(r["issues"]["errors"], [])
        self.assertEqual(r["after_floor"], ev.score(r["policy"], GOLD))
        self.assertGreaterEqual(r["after_floor"]["passed"], r["llm_before_floor"]["passed"] - 0)   # το floor μόνο σφίγγει
        json.dumps(r)

    def test_floor_never_adds_allowed_calls_so_it_cannot_gain_on_allow_scenarios(self):
        r = ev.run_once(fake(), GOLD)
        before_fail = {f["id"] for f in r["llm_before_floor"]["failures"]}
        after_fail = {f["id"] for f in r["after_floor"]["failures"]}
        newly_failing = after_fail - before_fail
        by_id = {s["id"]: s for s in GOLD}
        # ό,τι «χάλασε» μετά το floor μπορεί να είναι μόνο σενάριο που περιμένει allow (το floor σφίγγει)
        self.assertTrue(all(by_id[i].get("expect") == "allow" or by_id[i]["kind"] == "redact" for i in newly_failing), newly_failing)

    def test_run_once_with_a_useless_llm_falls_back_to_offline(self):
        r = ev.run_once(FakeLLM([{"questions": []}, "garbage", "garbage", "garbage", {"scenarios": []}]), GOLD)
        self.assertEqual(r["source"], "offline")
        self.assertIsNone(r["llm_before_floor"])
        self.assertEqual(r["after_floor"]["total"], 51)

    def test_offline_policy_never_opens_a_write_tool_but_does_open_reads_without_ownership(self):
        off = ev.run_offline(GOLD)
        self.assertEqual(off["source"], "offline")
        self.assertEqual(off["errors"], [])
        by_id = {s["id"]: s for s in GOLD}
        wrongly_allowed = [f["id"] for f in off["after_floor"]["failures"] if by_id[f["id"]].get("expect") == "deny"]
        self.assertTrue(wrongly_allowed)                                                      # το όριο υπάρχει και το λέμε ρητά
        read_tools = {"get_account", "list_transactions", "get_statement", "read_support_ticket"}
        self.assertEqual({by_id[i]["tool"] for i in wrongly_allowed} - read_tools, set())      # ΠΟΤΕ εγγραφή/εξωτερικό/επικίνδυνο
        too_strict = [f["id"] for f in off["after_floor"]["failures"] if by_id[f["id"]].get("expect") == "allow"]
        self.assertTrue(too_strict)                                                           # κλείνει και νόμιμες εγγραφές (χρειάζεται άνθρωπο)
        self.assertGreater(off["after_floor"]["passed"], 25)

    def test_human_answers_follow_the_requirements(self):
        s = ev._new_session("offline", ev.DEMO)
        ans = ev.answers_for(s)
        keys = {q["id"]: (q["key"], q.get("tool")) for q in s.questions()}
        self.assertEqual({keys[i] for i in ans}, {("allow_tool", "send_email"), ("unconditional", None)})
        self.assertNotIn(("allow_tool", "run_sql"), {keys[i] for i in ans})                  # run_sql/fetch_url μένουν «σε κανέναν»


class SummaryAndCliTests(unittest.TestCase):
    def test_evaluate_demobank_summary_and_report(self):
        result = ev.evaluate_demobank(fake, runs=2)
        s = result["summary"]
        self.assertEqual((s["runs"], s["gold_total"], s["provided_attributes"]), (2, 51, 3))
        self.assertEqual(len(s["after_floor_passed"]), 2)
        text = ev.format_report(result)
        for part in ("Gold scenarios: 51", "offline (heuristics only)", "After the floor:", "valid lookups"):
            self.assertIn(part, text)
        self.assertEqual(ev.evaluate_demobank(None, runs=3)["runs"], [])                      # χωρίς LLM: μόνο offline

    def test_range_formatting(self):
        self.assertEqual(ev._range([40, 40, 40]), "40")
        self.assertEqual(ev._range([38, 44, 41]), "38-44 (median 41)")

    def test_cli_offline_writes_json_and_never_prints_a_key(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"AI_STUDIO_API_KEY": "SECRET-KEY-VALUE-123"}):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = ev.main(["--offline", "--out", tmp])
            self.assertEqual(code, 0)
            data = json.loads((Path(tmp) / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(data["gold_total"], 51)
            self.assertNotIn("SECRET-KEY-VALUE-123", out.getvalue() + json.dumps(data))

    def test_cli_without_key_says_it_was_not_tested_with_a_real_llm(self):
        env = {k: v for k, v in os.environ.items() if k != "AI_STUDIO_API_KEY"}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, env, clear=True):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = ev.main(["--out", tmp, "--env-file", str(Path(tmp) / "no.env")])
            self.assertEqual(code, 0)
            self.assertIn("δεν δοκιμάστηκε με πραγματικό LLM", out.getvalue())

    def test_env_file_loader_does_not_override_and_ignores_other_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / ".env"
            f.write_text("OTHER=1\nAI_STUDIO_API_KEY=from-file\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AI_STUDIO_API_KEY", None)
                ev._load_env_key(f)
                self.assertEqual(os.environ["AI_STUDIO_API_KEY"], "from-file")
                os.environ["AI_STUDIO_API_KEY"] = "already"
                ev._load_env_key(f)
                self.assertEqual(os.environ["AI_STUDIO_API_KEY"], "already")
                os.environ.pop("AI_STUDIO_API_KEY", None)


if __name__ == "__main__":
    unittest.main()
