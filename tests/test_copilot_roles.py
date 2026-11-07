"""Διόρθωση N11: οι ερωτήσεις «ποιοι ρόλοι επιτρέπονται» δέχονται ΠΟΛΛΑΠΛΕΣ επιλογές και παράγουν κανόνα με πολλούς ρόλους."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import builtins  # noqa: E402

from app.policy_engine import PolicyEngine  # noqa: E402
from copilot import CopilotSession, FakeLLM  # noqa: E402
from copilot import evaluate as ev  # noqa: E402
from copilot.cli import main as cli_main  # noqa: E402
from copilot.dbschema import SchemaInfo, sanitize_schema  # noqa: E402
from copilot.floor import apply_floor  # noqa: E402
from copilot.heuristics import analyze_tools  # noqa: E402
from copilot.questions import (build_questions, confirmed_open_tools, decisions_from_answers, parse_access,  # noqa: E402
                               _t)
from copilot.tooldefs import load_tools  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "copilot"
GOOD = json.loads((FIX / "demobank.llm_response.json").read_text(encoding="utf-8"))
SCENARIOS = json.loads((FIX / "demobank.llm_scenarios.json").read_text(encoding="utf-8"))
ROLES = ["customer", "teller", "admin"]
SCHEMA = ("CREATE TABLE accounts (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, iban TEXT, balance REAL, card_number TEXT);"
          "CREATE TABLE tickets (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, text TEXT);")
T = _t("el")
TELLER, ADMIN, CUSTOMER = (T["opt_role"].format(role=r) for r in ("teller", "admin", "customer"))


def setup(roles=ROLES):
    tools = load_tools(FIX / "demobank.tools.list.json")
    info = SchemaInfo(sanitize_schema(SCHEMA))
    intake = {"company": "DemoBank", "agent": "bot", "language": "el", "requirements": "r", "roles": roles, "tools": tools,
              "context_attributes": {}, "db_schema": sanitize_schema(SCHEMA), "owner_columns": info.owner_columns()}
    return intake, analyze_tools(tools), info


def email_question(intake, analysis):
    return next(q for q in build_questions(intake, analysis, None) if q.get("tool") == "send_email")


class QuestionShapeTests(unittest.TestCase):
    def test_allow_questions_are_multi_select_with_one_option_per_role(self):
        intake, analysis, _ = setup()
        q = email_question(intake, analysis)
        self.assertTrue(q["multi"])
        self.assertEqual(q["options"][:3], [T["opt_none"], T["opt_priv"], T["opt_all"]])        # οι πρώτες 3 θέσεις μένουν ίδιες
        self.assertEqual(q["options"][3:], [CUSTOMER, TELLER, ADMIN])
        self.assertEqual(q["role_options"], {CUSTOMER: "customer", TELLER: "teller", ADMIN: "admin"})
        self.assertEqual(q["default"], T["opt_none"])                                           # ασφαλές default

    def test_without_known_roles_the_question_still_works_with_the_three_classic_options(self):
        intake, analysis, _ = setup(roles=None)
        q = email_question(intake, analysis)
        self.assertEqual(len(q["options"]), 3)
        self.assertEqual(q["role_options"], {})

    def test_english_labels(self):
        intake, analysis, _ = setup()
        intake["language"] = "en"
        q = email_question(intake, analysis)
        self.assertIn("The role 'teller'", q["options"])

    def test_merged_overflow_question_also_lists_roles(self):
        tools = [{"name": f"run_shell_{i}", "description": "Run a shell command", "params": {"cmd": {"type": "string"}},
                  "source_format": "list", "http_method": None} for i in range(12)]
        intake, _, _ = setup()
        intake["tools"] = tools
        qs = build_questions(intake, analyze_tools(tools), None)
        merged = next(q for q in qs if q["key"] == "allow_tools_more")
        self.assertTrue(merged["multi"])
        self.assertIn(TELLER, merged["options"])
        self.assertLessEqual(len(qs), 8)


class ParseAccessTests(unittest.TestCase):
    def parse(self, raw, roles=ROLES, with_options=True):
        q = {"role_options": {CUSTOMER: "customer", TELLER: "teller", ADMIN: "admin"} if with_options else {}}
        return parse_access(raw, q, T, roles)

    def test_several_roles_chosen_by_name(self):
        self.assertEqual(self.parse([TELLER, ADMIN]), ("privileged", ["teller", "admin"]))
        self.assertEqual(self.parse(ADMIN), ("privileged", ["admin"]))                       # μία επιλογή (συμβολοσειρά)
        self.assertEqual(self.parse([ADMIN, TELLER, ADMIN]), ("privileged", ["admin", "teller"]))   # χωρίς διπλότυπα

    def test_all_roles_chosen_means_all(self):
        self.assertEqual(self.parse([CUSTOMER, TELLER, ADMIN]), ("all", ["customer", "teller", "admin"]))
        self.assertEqual(self.parse(T["opt_all"]), ("all", []))

    def test_none_wins_over_everything_and_unknown_is_strict(self):
        self.assertEqual(self.parse([T["opt_none"], TELLER]), ("none", []))                  # αντίφαση => το πιο αυστηρό
        self.assertEqual(self.parse(T["opt_none"]), ("none", []))
        self.assertEqual(self.parse("maybe later"), ("none", []))
        self.assertEqual(self.parse([]), ("none", []))
        self.assertEqual(self.parse("hacker"), ("none", []))                                 # ρόλος που δεν υπάρχει

    def test_free_text_role_names(self):
        self.assertEqual(self.parse("teller, admin", with_options=False), ("privileged", ["teller", "admin"]))
        self.assertEqual(self.parse("Teller; «admin»", with_options=False), ("privileged", ["teller", "admin"]))
        self.assertEqual(self.parse("teller, hacker", with_options=False), ("privileged", ["teller"]))   # ο άγνωστος αγνοείται
        self.assertEqual(self.parse("όχι", with_options=False), ("none", []))

    def test_legacy_single_options_still_work(self):
        self.assertEqual(self.parse(T["opt_priv"]), ("privileged", []))


class DecisionTests(unittest.TestCase):
    def decide(self, answer):
        intake, analysis, _ = setup()
        q = email_question(intake, analysis)
        qs = build_questions(intake, analysis, None)
        sid = next(x["id"] for x in qs if x.get("tool") == "send_email")
        return decisions_from_answers(qs, {sid: answer}, intake), analysis

    def test_roles_are_recorded_and_open_the_tool_with_explicit_confirmation(self):
        dec, analysis = self.decide([TELLER, ADMIN])
        self.assertEqual(dec["tool_access"]["send_email"], "privileged")
        self.assertEqual(dec["tool_roles"]["send_email"], ["teller", "admin"])
        self.assertIn("send_email", confirmed_open_tools(dec, analysis))
        shown = next(x for x in dec["qa"] if "send_email" in x["text"])
        self.assertEqual(shown["answer"], "Μόνο οι ρόλοι: teller, admin")                   # αυτό βλέπει το LLM και ο άνθρωπος
        json.dumps(dec)

    def test_unanswered_stays_closed(self):
        intake, analysis, _ = setup()
        dec = decisions_from_answers(build_questions(intake, analysis, None), {}, intake)
        self.assertEqual(dec["tool_access"]["send_email"], "none")
        self.assertEqual(dec["tool_roles"], {})

    def test_all_roles_and_none(self):
        dec, _ = self.decide([CUSTOMER, TELLER, ADMIN])
        self.assertEqual((dec["tool_access"]["send_email"], dec["tool_roles"]), ("all", {}))
        dec, _ = self.decide(T["opt_none"])
        self.assertEqual(dec["tool_access"]["send_email"], "none")


class FloorEnforcesTheChosenRolesTests(unittest.TestCase):
    def floor(self, policy, answer):
        intake, analysis, info = setup()
        qs = build_questions(intake, analysis, None)
        sid = next(x["id"] for x in qs if x.get("tool") == "send_email")
        dec = decisions_from_answers(qs, {sid: answer}, intake)
        dec["confirmed_open"] = sorted(confirmed_open_tools(dec, analysis))
        return apply_floor(policy, intake, analysis, dec, info)

    def test_an_over_generous_draft_is_tightened_to_the_chosen_roles(self):
        p = copy.deepcopy(GOOD["policy"])
        for r in p["rules"]:
            if r["id"] == "email.staff":
                r["roles"] = ["customer", "teller", "admin"]          # το LLM άνοιξε και στον πελάτη
        out, issues = self.floor(p, [TELLER, ADMIN])
        eng = PolicyEngine(out)
        self.assertEqual(eng.evaluate({"id": "c1", "role": "customer"}, "send_email", {}, {})["action"], "deny")
        for role in ("teller", "admin"):
            self.assertEqual(eng.evaluate({"id": "x", "role": role}, "send_email", {}, {})["action"], "allow")
        self.assertEqual(next(r for r in out["rules"] if r["id"] == "floor.roles.send_email")["roles"], ["customer"])
        self.assertIn("floor.roles", {i["code"] for i in issues})
        self.assertNotIn("floor.privileged", {i["code"] for i in issues})                   # ρητοί ρόλοι: όχι «αόριστο» warning

    def test_idempotent_and_no_rule_when_nothing_to_close(self):
        out, _ = self.floor(copy.deepcopy(GOOD["policy"]), [TELLER, ADMIN])
        intake, analysis, info = setup()
        again, issues2 = self.floor(out, [TELLER, ADMIN])
        self.assertEqual(sum(1 for r in again["rules"] if r["id"] == "floor.roles.send_email"), 1)
        out_all, _ = self.floor(copy.deepcopy(GOOD["policy"]), [CUSTOMER, TELLER, ADMIN])
        self.assertFalse(any(r["id"].startswith("floor.roles.") for r in out_all["rules"]))

    def test_the_floor_only_tightens_it_cannot_add_a_role_the_draft_forgot(self):
        p = copy.deepcopy(GOOD["policy"])
        for r in p["rules"]:
            if r["id"] == "email.staff":
                r["roles"] = ["admin"]                                 # όπως στα τρεξίματα 2 και 3 του πραγματικού Gemini
        out, _ = self.floor(p, [TELLER, ADMIN])
        self.assertEqual(PolicyEngine(out).evaluate({"id": "t1", "role": "teller"}, "send_email", {}, {})["action"], "deny")


class EndToEndN11Tests(unittest.TestCase):
    """Το σενάριο N11 («ο ταμίας στέλνει email σε πελάτη») με την ΕΠΙΛΟΓΗ «teller ΚΑΙ admin»."""

    def run_session(self, answer):
        with tempfile.TemporaryDirectory() as tmp:
            llm = FakeLLM([{"questions": []}, GOOD, SCENARIOS])
            s = CopilotSession.new("DemoBank", "bot", FIX / "demobank.tools.list.json", "r", roles=ROLES, db_schema=SCHEMA,
                                   llm=llm, out_dir=tmp)
            ans = {}
            for q in s.questions():
                if q.get("tool") == "send_email":
                    ans[q["id"]] = answer
                if q["key"] == "unconditional":
                    ans[q["id"]] = q["options"][1]
            s.answer(ans)
            res = s.generate()
            return s, res, llm

    def test_the_prompt_names_both_roles_so_a_faithful_model_can_write_both(self):
        s, res, llm = self.run_session([TELLER, ADMIN])
        policy_prompt = next(m["user"] for m in llm.sent if "Write the draft policy" in m["user"])
        self.assertIn("Μόνο οι ρόλοι: teller, admin", policy_prompt)
        self.assertNotIn("πιο προνομιούχο", policy_prompt.split("send_email")[1].split("Q:")[0])
        self.assertEqual([i for i in res["issues"] if i["level"] == "error"], [])

    def test_n11_passes_with_the_two_roles_selected(self):
        s, res, _ = self.run_session([TELLER, ADMIN])
        gold = ev.load_gold()
        r = ev.score(res["policy"], gold)
        self.assertNotIn("N11", {f["id"] for f in r["failures"]})
        self.assertTrue(s.approve("Alice", "yes")["approved"])

    def test_review_shows_the_roles_the_human_chose(self):
        s, res, _ = self.run_session([TELLER, ADMIN])
        self.assertIn("Μόνο οι ρόλοι: teller, admin", res["review_md"])


class CliMultiSelectTests(unittest.TestCase):
    def run_cli(self, *argv, stdin=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(builtins, "input", side_effect=list(stdin or [])):
            code = cli_main(list(argv))
        return code, out.getvalue()

    def test_interactive_answer_accepts_comma_separated_choices(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_cli("init", "--company", "DemoBank", "--agent", "bot", "--tools", str(FIX / "demobank.tools.list.json"),
                         "--requirements", "r", "--roles", "customer,teller,admin", "--out", tmp, "--llm", "offline")
            state = json.loads((Path(tmp) / "session.json").read_text(encoding="utf-8"))
            session = CopilotSession.from_dict(state, llm="offline")
            qs = session.questions()
            n = len(qs)
            idx = next(i for i, q in enumerate(qs) if q.get("tool") == "send_email")
            replies = [""] * n
            replies[idx] = "5,6"                                  # options[4], options[5] = teller, admin
            code, out = self.run_cli("answer", "--out", tmp, "--llm", "offline", stdin=replies)
            self.assertEqual(code, 0)
            self.assertIn("πολλαπλή επιλογή", out)
            saved = json.loads((Path(tmp) / "session.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["answers"][qs[idx]["id"]], [TELLER, ADMIN])

    def test_single_digit_still_gives_a_plain_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.run_cli("init", "--company", "DemoBank", "--agent", "bot", "--tools", str(FIX / "demobank.tools.list.json"),
                         "--requirements", "r", "--roles", "customer,teller,admin", "--out", tmp, "--llm", "offline")
            session = CopilotSession.from_dict(json.loads((Path(tmp) / "session.json").read_text(encoding="utf-8")), llm="offline")
            n = len(session.questions())
            self.run_cli("answer", "--out", tmp, "--llm", "offline", stdin=["2"] + [""] * (n - 1))
            saved = json.loads((Path(tmp) / "session.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["answers"]["q1"], session.questions()[0]["options"][1])


if __name__ == "__main__":
    unittest.main()
