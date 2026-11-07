"""Βήμα 9: οι μετρήσεις με ΠΡΑΓΜΑΤΙΚΟ Gemini αναπαράγονται από το αρχείο replay, και τα δημόσια fixtures φορτώνουν.

Το replay είναι καταγραφή πραγματικών απαντήσεων του Gemini (gemini-3.5-flash-lite). Αν αλλάξει το copilot/prompts.py ή η
είσοδος του evaluate, το ταίριασμα prompt αποτυγχάνει: ξανακαταγράψτε με `python -m copilot.evaluate --record ...`.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from copilot import evaluate as ev  # noqa: E402
from copilot.heuristics import analyze_tools  # noqa: E402
from copilot.llm import ReplayLLM  # noqa: E402
from copilot.tooldefs import load_tools  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "copilot"
REPLAY = FIX / "replay" / "demobank.replay.ndjson"
STORED = json.loads((FIX / "measurements" / "step9_demobank.json").read_text(encoding="utf-8"))
GOLD = ev.load_gold()


class RealGeminiMeasurementTests(unittest.TestCase):
    def test_stored_measurement_is_what_the_replay_of_the_real_run_produces(self):
        passed = []
        replay = ReplayLLM(REPLAY)
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("το replay δεν επιτρέπεται να βγει στο δίκτυο")):
            for stored in STORED["runs"]:
                r = ev.run_once(replay, GOLD)
                passed.append(r["after_floor"]["passed"])
                self.assertEqual(r["after_floor"]["passed"], stored["after_floor"]["passed"])
                self.assertEqual(r["after_floor"]["failures"], stored["after_floor"]["failures"])
                self.assertEqual(r["policy"], stored["policy"])                       # ΑΚΡΙΒΩΣ η ίδια πολιτική
        self.assertEqual(passed, [49, 48, 48])
        self.assertEqual(replay.label, "replay")
        self.assertEqual(replay.fallback_used, 0, "τα prompts άλλαξαν μετά την καταγραφή: ξανακαταγράψτε το replay")

    def test_stored_numbers(self):
        s = STORED["summary"]
        self.assertEqual((s["gold_total"], s["runs"]), (51, 3))
        self.assertEqual(s["after_floor_passed"], [49, 48, 48])
        self.assertEqual(s["llm_before_floor_passed"], [49, 48, 48])
        self.assertEqual(s["llm_first_draft_passed"], [49, 48, 48])
        self.assertEqual(s["offline_passed"], 35)
        self.assertEqual((s["valid_lookups"], s["provided_attributes"]), ([3, 3, 3], 3))
        self.assertEqual(s["stub_needed"], [[], [], []])
        self.assertEqual(s["approval_blocking_errors"], [0, 0, 0])
        self.assertTrue(all(r["model"] == "gemini:gemini-3.5-flash-lite" for r in STORED["runs"]))

    def test_offline_number_is_reproducible(self):
        self.assertEqual(ev.run_offline(GOLD)["after_floor"]["passed"], STORED["offline"]["after_floor"]["passed"])

    def test_the_recurring_failures_are_the_documented_ones(self):
        fails = [sorted(f["id"] for f in r["after_floor"]["failures"]) for r in STORED["runs"]]
        self.assertEqual(fails, [["B09", "B10"], ["B09", "B10", "N11"], ["B09", "B10", "N11"]])

    def test_replay_file_has_no_secrets(self):
        text = REPLAY.read_text(encoding="utf-8")
        for needle in ("AIza", "x-goog-api-key", "AI_STUDIO_API_KEY"):
            self.assertNotIn(needle, text)
        recs = [json.loads(l) for l in text.splitlines()]
        self.assertEqual(len(recs), 9)                                              # 3 τρεξίματα × (ερωτήσεις, πολιτική, σενάρια)
        self.assertEqual({r["model"] for r in recs}, {"gemini-3.5-flash-lite"})


class PublicToolsTests(unittest.TestCase):
    def test_public_fixtures_are_definitions_only_and_documented(self):
        gh = json.loads((FIX / "public" / "github_mcp_tools.json").read_text(encoding="utf-8"))
        self.assertEqual(len(gh), 133)
        self.assertEqual(len({t["name"] for t in gh}), 133)
        self.assertTrue(all(set(t) == {"name", "description", "inputSchema"} for t in gh))   # μόνο ορισμοί, όχι δεδομένα
        src = (FIX / "public" / "SOURCES.md").read_text(encoding="utf-8")
        for part in ("github-mcp-server", "petstore3.swagger.io", "Downloaded on", "kept the FIRST definition"):
            self.assertIn(part, src)
        self.assertEqual(len(load_tools(FIX / "public" / "petstore.openapi.json")), 19)

    def test_heuristic_classification_of_the_public_tools(self):
        gh = analyze_tools(load_tools(FIX / "public" / "github_mcp_tools.json"))
        self.assertEqual({k: sum(1 for a in gh.values() if a["risk"] == k) for k in ("read", "write", "external", "dangerous")},
                         {"read": 62, "write": 68, "external": 3, "dangerous": 0})
        self.assertEqual(sum(a["returns_untrusted"] for a in gh.values()), 34)
        pet = analyze_tools(load_tools(FIX / "public" / "petstore.openapi.json"))
        self.assertEqual({k: sum(1 for a in pet.values() if a["risk"] == k) for k in ("read", "write")}, {"read": 8, "write": 11})

    def test_offline_copilot_covers_every_public_tool_and_keeps_the_question_limit(self):
        for case in ev.PUBLIC_CASES:
            with self.subTest(case=case["name"]):
                r = ev.run_public("offline", case)
                self.assertEqual(r["source"], "offline")
                self.assertEqual(r["tools_in_policy"], r["tools"])                    # κάθε εργαλείο έχει κανόνα
                self.assertLessEqual(r["questions_asked"], 8)
                self.assertEqual(r["blocking_errors"], [])
                self.assertIn("Review πολιτικής ασφαλείας", r["review_sample"])
        github = ev.run_public("offline", ev.PUBLIC_CASES[1])
        self.assertEqual(github["tools"], 133)
        self.assertEqual(github["questions_asked"], 6)


class PublicRealGeminiTests(unittest.TestCase):
    """Αποθηκευμένο αποτέλεσμα του ΠΡΑΓΜΑΤΙΚΟΥ Gemini στα δημόσια εργαλεία (χωρίς gold set: μόνο τι παρήχθη)."""

    @classmethod
    def setUpClass(cls):
        cls.llm = {r["name"]: r for r in json.loads((FIX / "measurements" / "step9_public_llm.json").read_text(encoding="utf-8"))}
        cls.off = {r["name"]: r for r in json.loads((FIX / "measurements" / "step9_public_offline.json").read_text(encoding="utf-8"))}

    def test_github_mcp_was_fully_covered_without_blocking_errors(self):
        r = self.llm["github_mcp"]
        self.assertEqual((r["source"], r["tools"], r["tools_in_policy"], r["blocking_errors"]), ("llm", 133, 133, []))
        self.assertEqual(r["matrix_cells"], {"allow": 124, "deny": 74, "conditional": 68})
        self.assertEqual(r["floor_changes"], {"floor.untrusted_tools": 2, "floor.denied": 3, "floor.ctx_requested": 1})
        self.assertLessEqual(r["questions_asked"], 8)

    def test_petstore_blocks_approval_until_the_human_confirms_unconditional_write_access(self):
        r = self.llm["petstore"]
        self.assertEqual((r["source"], r["tools"], r["tools_in_policy"]), ("llm", 19, 19))
        self.assertEqual(r["floor_changes"].get("probe.open"), 10)
        self.assertTrue(r["blocking_errors"])

    def test_offline_and_llm_see_the_same_tools_the_same_way(self):
        for name in ("petstore", "github_mcp"):
            self.assertEqual(self.llm[name]["risk"], self.off[name]["risk"])
            self.assertEqual(self.off[name]["source"], "offline")

    def test_public_replay_file_has_no_secrets_and_is_labelled_replay_only(self):
        text = (FIX / "replay" / "public.replay.ndjson").read_text(encoding="utf-8")
        for needle in ("AIza", "x-goog-api-key", "AI_STUDIO_API_KEY"):
            self.assertNotIn(needle, text)
        self.assertEqual(ReplayLLM(FIX / "replay" / "public.replay.ndjson").label, "replay")


if __name__ == "__main__":
    unittest.main()
