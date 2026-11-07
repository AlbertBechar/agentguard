"""Τεστ της λογικής του web UI (ui/service.py), με πραγματικά δεδομένα DemoBank / DemoClinic και πραγματικό replay.

Δεν χρειάζεται FastAPI. Τρέχει με:  python -m unittest discover -s tests
"""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard import Guard  # noqa: E402
from examples.demobank import run_demo  # noqa: E402
from examples.demobank.app import DemoBankApp  # noqa: E402
from ui import demo_presets, service  # noqa: E402
from ui.service import UIError  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "copilot"
FAKE_KEY = "AI" "za" "SyFAKE0123456789abcdefghijklmnopqr"   # ψεύτικο· σπασμένο ώστε να μη βρίσκεται από grep


def bank_body(mode="replay", **over) -> dict:
    p = demo_presets.demobank_preset()
    body = {k: p[k] for k in ("company", "agent", "requirements", "roles", "db_schema", "context_attributes")}
    body.update(tools=p["tools_text"], mode=mode)
    body.update(over)
    return body


def clinic_body(mode="offline", **over) -> dict:
    p = demo_presets.democlinic_preset()
    body = {k: p[k] for k in ("company", "agent", "requirements", "roles", "db_schema", "context_attributes")}
    body.update(tools=p["tools_text"], mode=mode)
    body.update(over)
    return body


class UITestCase(unittest.TestCase):
    """Κάθε τεστ έχει δικό του φάκελο εξόδου και άδειο store συνεδριών· ΔΕΝ υπάρχει κλειδί Gemini στο περιβάλλον."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._saved = (service.OUT_ROOT, service.STORE)
        service.OUT_ROOT = Path(self._tmp.name) / "ui"
        service.STORE = service.SessionStore()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        os.environ.pop("AI_STUDIO_API_KEY", None)
        self.addCleanup(patcher.stop)

    def tearDown(self):
        service.STORE.clear()
        service.OUT_ROOT, service.STORE = self._saved
        self._tmp.cleanup()

    # --- βοηθητικά ---
    def replay_session(self, answer="recorded"):
        j = service.create_session(bank_body("replay"))
        if answer == "recorded":
            service.submit_answers(j["sid"], j["recorded_answers"])
        return j

    def approved_replay(self):
        j = self.replay_session()
        g = service.generate(j["sid"])
        a = service.approve(j["sid"], "Δοκιμαστικός Εγκρίνων", "yes")
        return j["sid"], g, a


# ---------------------------------------------------------------------------
class StatusAndTools(UITestCase):
    def test_status_only_booleans_and_never_the_key(self):
        os.environ["AI_STUDIO_API_KEY"] = FAKE_KEY
        st = service.status()
        self.assertEqual(set(st), {"live_available", "replay_available", "demobank_available"})
        self.assertTrue(all(isinstance(v, bool) for v in st.values()))
        self.assertTrue(st["live_available"])
        self.assertNotIn(FAKE_KEY, json.dumps(st))
        del os.environ["AI_STUDIO_API_KEY"]
        self.assertFalse(service.status()["live_available"])

    def test_presets_load_and_parse_with_the_copilot_loader(self):
        presets = service.list_presets()
        self.assertEqual([p["id"] for p in presets], ["demobank", "democlinic"])
        counts = {p["id"]: service.parse_tools(p["tools_text"])["count"] for p in presets}
        self.assertEqual(counts, {"demobank": 10, "democlinic": 6})
        bank, clinic = presets
        self.assertIn("replay", bank["modes"])
        self.assertNotIn("replay", clinic["modes"])
        self.assertTrue(bank["attack_available"] and not clinic["attack_available"])
        for p in presets:
            self.assertIn("όχι πραγματική εταιρία", p["badge"])

    def test_all_five_tool_formats_are_accepted(self):
        for name in ("demobank.tools.list.json", "demobank.tools.gemini.json", "demobank.tools.openai.json",
                     "demobank.tools.mcp.json", "demobank.tools.openapi.json"):
            text = (FIX / name).read_text(encoding="utf-8")
            res = service.parse_tools(text)
            self.assertGreaterEqual(res["count"], 10, name)

    def test_bad_tools_give_understandable_greek_errors(self):
        cases = {
            "{ not json": "tools_not_json",
            "": "tools_empty",
            "   ": "tools_empty",
            "[]": "tools_invalid",
            '[{"description": "no name"}]': "tools_invalid",
            '{"hello": 1}': "tools_invalid",
            '[{"name": "a"}, {"name": "a"}]': "tools_invalid",
        }
        for text, code in cases.items():
            with self.assertRaises(UIError, msg=text) as cm:
                service.parse_tools(text)
            self.assertEqual(cm.exception.code, code, text)
            self.assertRegex(cm.exception.message, r"[Α-Ωα-ω]", "το μήνυμα πρέπει να είναι στα ελληνικά")
            self.assertNotIn("Traceback", cm.exception.message)
        with self.assertRaises(UIError) as cm:
            service.parse_tools("[{broken")
        self.assertIn("γραμμή", cm.exception.message)

    def test_tools_text_is_never_treated_as_a_file_path(self):
        """Το load_tools του Copilot διαβάζει ως αρχείο κάθε string που δεν αρχίζει με [ ή {· το UI δεν πρέπει να το επιτρέπει."""
        secret_file = Path(self._tmp.name) / "secret.json"
        secret_file.write_text('[{"name": "leaked_tool"}]', encoding="utf-8")
        for text in (str(secret_file), json.dumps(str(secret_file))):          # σκέτη διαδρομή και διαδρομή σε εισαγωγικά
            with self.assertRaises(UIError) as cm:
                service.parse_tools(text)
            self.assertIn(cm.exception.code, ("tools_not_json", "tools_invalid"))
            self.assertNotIn("leaked_tool", cm.exception.message)
        with self.assertRaises(UIError):
            service.create_session(bank_body("offline", tools=str(secret_file)))


# ---------------------------------------------------------------------------
class SessionFlow(UITestCase):
    def test_replay_flow_create_answer_generate_approve(self):
        j = self.replay_session(answer=None)
        self.assertEqual(j["mode"], "replay")
        self.assertEqual(j["preset"], "demobank")
        self.assertEqual([d["stage"] for d in j["dry_run"]], ["questions", "policy", "scenarios"])
        self.assertTrue(all(q["id"] and q["text"] and q["default"] for q in j["questions"]))
        self.assertTrue(set(j["recorded_answers"]) <= {q["id"] for q in j["questions"]})
        ans = service.submit_answers(j["sid"], j["recorded_answers"])
        self.assertEqual(sorted(ans["accepted"]), sorted(j["recorded_answers"]))
        g = service.generate(j["sid"])
        self.assertEqual(g["summary"]["errors"], 0)
        self.assertTrue(g["summary"]["can_approve"])
        self.assertEqual((g["summary"]["scenarios_passed"], g["summary"]["scenarios_total"]), (24, 24))
        self.assertEqual(g["replay"]["fallback_used"], 0, "τα δεδομένα/απαντήσεις δεν ταιριάζουν με την καταγραφή")
        self.assertEqual(g["stage_el"], "πρόχειρο")
        self.assertEqual(g["matrix"]["run_sql"], {"customer": "deny", "teller": "deny", "admin": "deny"})
        self.assertEqual(g["matrix"]["get_account"]["customer"], "conditional")
        self.assertEqual([l["name"] for l in g["lookups"]], ["account_owner_id", "from_account_owner_id", "ticket_customer_id"])
        self.assertIn("SELECT", g["lookups"][0]["sql"])
        a = service.approve(j["sid"], "Άρης", "yes")
        self.assertTrue(a["approved"])
        self.assertEqual([f["name"] for f in a["files"]], ["policy.json", "approval.json"])
        self.assertEqual(a["scenarios"], {"passed": 24, "total": 24})
        policy = json.loads(service.download(j["sid"], "policy.json")[0])
        self.assertEqual(policy["meta"]["approved_by"], "Άρης")
        self.assertEqual(policy["meta"]["generated_by"], "copilot:replay")

    def test_replay_with_safe_defaults_is_honest_about_fallback_and_approval_is_refused(self):
        """Με τις ασφαλείς προεπιλογές το prompt δεν ταιριάζει με την καταγραφή: το UI το δείχνει και η έγκριση αρνείται."""
        j = self.replay_session(answer=None)
        g = service.generate(j["sid"])
        self.assertGreater(g["replay"]["fallback_used"], 0)
        self.assertGreaterEqual(g["summary"]["errors"], 1)
        self.assertFalse(g["summary"]["can_approve"])
        with self.assertRaises(UIError) as cm:
            service.approve(j["sid"], "Άρης", "yes")
        self.assertEqual(cm.exception.status, 409)
        self.assertTrue(any("close_account" in r for r in cm.exception.reasons))
        self.assertTrue(all(isinstance(i["fix"], str) for i in cm.exception.items))
        self.assertEqual(cm.exception.payload()["reasons"], cm.exception.reasons)

    def test_regenerate_in_replay_is_reproducible_even_after_going_back(self):
        """Το ReplayLLM καταναλώνει τις καταγραφές· ο χρήστης που γυρίζει πίσω και ξαναδημιουργεί δεν πρέπει να παίρνει άλλο αποτέλεσμα."""
        j = self.replay_session(answer=None)
        first_defaults = service.generate(j["sid"])                              # ασφαλείς προεπιλογές => fallback
        self.assertGreater(first_defaults["replay"]["fallback_used"], 0)
        service.submit_answers(j["sid"], j["recorded_answers"])                  # γυρνά πίσω και διαλέγει τις απαντήσεις της καταγραφής
        a = service.generate(j["sid"])
        b = service.generate(j["sid"])                                           # και ξαναδημιουργεί χωρίς αλλαγή
        for g in (a, b):
            self.assertEqual((g["replay"]["fallback_used"], g["summary"]["errors"], g["summary"]["scenarios_passed"]), (0, 0, 24))
        self.assertEqual(a["policy"], b["policy"])
        again_defaults = service.generate(service.create_session(bank_body("replay"))["sid"])
        self.assertEqual(again_defaults["policy"], first_defaults["policy"])     # ίδια είσοδος => ίδια πολιτική σε νέα συνεδρία

    def test_replay_accepts_only_demobank_data(self):
        for over, field in (({"company": "Άλλη εταιρία"}, "εταιρία"), ({"requirements": "Κάτι άλλο"}, "απαιτήσεις"),
                            ({"roles": ["a", "b"]}, "ρόλοι")):
            with self.assertRaises(UIError, msg=field) as cm:
                service.create_session(bank_body("replay", **over))
            self.assertEqual(cm.exception.code, "replay_data_mismatch")
            self.assertIn(field, cm.exception.message)
        with self.assertRaises(UIError) as cm:
            service.create_session(clinic_body("replay"))
        self.assertEqual(cm.exception.code, "replay_data_mismatch")
        self.assertEqual(len(service.STORE), 0, "αποτυχημένο αίτημα δεν αφήνει συνεδρία")

    def test_live_without_key_is_a_clean_error_with_alternatives(self):
        with self.assertRaises(UIError) as cm:
            service.create_session(bank_body("live"))
        self.assertEqual((cm.exception.code, cm.exception.status), ("no_api_key", 409))
        self.assertIn("Replay", cm.exception.message)
        self.assertIn("Χωρίς AI", cm.exception.message)
        self.assertNotIn("AIza", cm.exception.message)

    def test_offline_clinic_flow_end_to_end(self):
        j = service.create_session(clinic_body("offline"))
        self.assertEqual((j["preset"], j["llm_label"]), ("democlinic", "offline"))
        self.assertNotIn("recorded_answers", j)
        g = service.generate(j["sid"])
        self.assertEqual(set(g["matrix"]), {t["name"] for t in json.loads(demo_presets.democlinic_preset()["tools_text"])})
        self.assertEqual(g["roles"], ["patient", "secretary", "doctor"])
        self.assertEqual(g["source"], "offline")
        self.assertEqual(g["summary"]["errors"], 0)
        a = service.approve(j["sid"], "Δρ. Δοκιμή", "yes")
        self.assertTrue(a["approved"])
        t = service.try_decision(j["sid"], {"role": "patient", "tool": "export_patients_csv", "args": {"url": "https://example.test/x"}})
        self.assertEqual((t["decision"], t["stage_el"]), ("deny", "εγκεκριμένο"))

    def test_approval_requires_explicit_confirmation_name_and_a_draft(self):
        j = self.replay_session()
        with self.assertRaises(UIError) as cm:                                  # δεν έχει γίνει generate
            service.approve(j["sid"], "Άρης", "yes")
        self.assertTrue(any("generate" in r for r in cm.exception.reasons))
        service.generate(j["sid"])
        for by, confirm in (("Άρης", "no"), ("   ", "yes"), (None, "yes"), ("Άρης", None), ("Άρης", True)):
            with self.assertRaises(UIError, msg=repr((by, confirm))) as cm:
                service.approve(j["sid"], by, confirm)
            self.assertEqual(cm.exception.status, 409)
        self.assertFalse((service.OUT_ROOT / j["sid"] / "policy.json").exists(), "δεν γράφεται policy.json χωρίς έγκριση")

    def test_changing_answers_withdraws_the_approval(self):
        sid, _, _ = self.approved_replay()
        self.assertTrue((service.OUT_ROOT / sid / "policy.json").exists())
        service.submit_answers(sid, {"q1": "Όχι, σε κανέναν"})
        self.assertFalse((service.OUT_ROOT / sid / "policy.json").exists())
        with self.assertRaises(UIError) as cm:
            service.download(sid, "policy.json")
        self.assertIn(cm.exception.code, ("not_approved",))
        with self.assertRaises(UIError) as cm:
            service.try_decision(sid, {"role": "customer", "tool": "get_account", "args": {"account_id": "A1"}})
        self.assertEqual(cm.exception.code, "no_draft")

    def test_input_validation(self):
        bad = [({"mode": "magic"}, "input_invalid"), ({"company": ""}, "input_invalid"), ({"company": "x" * 500}, "input_too_big"),
               ({"requirements": None}, "input_invalid"), ({"roles": "customer"}, "input_invalid"),
               ({"roles": [1, 2]}, "input_invalid"), ({"context_attributes": {"bad name": "x"}}, "input_invalid"),
               ({"db_schema": "INSERT INTO users VALUES (1)"}, "schema_invalid"),
               ({"db_schema": "SELECT * FROM users"}, "schema_invalid"), ({"tools": 5}, "tools_empty")]
        for over, code in bad:
            body = bank_body("offline")
            body.update(over)
            with self.assertRaises(UIError, msg=str(over)) as cm:
                service.create_session(body)
            self.assertEqual(cm.exception.code, code, over)
        with self.assertRaises(UIError):
            service.create_session("not a dict")  # type: ignore[arg-type]
        for answers in ("x", {"q1": 5}, {"q1": [1]}, {5: "x"}):
            j = service.create_session(bank_body("offline"))
            with self.assertRaises(UIError, msg=str(answers)):
                service.submit_answers(j["sid"], answers)
        j = service.create_session(bank_body("offline"))
        res = service.submit_answers(j["sid"], {"q1": "Όχι, σε κανέναν", "zzz": "x"})
        self.assertEqual((res["accepted"], res["unknown"]), (["q1"], ["zzz"]))

    def test_unknown_session_is_a_clean_404(self):
        for fn in (lambda: service.generate("nope"), lambda: service.snippet("nope", "python"),
                   lambda: service.download("nope", "policy.json"), lambda: service.try_decision("nope", {}),
                   lambda: service.submit_answers("nope", {}), lambda: service.approve("nope", "x", "yes"),
                   lambda: service.generate(None)):  # type: ignore[arg-type]
            with self.assertRaises(UIError) as cm:
                fn()
            self.assertEqual((cm.exception.status, cm.exception.code), (404, "session_not_found"))

    def test_snippets_are_labelled_honestly(self):
        sid, _, _ = self.approved_replay()
        py, node, http = (service.snippet(sid, l) for l in ("python", "node", "http"))
        self.assertIn("Guard.from_policy", py["code"])
        self.assertEqual(py["stage"], "approved")
        for s in (node, http):
            self.assertIn("δεν έχει εκτελεστεί", s["note"])
            self.assertIs(s["tested"], False)
        self.assertEqual((ROOT / "agentguard" / "__main__.py").is_file(), "δεν υπάρχει ακόμα" not in node["note"])
        with self.assertRaises(UIError):
            service.snippet(sid, "ruby")
        j = self.replay_session()
        with self.assertRaises(UIError) as cm:                                  # πριν το generate
            service.snippet(j["sid"], "python")
        self.assertEqual(cm.exception.code, "no_draft")


# ---------------------------------------------------------------------------
class TryAndDownload(UITestCase):
    def test_try_allow_deny_and_stage_labels(self):
        j = self.replay_session()
        g = service.generate(j["sid"])
        self.assertIn("Ως «customer» κάλεσε «run_sql» (δεν έχει δικαίωμα)", [p["label"] for p in g["try_hints"]["probes"]])
        draft = service.try_decision(j["sid"], {"role": "customer", "tool": "get_account", "args": {"account_id": "A1"}})
        self.assertEqual((draft["decision"], draft["stage_el"]), ("allow", "πρόχειρο"))     # lookup πάνω στη δοκιμαστική βάση
        self.assertEqual(draft["facts"]["demo_db"], ["account_owner_id"])
        service.approve(j["sid"], "Άρης", "yes")
        cases = [
            ({"role": "customer", "tool": "get_account", "args": {"account_id": "A1"}}, "allow"),
            ({"role": "customer", "tool": "get_account", "args": {"account_id": "A2"}}, "deny"),        # λογαριασμός άλλου πελάτη
            ({"role": "teller", "tool": "get_account", "args": {"account_id": "A2"}}, "allow"),
            ({"role": "customer", "tool": "run_sql", "args": {"query": "select 1"}}, "deny"),
            ({"role": "customer", "tool": "transfer_funds", "args": {"from_account": "A1", "to_account": "A3", "amount": 5000}}, "deny"),
        ]
        for body, expected in cases:
            t = service.try_decision(j["sid"], body)
            self.assertEqual(t["decision"], expected, body)
            self.assertEqual(t["stage_el"], "εγκεκριμένο")
        t = service.try_decision(j["sid"], {"role": "customer", "tool": "get_account", "args": {"account_id": "A1"}})
        self.assertEqual(t["user"]["id"], "c1")
        self.assertEqual(t["reason_el"], None)                                   # ο κανόνας έχει δικό του λόγο
        t = service.try_decision(j["sid"], {"role": "customer", "tool": "get_account", "args": {"account_id": "A2"}})
        self.assertIn("προεπιλογή", t["reason_el"])

    def test_try_manual_context_overrides_the_demo_database(self):
        j = self.replay_session()
        service.generate(j["sid"])
        body = {"role": "customer", "tool": "get_account", "args": {"account_id": "A2"}, "ctx": {"account_owner_id": "c1"}}
        t = service.try_decision(j["sid"], body)
        self.assertEqual(t["decision"], "allow")
        self.assertEqual(t["facts"]["manual"], ["account_owner_id"])

    def test_needs_approval_matches_the_real_guard(self):
        """Το needs_approval του «Δοκίμασε» πρέπει να συμφωνεί με τον πραγματικό Guard (taint + εργαλείο υψηλού κινδύνου)."""
        sid, _, _ = self.approved_replay()
        policy = json.loads(service.download(sid, "policy.json")[0])
        teller = {"id": "t1", "role": "teller"}
        mail = {"to": "c1@mail.example", "subject": "x", "body": "y"}
        for tainted, expected_ui, expected_guard in ((False, "allow", "ok"), (True, "needs_approval", "needs_approval")):
            app = DemoBankApp()
            try:
                guard = Guard.from_policy(policy, db=app.readonly_connection(), audit_path=None)
                if tainted:
                    first = guard.call("s", teller, "read_support_ticket", {"ticket_id": "T1"}, app.call_tool)
                    self.assertEqual(first["status"], "ok")
                real = guard.call("s", teller, "send_email", mail, app.call_tool)
            finally:
                app.close()
            ui = service.try_decision(sid, {"role": "teller", "tool": "send_email", "args": mail, "after_untrusted": tainted})
            self.assertEqual(real["status"], expected_guard)
            self.assertEqual(ui["decision"], expected_ui)
            if tainted:
                self.assertEqual(ui["rule"], real["rule"])
            else:
                self.assertTrue(ui["high_risk"] and ui["note"])

    def test_try_input_validation_and_history(self):
        j = self.replay_session()
        service.generate(j["sid"])
        for body in ({}, {"tool": "get_account"}, {"role": "customer"}, {"role": "customer", "tool": "get_account", "args": []},
                     {"role": "customer", "tool": "get_account", "ctx": "x"}, {"user": {"id": "c1"}, "tool": "get_account"},
                     {"role": "customer", "tool": "x" * 300}):
            with self.assertRaises(UIError, msg=str(body)) as cm:
                service.try_decision(j["sid"], body)
            self.assertEqual(cm.exception.code in ("input_invalid", "input_too_big"), True)
        with self.assertRaises(UIError):
            service.try_decision(j["sid"], {"role": "customer", "tool": "get_account", "args": {"x": "y" * 30_000}})
        unknown_role = service.try_decision(j["sid"], {"role": "hacker", "tool": "get_account", "args": {"account_id": "A1"}})
        self.assertEqual((unknown_role["decision"], unknown_role["rule"]), ("deny", "security.unknown_role"))
        unknown_tool = service.try_decision(j["sid"], {"role": "customer", "tool": "rm_rf", "args": {}})
        self.assertEqual((unknown_tool["decision"], unknown_tool["rule"]), ("deny", "security.unknown_tool"))
        for _ in range(12):
            res = service.try_decision(j["sid"], {"role": "customer", "tool": "get_account", "args": {"account_id": "A1"}})
        self.assertEqual(len(res["history"]), 10)
        self.assertEqual(res["history"][0]["decision"], "allow")

    def test_download_only_from_the_whitelist(self):
        j = self.replay_session()
        service.generate(j["sid"])
        with self.assertRaises(UIError) as cm:                                  # πριν την έγκριση
            service.download(j["sid"], "policy.json")
        self.assertEqual(cm.exception.code, "not_approved")
        service.approve(j["sid"], "Άρης", "yes")
        for name in ("policy.json", "approval.json"):
            data, fname, media = service.download(j["sid"], name)
            self.assertEqual((fname, media), (name, "application/json"))
            json.loads(data)
        evil = ["../x", "..\\x", "/etc/passwd", "policy.draft.json", "review.md", "policy.json/", "policy.json\x00.txt",
                "%2e%2e%2fx", "POLICY.JSON", "", "..", None, 5]
        for name in evil:
            with self.assertRaises(UIError, msg=repr(name)) as cm:
                service.download(j["sid"], name)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "download_not_allowed")


# ---------------------------------------------------------------------------
class Attacks(UITestCase):
    @staticmethod
    def cli_numbers() -> dict:
        out = subprocess.run([sys.executable, str(ROOT / "examples" / "demobank" / "run_demo.py")], capture_output=True, text=True,
                             encoding="utf-8", cwd=str(ROOT), timeout=180, env={**os.environ, "PYTHONIOENCODING": "utf-8"}).stdout
        a = re.search(r"ATTACKS that succeeded:\s+without Guard (\d+)/(\d+)\s+with Guard (\d+)/(\d+)", out)
        n = re.search(r"NORMAL uses that worked:\s+without Guard (\d+)/(\d+)\s+with Guard (\d+)/(\d+)", out)
        assert a and n, out[-500:]
        return {"attacks": int(a[2]), "attacks_without_guard": int(a[1]), "attacks_with_guard": int(a[3]),
                "normal": int(n[2]), "normal_without_guard": int(n[1]), "normal_with_guard": int(n[3])}

    def test_reference_attack_numbers_equal_the_terminal_demo(self):
        res = service.attack_run({"source": "reference"})
        self.assertEqual(res["summary"], self.cli_numbers())
        self.assertEqual(res["summary"], run_demo.summarize(run_demo.run()))
        self.assertEqual(res["problems"], [])
        self.assertEqual(len(res["attacks"]), res["summary"]["attacks"])
        for item in res["attacks"] + res["normal"]:
            self.assertTrue(item["how_kind"] and item["how_text"])
        self.assertTrue(any(i["how_kind"] in ("neutralised", "harmless") for i in res["attacks"]))     # οι ειλικρινείς εξαιρέσεις φαίνονται

    def test_session_attack_needs_approval_and_demobank(self):
        j = self.replay_session()
        service.generate(j["sid"])
        with self.assertRaises(UIError) as cm:
            service.attack_run({"source": "session", "sid": j["sid"]})
        self.assertEqual(cm.exception.code, "not_approved")
        service.approve(j["sid"], "Άρης", "yes")
        res = service.attack_run({"source": "session", "sid": j["sid"]})
        self.assertEqual(res["summary"], self.cli_numbers())            # η πολιτική του Copilot (replay) δίνει τα ίδια νούμερα
        self.assertEqual(res["source_label"], "Η πολιτική που εγκρίθηκε από το Copilot")
        c = service.create_session(clinic_body("offline"))
        service.generate(c["sid"])
        service.approve(c["sid"], "Δρ. Δοκιμή", "yes")
        with self.assertRaises(UIError) as cm:
            service.attack_run({"source": "session", "sid": c["sid"]})
        self.assertEqual(cm.exception.code, "attack_not_available")
        for body in ({}, {"source": "other"}, {"source": "session"}, "x"):
            with self.assertRaises(UIError):
                service.attack_run(body)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
class StoreAndSecrets(UITestCase):
    def test_store_limits_ttl_and_lru(self):
        clock = [0.0]
        store = service.SessionStore(ttl=100, max_sessions=3, clock=lambda: clock[0])
        service.STORE = store
        sids = []
        for _ in range(3):
            sids.append(service.create_session(bank_body("offline"))["sid"])
            clock[0] += 1
        store.get(sids[0])                                   # η πρώτη χρησιμοποιήθηκε πρόσφατα
        clock[0] += 1
        extra = service.create_session(bank_body("offline"))["sid"]
        self.assertEqual(len(store), 3)
        with self.assertRaises(UIError):                     # διώχθηκε η παλαιότερη σε χρήση (η δεύτερη)
            store.get(sids[1])
        store.get(sids[0])
        store.get(extra)
        self.assertFalse((service.OUT_ROOT / sids[1]).exists() and (service.OUT_ROOT / sids[1]).is_dir() and any((service.OUT_ROOT / sids[1]).iterdir()))
        clock[0] += 101                                      # λήξη μετά από 2 ώρες αδράνειας (εδώ 100 δευτ.)
        with self.assertRaises(UIError) as cm:
            store.get(extra)
        self.assertEqual(cm.exception.code, "session_not_found")
        self.assertEqual(len(store), 0)

    def test_default_limits_match_the_spec(self):
        self.assertEqual((service.SESSION_TTL, service.MAX_SESSIONS), (2 * 3600, 20))

    def test_session_ids_are_unguessable_and_unique(self):
        sids = {service.create_session(bank_body("offline"))["sid"] for _ in range(5)}
        self.assertEqual(len(sids), 5)
        self.assertTrue(all(len(s) >= 20 and re.fullmatch(r"[A-Za-z0-9_\-]+", s) for s in sids))

    def test_the_api_key_never_appears_in_any_result_or_error(self):
        os.environ["AI_STUDIO_API_KEY"] = FAKE_KEY
        seen = []
        seen.append(service.status())
        seen.append(service.list_presets())
        j = service.create_session(bank_body("replay"))
        seen += [j, service.submit_answers(j["sid"], j["recorded_answers"]), service.generate(j["sid"]),
                 service.approve(j["sid"], "Άρης", "yes"), service.snippet(j["sid"], "python"),
                 service.try_decision(j["sid"], {"role": "customer", "tool": "get_account", "args": {"account_id": "A1"}}),
                 service.attack_run({"source": "session", "sid": j["sid"]})]
        for name in ("policy.json", "approval.json"):
            seen.append(service.download(j["sid"], name)[0].decode("utf-8"))
        errors = []
        for fn in (lambda: service.create_session(bank_body("replay", company="x")), lambda: service.parse_tools("{oops"),
                   lambda: service.approve(j["sid"], "", "no"), lambda: service.generate("nope")):
            try:
                fn()
            except UIError as e:
                errors.append(e.payload())
        blob = json.dumps(seen + errors, ensure_ascii=False, default=str)
        self.assertNotIn(FAKE_KEY, blob)
        self.assertNotIn("AI" "zaSy", blob)
        # και τα αρχεία στον δίσκο
        for p in service.OUT_ROOT.rglob("*"):
            if p.is_file():
                self.assertNotIn(FAKE_KEY, p.read_text(encoding="utf-8"), str(p))

    def test_scrub_removes_the_key_and_key_shaped_strings(self):
        os.environ["AI_STUDIO_API_KEY"] = FAKE_KEY
        self.assertEqual(service.scrub(f"σφάλμα με {FAKE_KEY} μέσα"), "σφάλμα με *** μέσα")
        self.assertEqual(service.scrub("AI" "zaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345 τέλος"), "*** τέλος")
        self.assertNotIn(FAKE_KEY, service.UIError("x", f"boom {FAKE_KEY}").message)
        self.assertNotIn(FAKE_KEY, json.dumps(service.UIError("x", "m", reasons=[f"r {FAKE_KEY}"]).payload()))

    def test_results_endpoint_reports_missing_and_reads_a_real_file(self):
        missing = Path(self._tmp.name) / "none.json"
        with mock.patch.object(service, "RESULTS_FILE", missing):
            with self.assertRaises(UIError) as cm:
                service.results()
            self.assertEqual((cm.exception.status, cm.exception.code), (404, "results_missing"))
        present = Path(self._tmp.name) / "results.json"
        present.write_text(json.dumps({"measured_at": "2026-01-01"}), encoding="utf-8")
        with mock.patch.object(service, "RESULTS_FILE", present):
            self.assertEqual(service.results(), {"measured_at": "2026-01-01"})
        present.write_text("{not json", encoding="utf-8")
        with mock.patch.object(service, "RESULTS_FILE", present):
            with self.assertRaises(UIError) as cm:
                service.results()
            self.assertEqual(cm.exception.code, "results_invalid")


if __name__ == "__main__":
    unittest.main()
