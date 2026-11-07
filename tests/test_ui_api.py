"""Τεστ του HTTP API του web UI (ui/server.py) με FastAPI TestClient και πραγματικά δεδομένα.

Χρειάζεται fastapi + httpx (pip install -r ui/requirements.txt)· αλλιώς τα τεστ παραλείπονται.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient
    HAVE_FASTAPI = True
except ImportError:                                     # pragma: no cover
    HAVE_FASTAPI = False

if HAVE_FASTAPI:
    from ui import demo_presets, server, service

FAKE_KEY = "AI" "za" "SyFAKE0123456789abcdefghijklmnopqr"
BASE = "http://127.0.0.1:8765"


def bank_body(mode="replay", **over) -> dict:
    p = demo_presets.demobank_preset()
    body = {k: p[k] for k in ("company", "agent", "requirements", "roles", "db_schema", "context_attributes")}
    body.update(tools=p["tools_text"], mode=mode)
    body.update(over)
    return body


@unittest.skipUnless(HAVE_FASTAPI, "χρειάζεται fastapi/httpx (pip install -r ui/requirements.txt)")
class ApiTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._saved = (service.OUT_ROOT, service.STORE)
        service.OUT_ROOT = Path(self._tmp.name) / "ui"
        service.STORE = service.SessionStore()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        os.environ.pop("AI_STUDIO_API_KEY", None)
        self.addCleanup(patcher.stop)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.c = TestClient(server.app, base_url=BASE, raise_server_exceptions=False)

    def tearDown(self):
        service.STORE.clear()
        service.OUT_ROOT, service.STORE = self._saved
        self._tmp.cleanup()

    def start(self, mode="replay", answers=True, **over):
        r = self.c.post("/api/session", json=bank_body(mode, **over))
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        if answers and "recorded_answers" in j:
            self.assertEqual(self.c.post(f"/api/session/{j['sid']}/answers", json={"answers": j["recorded_answers"]}).status_code, 200)
        return j

    def assertErrorShape(self, r, status, code=None):
        self.assertEqual(r.status_code, status, r.text)
        self.assertTrue(r.headers["content-type"].startswith("application/json"))
        body = r.json()
        self.assertEqual(list(body["error"])[:2], ["code", "message"])
        self.assertTrue(body["error"]["message"])
        self.assertNotIn("Traceback", r.text)
        if code:
            self.assertEqual(body["error"]["code"], code)
        return body


class FlowTests(ApiTestCase):
    def test_status_and_presets(self):
        st = self.c.get("/api/status").json()
        self.assertEqual(st, {"live_available": False, "replay_available": True, "demobank_available": True})
        presets = self.c.get("/api/presets").json()["presets"]
        self.assertEqual([p["id"] for p in presets], ["demobank", "democlinic"])
        self.assertEqual(self.c.post("/api/tools/parse", json={"text": presets[0]["tools_text"]}).json()["count"], 10)
        self.assertEqual(self.c.post("/api/tools/parse", json={"text": presets[1]["tools_text"]}).json()["count"], 6)

    def test_full_replay_flow_over_http_with_409_reasons(self):
        j = self.start(answers=False)
        sid = j["sid"]
        g = self.c.post(f"/api/session/{sid}/generate")                       # ασφαλείς προεπιλογές => το replay δεν ταιριάζει
        self.assertEqual(g.status_code, 200)
        self.assertGreater(g.json()["replay"]["fallback_used"], 0)
        r = self.c.post(f"/api/session/{sid}/approve", json={"by": "Άρης", "confirm": "yes"})
        body = self.assertErrorShape(r, 409, "approval_refused")
        self.assertTrue(body["reasons"] and body["reasons"] == body["error"]["reasons"])
        self.assertTrue(all(i["fix"] in ("questions", "check", "approve") for i in body["error"]["items"]))
        # τώρα με τις απαντήσεις της καταγραφής
        self.c.post(f"/api/session/{sid}/answers", json={"answers": j["recorded_answers"]})
        g = self.c.post(f"/api/session/{sid}/generate").json()
        self.assertEqual((g["summary"]["errors"], g["replay"]["fallback_used"]), (0, 0))
        a = self.c.post(f"/api/session/{sid}/approve", json={"by": "Άρης", "confirm": "yes"})
        self.assertEqual(a.status_code, 200, a.text)
        self.assertTrue(a.json()["approved"])
        for lang in ("python", "node", "http"):
            s = self.c.get(f"/api/session/{sid}/snippet/{lang}")
            self.assertEqual(s.status_code, 200)
            self.assertTrue(s.json()["code"])
        d = self.c.get(f"/api/session/{sid}/download/policy.json")
        self.assertEqual((d.status_code, d.headers["content-disposition"]), (200, 'attachment; filename="policy.json"'))
        self.assertEqual(json.loads(d.content)["meta"]["approved_by"], "Άρης")
        t = self.c.post(f"/api/session/{sid}/try", json={"role": "teller", "tool": "send_email", "after_untrusted": True,
                                                         "args": {"to": "c1@mail.example", "subject": "x", "body": "y"}})
        self.assertEqual((t.status_code, t.json()["decision"]), (200, "needs_approval"))

    def test_live_without_key_and_replay_with_other_data_are_clean_errors(self):
        self.assertErrorShape(self.c.post("/api/session", json=bank_body("live")), 409, "no_api_key")
        self.assertErrorShape(self.c.post("/api/session", json=bank_body("replay", company="Άλλη")), 422, "replay_data_mismatch")
        self.assertErrorShape(self.c.post("/api/tools/parse", json={"text": "{oops"}), 422, "tools_not_json")
        self.assertErrorShape(self.c.post("/api/tools/parse", json={"text": '[{"x": 1}]'}), 422, "tools_invalid")

    def test_attack_reference_and_session_over_http(self):
        ref = self.c.post("/api/attack/run", json={"source": "reference"})
        self.assertEqual(ref.status_code, 200)
        s = ref.json()["summary"]
        self.assertEqual((s["attacks_without_guard"], s["attacks_with_guard"], s["normal_with_guard"]), (20, 0, 15))
        j = self.start()
        self.c.post(f"/api/session/{j['sid']}/generate")
        self.assertErrorShape(self.c.post("/api/attack/run", json={"source": "session", "sid": j["sid"]}), 409, "not_approved")
        self.c.post(f"/api/session/{j['sid']}/approve", json={"by": "Άρης", "confirm": "yes"})
        self.assertEqual(self.c.post("/api/attack/run", json={"source": "session", "sid": j["sid"]}).json()["summary"], s)

    def test_results_endpoint(self):
        with mock.patch.object(service, "RESULTS_FILE", Path(self._tmp.name) / "missing.json"):
            self.assertErrorShape(self.c.get("/api/results"), 404, "results_missing")


class ErrorAndSecurityTests(ApiTestCase):
    def test_every_error_is_greek_json_never_a_stack_trace(self):
        j = self.start()
        sid = j["sid"]
        cases = [
            (self.c.get("/api/nope"), 404, "not_found"),
            (self.c.get("/nope.html"), 404, "not_found"),
            (self.c.put("/api/status", json={}), 405, "method_not_allowed"),
            (self.c.post("/api/session", content="{broken", headers={"content-type": "application/json"}), 422, "request_invalid"),
            (self.c.post("/api/session", json=[1, 2]), 422, "request_invalid"),
            (self.c.post("/api/session", json={"mode": "x"}), 422, "input_invalid"),
            (self.c.post("/api/session/zzz/generate"), 404, "session_not_found"),
            (self.c.get(f"/api/session/{sid}/snippet/ruby"), 404, "input_invalid"),
            (self.c.post(f"/api/session/{sid}/try", json={"role": "customer", "tool": "get_account"}), 409, "no_draft"),
            (self.c.post("/api/attack/run", json={"source": "x"}), 422, "input_invalid"),
        ]
        for r, status, code in cases:
            self.assertErrorShape(r, status, code)
            self.assertRegex(r.json()["error"]["message"], r"[Α-Ωα-ω]")

    def test_unexpected_exception_returns_500_json_and_logs_without_secrets(self):
        os.environ["AI_STUDIO_API_KEY"] = FAKE_KEY
        with mock.patch.object(service, "status", side_effect=RuntimeError(f"boom {FAKE_KEY}")):
            with self.assertLogs("agentguard.ui", level="ERROR") as logs:
                r = self.c.get("/api/status")
        self.assertErrorShape(r, 500, "internal_error")
        self.assertNotIn(FAKE_KEY, r.text)
        log_text = "\n".join(logs.output)
        self.assertIn("RuntimeError", log_text)                      # το traceback γράφεται στο log…
        self.assertNotIn(FAKE_KEY, log_text)                         # …χωρίς το κλειδί

    def test_download_with_dangerous_names_is_rejected(self):
        j = self.start()
        sid = j["sid"]
        self.c.post(f"/api/session/{sid}/generate")
        self.c.post(f"/api/session/{sid}/approve", json={"by": "Άρης", "confirm": "yes"})
        for name in ("..%2Fx", "../x", "%2e%2e/x", "..%5Cx", "policy.draft.json", "review.md", "POLICY.JSON", "policy.json%00", "%2fetc%2fpasswd"):
            r = self.c.get(f"/api/session/{sid}/download/{name}")
            self.assertEqual(r.status_code, 404, name)
            self.assertTrue(r.headers["content-type"].startswith("application/json"), name)
            self.assertNotIn("root:", r.text)
        self.assertEqual(self.c.get(f"/api/session/{sid}/download/policy.json").status_code, 200)

    def test_only_local_hosts_and_same_origin_posts_are_accepted(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for host in ("evil.example", "evil.example:8765", "127.0.0.1.evil.example", "192.168.1.5"):
                self.assertErrorShape(TestClient(server.app, base_url=f"http://{host}").get("/api/status"), 403, "host_not_allowed")
            for host in ("127.0.0.1:9", "localhost:8765", "[::1]:8765"):
                self.assertEqual(TestClient(server.app, base_url=f"http://{host}").get("/api/status").status_code, 200, host)
        self.assertErrorShape(self.c.post("/api/tools/parse", json={"text": "[]"}, headers={"origin": "http://evil.example"}), 403, "origin_not_allowed")
        self.assertEqual(self.c.post("/api/tools/parse", json={"text": "[]"}, headers={"origin": BASE}).status_code, 422)   # επιτρέπεται, απλώς άκυρα εργαλεία
        self.assertErrorShape(self.c.post("/api/tools/parse", content='{"text": "[]"}', headers={"content-type": "text/plain"}), 415, "content_type")
        self.assertErrorShape(self.c.post("/api/tools/parse", content="text=x", headers={"content-type": "application/x-www-form-urlencoded"}),
                              415, "content_type")

    def test_security_headers_on_api_and_static(self):
        for path in ("/api/status", "/"):
            r = self.c.get(path)
            self.assertEqual(r.status_code, 200, path)
            csp = r.headers["content-security-policy"]
            self.assertIn("default-src 'self'", csp)
            self.assertNotIn("unsafe-inline", csp)
            self.assertNotIn("unsafe-eval", csp)
            self.assertEqual(r.headers["x-content-type-options"], "nosniff")
            self.assertEqual(r.headers["x-frame-options"], "DENY")
        self.assertEqual(self.c.get("/api/status").headers["cache-control"], "no-store")

    def test_server_binds_only_to_loopback(self):
        quiet = io.StringIO()
        with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
            with mock.patch("uvicorn.run") as run, mock.patch.object(server, "_port_free", return_value=True):
                self.assertEqual(server.main(["--port", "8123"]), 0)
            self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")
            self.assertEqual(run.call_args.kwargs["port"], 8123)
            self.assertFalse(run.call_args.kwargs["access_log"])
            with mock.patch.object(server, "_port_free", return_value=False):
                self.assertEqual(server.main(["--port", "8123"]), 2)              # θύρα σε χρήση: καθαρό μήνυμα, όχι traceback
            with self.assertRaises(SystemExit):                                      # δεν υπάρχει επιλογή --host
                server.main(["--host", "0.0.0.0"])
        self.assertIn("ήδη σε χρήση", quiet.getvalue())
        self.assertNotIn("Traceback", quiet.getvalue())

    def test_the_api_key_never_appears_in_any_http_response(self):
        os.environ["AI_STUDIO_API_KEY"] = FAKE_KEY
        responses = [self.c.get("/api/status"), self.c.get("/api/presets"), self.c.post("/api/session", json=bank_body("replay", company="x"))]
        j = self.start()
        sid = j["sid"]
        responses += [self.c.post(f"/api/session/{sid}/generate"), self.c.post(f"/api/session/{sid}/approve", json={"by": "Άρης", "confirm": "yes"}),
                      self.c.get(f"/api/session/{sid}/snippet/python"), self.c.get(f"/api/session/{sid}/download/approval.json"),
                      self.c.post(f"/api/session/{sid}/try", json={"role": "customer", "tool": "get_account", "args": {"account_id": "A1"}}),
                      self.c.post("/api/attack/run", json={"source": "session", "sid": sid}), self.c.get("/api/nope"), self.c.get("/")]
        for r in responses:
            self.assertNotIn(FAKE_KEY, r.text)
            self.assertNotIn(FAKE_KEY, json.dumps(dict(r.headers)))
        self.assertTrue(self.c.get("/api/status").json()["live_available"])
        # η μοναδική αναφορά στο όνομα της μεταβλητής στο frontend είναι οδηγία προς τον χρήστη, όχι πεδίο εισαγωγής
        for p in (ROOT / "ui" / "static").rglob("*.html"):
            self.assertNotRegex(p.read_text(encoding="utf-8"), r'(?i)<input[^>]*(api[_-]?key|AI_STUDIO)')


class StaticTests(ApiTestCase):
    def test_index_is_served_and_has_no_external_resources(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/html", r.headers["content-type"])
        static = ROOT / "ui" / "static"
        loaders = re.compile(r"""(?:src|href)\s*=\s*["']\s*(?:https?:)?//|url\(\s*["']?\s*(?:https?:)?//|@import\s+["']?(?:https?:)?//""", re.I)
        for p in static.rglob("*"):
            if p.suffix in (".html", ".css", ".js", ".svg"):
                self.assertIsNone(loaders.search(p.read_text(encoding="utf-8")), f"εξωτερικός πόρος σε {p.relative_to(ROOT)}")


if __name__ == "__main__":
    unittest.main()
