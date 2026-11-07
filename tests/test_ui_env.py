"""Τεστ του φορτωτή .env του UI (ui/envfile.py): φορτώνει σωστά και το κλειδί δεν εμφανίζεται πουθενά."""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ui import demo_presets, envfile, service  # noqa: E402

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient
    from ui import server
    HAVE_FASTAPI = True
except ImportError:                                     # pragma: no cover
    HAVE_FASTAPI = False

FAKE_KEY = "AI" "za" "SyFAKEenvfile0123456789abcdefghijk"   # ψεύτικο· σπασμένο ώστε να μη βρίσκεται από grep


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / ".env"

    def write(self, text: str, **kw):
        self.path.write_text(text, encoding=kw.get("encoding", "utf-8"))

    def test_loads_the_key_and_returns_only_names(self):
        self.write(f'# σχόλιο\nAI_STUDIO_API_KEY="{FAKE_KEY}"\nCOPILOT_MODEL=gemini-test # σχόλιο\n')
        env: dict = {}
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            names = envfile.load_env(self.path, env)
        self.assertEqual(sorted(names), ["AI_STUDIO_API_KEY", "COPILOT_MODEL"])
        self.assertEqual(env["AI_STUDIO_API_KEY"], FAKE_KEY)                 # χωρίς τα εισαγωγικά
        self.assertEqual(env["COPILOT_MODEL"], "gemini-test")                # χωρίς το σχόλιο
        self.assertNotIn(FAKE_KEY, json.dumps(names))
        self.assertEqual(out.getvalue(), "", "ο φορτωτής δεν τυπώνει τίποτα")

    def test_never_overrides_an_existing_variable(self):
        self.write(f"AI_STUDIO_API_KEY={FAKE_KEY}\n")
        env = {"AI_STUDIO_API_KEY": "from-the-terminal"}
        self.assertEqual(envfile.load_env(self.path, env), [])
        self.assertEqual(env["AI_STUDIO_API_KEY"], "from-the-terminal")

    def test_loads_only_the_whitelisted_names(self):
        self.write(f"AI_STUDIO_API_KEY={FAKE_KEY}\nDATABASE_PASSWORD=secret\nPATH=/evil\nexport GEMINI_MODEL = m1\n")
        env: dict = {}
        self.assertEqual(sorted(envfile.load_env(self.path, env)), ["AI_STUDIO_API_KEY", "GEMINI_MODEL"])
        self.assertEqual(set(env), {"AI_STUDIO_API_KEY", "GEMINI_MODEL"})
        self.assertEqual(env["GEMINI_MODEL"], "m1")

    def test_robust_to_missing_empty_and_odd_files(self):
        self.assertEqual(envfile.load_env(Path(self.tmp.name) / "nope", {}), [])
        for text in ("", "\n\n", "no equals sign\n", "AI_STUDIO_API_KEY=\n", "=value\n", "# only comments\n"):
            self.write(text)
            self.assertEqual(envfile.load_env(self.path, {}), [], repr(text))
        self.path.write_bytes(b"\xff\xfe\x00bad bytes")
        self.assertEqual(envfile.load_env(self.path, {}), [])
        self.write(f"AI_STUDIO_API_KEY={FAKE_KEY}\n", encoding="utf-8-sig")        # BOM των Windows
        env: dict = {}
        self.assertEqual(envfile.load_env(self.path, env), ["AI_STUDIO_API_KEY"])

    def test_default_path_is_the_repo_root_env_and_nothing_else(self):
        self.assertEqual(envfile.DEFAULT_PATH, ROOT / ".env")
        self.assertEqual(envfile.ALLOWED, ("AI_STUDIO_API_KEY", "COPILOT_MODEL", "GEMINI_MODEL"))
        self.assertIsNone(__import__("inspect").signature(envfile.load_env).parameters["path"].default)   # δεν υπάρχει προεπιλογή από χρήστη


@unittest.skipUnless(HAVE_FASTAPI, "χρειάζεται fastapi/httpx")
class KeyNeverLeaksAfterEnvLoad(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._saved = (service.OUT_ROOT, service.STORE)
        service.OUT_ROOT = Path(self.tmp.name) / "ui"
        service.STORE = service.SessionStore()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("AI_STUDIO_API_KEY", None)
        self.env_file = Path(self.tmp.name) / ".env"
        self.env_file.write_text(f'AI_STUDIO_API_KEY="{FAKE_KEY}"\n', encoding="utf-8")
        self.addCleanup(lambda: (service.STORE.clear(), setattr(service, "OUT_ROOT", self._saved[0]), setattr(service, "STORE", self._saved[1])))

    def test_server_startup_loads_the_key_and_no_response_or_log_contains_it(self):
        p = demo_presets.demobank_preset()
        body = {k: p[k] for k in ("company", "agent", "requirements", "roles", "db_schema", "context_attributes")}
        body.update(tools=p["tools_text"], mode="replay")
        with mock.patch.object(envfile, "DEFAULT_PATH", self.env_file), warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with self.assertLogs("agentguard.ui", level="WARNING") as logs:
                with TestClient(server.app, base_url="http://127.0.0.1:8765", raise_server_exceptions=False) as c:   # εκκινεί το lifespan
                    self.assertEqual(os.environ.get("AI_STUDIO_API_KEY"), FAKE_KEY)
                    st = c.get("/api/status").json()
                    self.assertTrue(st["live_available"])
                    responses = [c.get("/api/status"), c.get("/api/presets"), c.post("/api/session", json=body)]
                    sid = responses[-1].json()["sid"]
                    c.post(f"/api/session/{sid}/answers", json={"answers": responses[-1].json()["recorded_answers"]})
                    responses += [c.post(f"/api/session/{sid}/generate"), c.post(f"/api/session/{sid}/approve", json={"by": "Άρης", "confirm": "yes"}),
                                  c.get(f"/api/session/{sid}/download/approval.json"), c.get(f"/api/session/{sid}/snippet/python"),
                                  c.post(f"/api/session/{sid}/try", json={"role": "customer", "tool": "get_account", "args": {"account_id": "A1"}}),
                                  c.post("/api/attack/run", json={"source": "session", "sid": sid}),
                                  c.post("/api/session", json={**body, "company": "άλλη"}),            # σφάλμα replay
                                  c.get("/api/nope"), c.get("/")]
                    with mock.patch.object(service, "status", side_effect=RuntimeError(f"boom {FAKE_KEY}")):
                        responses.append(c.get("/api/status"))                                         # 500 με το κλειδί μέσα στο μήνυμα
        for r in responses:
            self.assertNotIn(FAKE_KEY, r.text)
            self.assertNotIn(FAKE_KEY, json.dumps(dict(r.headers)))
        log_text = "\n".join(logs.output)
        self.assertIn("AI_STUDIO_API_KEY", log_text)               # το όνομα αναφέρεται…
        self.assertNotIn(FAKE_KEY, log_text)                       # …η τιμή ποτέ
        for path in service.OUT_ROOT.rglob("*"):
            if path.is_file():
                self.assertNotIn(FAKE_KEY, path.read_text(encoding="utf-8"))

    def test_importing_the_server_does_not_touch_the_environment(self):
        """Το import του ui.server (π.χ. από τα τεστ) δεν πρέπει να βάζει κλειδί στο περιβάλλον της σουίτας."""
        with mock.patch.object(envfile, "DEFAULT_PATH", self.env_file):
            import importlib
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                importlib.reload(server)
            self.assertNotIn("AI_STUDIO_API_KEY", os.environ)


if __name__ == "__main__":
    unittest.main()
