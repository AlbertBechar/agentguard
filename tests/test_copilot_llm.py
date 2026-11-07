"""Τεστ για copilot/llm.py (χωρίς δίκτυο: mock στο urllib.request.urlopen)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from copilot.llm import FakeLLM, GeminiLLM, LLMError, ReplayLLM, default_llm, extract_json  # noqa: E402

KEY = "AIzaSyFAKE-KEY-FOR-TESTS-0123456789"


class FakeResp:
    def __init__(self, text=None, raw=None):
        self._raw = raw if raw is not None else json.dumps(
            {"candidates": [{"content": {"parts": [{"text": text}]}}]}).encode("utf-8")

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, body="boom"):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(body.encode("utf-8")))


def make(**kw):
    llm = GeminiLLM(api_key=KEY, model="test-model", backoff=0, **kw)
    llm._sleep = lambda s: None
    return llm


class ExtractJsonTests(unittest.TestCase):
    def test_plain_fenced_and_surrounded(self):
        self.assertEqual(extract_json('{"a": 1}'), {"a": 1})
        self.assertEqual(extract_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(extract_json('```\n{"a": [1, 2]}\n```'), {"a": [1, 2]})
        self.assertEqual(extract_json('Βεβαίως! Ορίστε:\n{"a": {"b": 2}} Ελπίζω να βοηθά.'), {"a": {"b": 2}})
        self.assertEqual(extract_json('λάθος { όχι json } μετά {"ok": true}'), {"ok": True})

    def test_errors(self):
        for bad in ("", "   ", "no json here", "[1, 2, 3]", "{broken", None, 5):
            with self.subTest(bad=bad):
                with self.assertRaises(LLMError):
                    extract_json(bad)


class GeminiTests(unittest.TestCase):
    def test_success_sends_key_only_in_header(self):
        llm = make()
        with mock.patch("urllib.request.urlopen", return_value=FakeResp('{"x": 1}')) as uo:
            out = llm.complete_json("sys", "usr", schema_hint='{"x": int}')
        self.assertEqual(out, {"x": 1})
        req = uo.call_args[0][0]
        self.assertNotIn(KEY, req.full_url)
        self.assertEqual(req.get_header("X-goog-api-key"), KEY)
        body = json.loads(req.data.decode("utf-8"))
        self.assertEqual(body["generationConfig"]["responseMimeType"], "application/json")
        self.assertIn('{"x": int}', body["systemInstruction"]["parts"][0]["text"])
        self.assertEqual(uo.call_args[1]["timeout"], 60)
        self.assertIn("test-model", req.full_url)

    def test_text_mode_has_no_json_mime_type(self):
        llm = make()
        with mock.patch("urllib.request.urlopen", return_value=FakeResp("γεια")) as uo:
            self.assertEqual(llm.complete_text("s", "u"), "γεια")
        self.assertNotIn("responseMimeType", json.loads(uo.call_args[0][0].data)["generationConfig"])

    def test_retry_on_429_then_success(self):
        llm = make()
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(429), http_error(503), FakeResp('{"ok": 1}')]) as uo:
            self.assertEqual(llm.complete_json("s", "u"), {"ok": 1})
        self.assertEqual(uo.call_count, 3)  # 1 + 2 επαναλήψεις

    def test_gives_up_after_two_retries(self):
        llm = make()
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(429)] * 5) as uo:
            with self.assertRaises(LLMError) as cm:
                llm.complete_json("s", "u")
        self.assertEqual(uo.call_count, 3)
        self.assertIn("429", str(cm.exception))

    def test_500_is_retried_but_400_is_not(self):
        llm = make()
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(500), http_error(500), http_error(500)]) as uo:
            with self.assertRaises(LLMError):
                llm.complete_json("s", "u")
        self.assertEqual(uo.call_count, 3)
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(400)]) as uo:
            with self.assertRaises(LLMError):
                llm.complete_json("s", "u")
        self.assertEqual(uo.call_count, 1)

    def test_network_error_and_timeout_are_clean_errors(self):
        llm = make()
        for exc in (urllib.error.URLError("no route"), TimeoutError("slow")):
            with self.subTest(exc=type(exc).__name__):
                with mock.patch("urllib.request.urlopen", side_effect=exc):
                    with self.assertRaises(LLMError) as cm:
                        llm.complete_json("s", "u")
                self.assertIn("δικτύου", str(cm.exception))

    def test_broken_model_output_and_fences(self):
        llm = make()
        with mock.patch("urllib.request.urlopen", return_value=FakeResp("not json at all")):
            with self.assertRaises(LLMError):
                llm.complete_json("s", "u")
        with mock.patch("urllib.request.urlopen", return_value=FakeResp('```json\n{"a": 2}\n```')):
            self.assertEqual(llm.complete_json("s", "u"), {"a": 2})
        with mock.patch("urllib.request.urlopen", return_value=FakeResp(raw=b"<html>not json</html>")):
            with self.assertRaises(LLMError):
                llm.complete_json("s", "u")

    def test_blocked_and_empty_responses(self):
        llm = make()
        blocked = FakeResp(raw=json.dumps({"promptFeedback": {"blockReason": "SAFETY"}}).encode())
        with mock.patch("urllib.request.urlopen", return_value=blocked):
            with self.assertRaises(LLMError) as cm:
                llm.complete_json("s", "u")
        self.assertIn("SAFETY", str(cm.exception))
        with mock.patch("urllib.request.urlopen", return_value=FakeResp("   ")):
            with self.assertRaises(LLMError):
                llm.complete_json("s", "u")

    def test_missing_key_is_a_clean_error_without_network(self):
        llm = GeminiLLM(api_key="")
        with mock.patch("urllib.request.urlopen") as uo:
            with self.assertRaises(LLMError) as cm:
                llm.complete_json("s", "u")
        uo.assert_not_called()
        self.assertIn("AI_STUDIO_API_KEY", str(cm.exception))

    def test_key_never_appears_in_errors_logs_or_output(self):
        llm = make()
        echo = http_error(403, f"API key {KEY} is invalid")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), self.assertNoLogs():
            for exc in (echo, http_error(500, f"key={KEY}"), urllib.error.URLError(f"failed for {KEY}")):
                with mock.patch("urllib.request.urlopen", side_effect=exc):
                    with self.assertRaises(LLMError) as cm:
                        llm.complete_json("s", "u")
                self.assertNotIn(KEY, str(cm.exception))
                self.assertNotIn(KEY, repr(cm.exception))
                self.assertIsNone(cm.exception.__cause__)  # η αρχική εξαίρεση (με το σώμα) δεν κρατιέται
        self.assertNotIn(KEY, out.getvalue() + err.getvalue())

    def test_model_selection_from_environment(self):
        with mock.patch.dict(os.environ, {"COPILOT_MODEL": "m-copilot", "GEMINI_MODEL": "m-chat"}, clear=False):
            self.assertEqual(GeminiLLM(api_key="k").model, "m-copilot")
        env = {k: v for k, v in os.environ.items() if k not in ("COPILOT_MODEL", "GEMINI_MODEL")}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(GeminiLLM(api_key="k").model, "gemini-3.5-flash-lite")
        with mock.patch.dict(os.environ, {"GEMINI_MODEL": "m-chat"}, clear=False):
            os.environ.pop("COPILOT_MODEL", None)
            self.assertEqual(GeminiLLM(api_key="k").model, "m-chat")

    def test_default_llm_depends_on_key(self):
        with mock.patch.dict(os.environ, {"AI_STUDIO_API_KEY": "abc"}):
            self.assertIsInstance(default_llm(), GeminiLLM)
        env = {k: v for k, v in os.environ.items() if k != "AI_STUDIO_API_KEY"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsNone(default_llm())

    def test_record_and_replay_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Path(tmp) / "sub" / "rec.jsonl"
            llm = make(record_path=rec)
            with mock.patch("urllib.request.urlopen", side_effect=[FakeResp('{"n": 1}'), FakeResp('{"n": 2}')]):
                llm.complete_json("S1", "U1")
                llm.complete_json("S2", "U2")
            self.assertNotIn(KEY, rec.read_text(encoding="utf-8"))  # το κλειδί δεν καταγράφεται
            rp = ReplayLLM(rec)
            self.assertEqual(rp.label, "replay")
            self.assertEqual(rp.complete_json("S2", "U2"), {"n": 2})   # ταίριασμα ακριβώς, όχι σειράς
            self.assertEqual(rp.complete_json("S1", "U1"), {"n": 1})
            self.assertEqual(rp.fallback_used, 0)
            with self.assertRaises(LLMError):
                rp.complete_json("S1", "U1")                           # δεν υπάρχει άλλη

    def test_replay_fallback_and_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            rec = Path(tmp) / "rec.jsonl"
            rec.write_text(json.dumps({"digest": "x", "kind": "json", "response": '{"z": 9}'}) + "\n", encoding="utf-8")
            rp = ReplayLLM(rec)
            self.assertEqual(rp.complete_json("changed", "prompt"), {"z": 9})
            self.assertEqual(rp.fallback_used, 1)
            with self.assertRaises(LLMError):
                ReplayLLM(Path(tmp) / "missing.jsonl")
            empty = Path(tmp) / "empty.jsonl"
            empty.write_text("", encoding="utf-8")
            with self.assertRaises(LLMError):
                ReplayLLM(empty)
            bad = Path(tmp) / "bad.jsonl"
            bad.write_text("{nope\n", encoding="utf-8")
            with self.assertRaises(LLMError):
                ReplayLLM(bad)


class FakeLLMTests(unittest.TestCase):
    def test_sequence_records_and_exhausts(self):
        f = FakeLLM([{"a": 1}, '```json\n{"b": 2}\n```', "plain text"])
        self.assertEqual(f.complete_json("s1", "u1"), {"a": 1})
        self.assertEqual(f.complete_json("s2", "u2"), {"b": 2})
        self.assertEqual(f.complete_text("s3", "u3"), "plain text")
        self.assertEqual([m["user"] for m in f.sent], ["u1", "u2", "u3"])
        self.assertEqual([m["kind"] for m in f.sent], ["json", "json", "text"])
        with self.assertRaises(LLMError):
            f.complete_json("s", "u")

    def test_callable_and_exception_items(self):
        f = FakeLLM(lambda system, user, kind: {"echo": user})
        self.assertEqual(f.complete_json("s", "hello"), {"echo": "hello"})
        g = FakeLLM([LLMError("x")])
        with self.assertRaises(LLMError):
            g.complete_json("s", "u")

    def test_schema_hint_reaches_the_system_prompt(self):
        f = FakeLLM([{}])
        f.complete_json("SYS", "U", schema_hint="{shape}")
        self.assertIn("{shape}", f.sent[0]["system"])


if __name__ == "__main__":
    unittest.main()
