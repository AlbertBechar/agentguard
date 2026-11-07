"""
copilot/llm.py -- το LLM του Copilot (μόνο standard library).

Κοινό interface:  complete_json(system, user, *, schema_hint=None) -> dict   και   complete_text(...) -> str
Υλοποιήσεις:      GeminiLLM (urllib), FakeLLM (τεστ), ReplayLLM (παίζει ξανά πραγματικές καταγραφές).

Το LLM χρησιμοποιείται ΜΟΝΟ στη σχεδίαση. Το κλειδί διαβάζεται από AI_STUDIO_API_KEY, στέλνεται ΜΟΝΟ στο header
(x-goog-api-key, ποτέ στο URL) και δεν εμφανίζεται ποτέ σε μηνύματα σφάλματος.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_MODEL = "gemini-3.5-flash-lite"   # ίδιο προεπιλεγμένο μοντέλο με το app/chatbot.py
_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.S)


class LLMError(RuntimeError):
    """Σφάλμα του LLM (δίκτυο, ποσόστωση, κακή απάντηση). Το μήνυμα δεν περιέχει ποτέ το κλειδί."""


class LLMFormatError(LLMError):
    """Η απάντηση του μοντέλου δεν είναι έγκυρο JSON αντικείμενο (αξίζει επανάληψη, σε αντίθεση με σφάλμα δικτύου)."""


# ---------------------------------------------------------------------------
# Ανοχή στην έξοδο του μοντέλου
# ---------------------------------------------------------------------------

def extract_json(text) -> dict:
    """Βγάζει το πρώτο JSON αντικείμενο από κείμενο μοντέλου (fences ```json, κείμενο γύρω-γύρω)."""
    if not isinstance(text, str) or not text.strip():
        raise LLMFormatError("Το μοντέλο δεν επέστρεψε κείμενο.")
    candidates = [text.strip()] + [m.strip() for m in _FENCE.findall(text)]
    for cand in candidates:
        try:
            obj = json.loads(cand)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    decoder = json.JSONDecoder()
    for m in re.finditer(r"\{", text):
        try:
            obj, _ = decoder.raw_decode(text[m.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    raise LLMFormatError("Η απάντηση του μοντέλου δεν περιέχει έγκυρο JSON αντικείμενο.")


def _digest(kind: str, system: str, user: str) -> str:
    return hashlib.sha256(f"{kind}\x00{system}\x00{user}".encode("utf-8")).hexdigest()


def _with_hint(system: str, schema_hint) -> str:
    if schema_hint:
        return f"{system}\n\nReturn ONLY a JSON object of this shape:\n{schema_hint}"
    return system


class LLM:
    """Βάση: οι υποκλάσεις υλοποιούν _complete(kind, system, user) -> str."""
    label = "llm"

    def _complete(self, kind: str, system: str, user: str) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    def complete_json(self, system: str, user: str, *, schema_hint: str | None = None) -> dict:
        return extract_json(self._complete("json", _with_hint(system, schema_hint), user))

    def complete_text(self, system: str, user: str, *, schema_hint: str | None = None) -> str:
        return self._complete("text", _with_hint(system, schema_hint), user)


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------

class GeminiLLM(LLM):
    def __init__(self, api_key: str | None = None, model: str | None = None, *, timeout: float = 60,
                 max_retries: int = 2, backoff: float = 1.0, record_path=None):
        self._key = api_key if api_key is not None else os.environ.get("AI_STUDIO_API_KEY", "")
        self.model = model or os.environ.get("COPILOT_MODEL") or os.environ.get("GEMINI_MODEL") or DEFAULT_MODEL
        self.timeout, self.max_retries, self.backoff = timeout, max_retries, backoff
        self.record_path = Path(record_path) if record_path else None
        self._sleep = time.sleep
        self.label = f"gemini:{self.model}"

    # --- ασφάλεια: το κλειδί δεν πρέπει να εμφανιστεί πουθενά
    def _scrub(self, text) -> str:
        text = str(text)
        return text.replace(self._key, "***") if self._key else text

    def _request(self, payload: dict) -> dict:
        if not self._key:
            raise LLMError("Λείπει το AI_STUDIO_API_KEY (μεταβλητή περιβάλλοντος): δεν υπάρχει πρόσβαση στο Gemini.")
        url = _ENDPOINT.format(model=self.model)
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json", "x-goog-api-key": self._key})
        last = "άγνωστο σφάλμα"
        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode("utf-8", "replace")[:300]
                except Exception:  # noqa: BLE001
                    body = ""
                last = self._scrub(f"HTTP {e.code} από το Gemini. {body}".strip())
                if e.code == 429 or e.code >= 500:
                    if attempt < self.max_retries:
                        self._sleep(self.backoff * (2 ** attempt))
                        continue
                raise LLMError(last) from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = self._scrub(f"Σφάλμα δικτύου προς το Gemini: {type(e).__name__}")
                if attempt < self.max_retries:
                    self._sleep(self.backoff * (2 ** attempt))
                    continue
                raise LLMError(last) from None
            except json.JSONDecodeError:
                raise LLMError("Το Gemini επέστρεψε μη έγκυρη απάντηση (όχι JSON).") from None
        raise LLMError(last)

    def _complete(self, kind: str, system: str, user: str) -> str:
        gen = {"temperature": 0}
        if kind == "json":
            gen["responseMimeType"] = "application/json"
        payload = {"systemInstruction": {"parts": [{"text": system}]},
                   "contents": [{"role": "user", "parts": [{"text": user}]}],
                   "generationConfig": gen}
        data = self._request(payload)
        try:
            parts = data["candidates"][0]["content"]["parts"]
            text = "".join(p.get("text", "") for p in parts)
        except (KeyError, IndexError, TypeError):
            reason = (data.get("promptFeedback") or {}).get("blockReason") if isinstance(data, dict) else None
            raise LLMError("Το Gemini δεν επέστρεψε απάντηση" + (f" (λόγος: {reason})." if reason else ".")) from None
        if not text.strip():
            raise LLMError("Το Gemini επέστρεψε κενή απάντηση.")
        self._record(kind, system, user, text)
        return text

    def _record(self, kind, system, user, response):
        if not self.record_path:
            return
        self.record_path.parent.mkdir(parents=True, exist_ok=True)
        line = {"digest": _digest(kind, system, user), "kind": kind, "model": self.model,
                "system": system, "user": user, "response": response}
        with open(self.record_path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")


def default_llm():
    """GeminiLLM αν υπάρχει AI_STUDIO_API_KEY, αλλιώς None (λειτουργία χωρίς LLM)."""
    return GeminiLLM() if os.environ.get("AI_STUDIO_API_KEY") else None


# ---------------------------------------------------------------------------
# Fake (τεστ) και Replay (demo χωρίς δίκτυο)
# ---------------------------------------------------------------------------

class FakeLLM(LLM):
    """Ψεύτικο LLM για τεστ. responses: λίστα (σειριακά) ή callable(system, user, kind) -> dict | str.

    .sent = ό,τι στάλθηκε ({"kind","system","user"}). Όταν τελειώσουν οι απαντήσεις: LLMError (fail-closed).
    """
    label = "fake"

    def __init__(self, responses=()):
        self._responses = responses if callable(responses) else list(responses)
        self._i = 0
        self.sent: list[dict] = []

    def _complete(self, kind: str, system: str, user: str) -> str:
        self.sent.append({"kind": kind, "system": system, "user": user})
        if callable(self._responses):
            item = self._responses(system, user, kind)
        else:
            if self._i >= len(self._responses):
                raise LLMError("FakeLLM: δεν υπάρχουν άλλες προγραμματισμένες απαντήσεις.")
            item = self._responses[self._i]
            self._i += 1
        if isinstance(item, Exception):
            raise item
        return item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)


class ReplayLLM(LLM):
    """Παίζει ξανά ΠΡΑΓΜΑΤΙΚΕΣ απαντήσεις που κατέγραψε το GeminiLLM (record_path). Πάντα ετικετάρεται «replay».

    Πρώτα ταιριάζει ακριβώς (system+user)· αν το prompt άλλαξε λίγο, δίνει την επόμενη αχρησιμοποίητη
    καταγραφή του ίδιου είδους και το μετρά στο .fallback_used.
    """
    label = "replay"

    def __init__(self, path):
        self.path = Path(path)
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            raise LLMError(f"Δεν διαβάζεται το αρχείο replay {self.path}: {e}") from None
        self._records = []
        for n, line in enumerate(lines, 1):
            if line.strip():
                try:
                    self._records.append(json.loads(line))
                except json.JSONDecodeError:
                    raise LLMError(f"Χαλασμένη γραμμή {n} στο αρχείο replay.") from None
        if not self._records:
            raise LLMError("Το αρχείο replay είναι κενό.")
        self._used = [False] * len(self._records)
        self.fallback_used = 0
        self.sent: list[dict] = []

    def _complete(self, kind: str, system: str, user: str) -> str:
        self.sent.append({"kind": kind, "system": system, "user": user})
        want = _digest(kind, system, user)
        for i, rec in enumerate(self._records):
            if not self._used[i] and rec.get("digest") == want:
                self._used[i] = True
                return rec["response"]
        for i, rec in enumerate(self._records):
            if not self._used[i] and rec.get("kind") == kind:
                self._used[i] = True
                self.fallback_used += 1
                return rec["response"]
        raise LLMError("Το replay δεν έχει άλλη καταγεγραμμένη απάντηση για αυτό το αίτημα.")
