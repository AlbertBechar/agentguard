"""LLM chatbot with function calling (plain REST, no SDK).

Two backends, picked with LLM_PROVIDER:
  gemini  (default) Google's native generateContent API
  openai  any OpenAI-compatible /chat/completions endpoint: OpenAI, Anthropic, Google's OpenAI
          endpoint, OpenRouter, Groq, Together, Ollama, vLLM, LiteLLM and most LLM gateways
"""
import json
import os
import time
from datetime import date
from pathlib import Path

import requests

from .db import execute, query
from .tools import DECLARATIONS, call_tool

PROVIDER = os.environ.get("LLM_PROVIDER", "gemini").strip().lower()
if PROVIDER == "gemini":
    API_KEY = os.environ.get("LLM_API_KEY") or os.environ.get("AI_STUDIO_API_KEY", "")
    MODEL = os.environ.get("LLM_MODEL") or os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")
    API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
elif PROVIDER == "openai":
    API_KEY = os.environ.get("LLM_API_KEY", "")
    MODEL = os.environ.get("LLM_MODEL", "")
    API_URL = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
else:
    raise RuntimeError(f"Unknown LLM_PROVIDER={PROVIDER!r} (use 'gemini' or 'openai')")
MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "0"))  # 0 = don't send (openai provider only)

SYSTEM_PROMPT_PATH = Path(os.environ.get("SYSTEM_PROMPT_PATH", Path(__file__).resolve().parent.parent / "system.md"))
MAX_STEPS = int(os.environ.get("CHAT_MAX_TOOL_STEPS", "10"))
MAX_HISTORY = 60  # stored messages kept per user
REQUEST_TIMEOUT = int(os.environ.get("LLM_TIMEOUT") or os.environ.get("GEMINI_TIMEOUT", "120"))  # seconds per call
MAX_RETRIES = int(os.environ.get("LLM_RETRIES") or os.environ.get("GEMINI_RETRIES", "1"))


def system_prompt(user):
    # Re-read on every request so edits to system.md apply without a restart.
    text = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    values = {
        "user_id": user["id"], "username": user["username"], "full_name": user["full_name"],
        "role": user["role"], "email": user["email"], "today": date.today().isoformat(),
    }
    for k, v in values.items():
        text = text.replace("{{" + k + "}}", str(v))
    return text


# --------------------------------------------------------------------------- backends
# Each backend stores the conversation in its provider's native message format, so that
# provider-specific data (e.g. Gemini thought signatures) is echoed back verbatim.

def _lower_types(schema):
    """Gemini schema types (OBJECT, STRING...) -> JSON schema types (object, string...)."""
    if isinstance(schema, dict):
        return {k: (v.lower() if k == "type" and isinstance(v, str) else _lower_types(v)) for k, v in schema.items()}
    if isinstance(schema, list):
        return [_lower_types(v) for v in schema]
    return schema


class Gemini:
    label = "Gemini"

    @staticmethod
    def owns(msg):
        return "parts" in msg

    @staticmethod
    def user_message(text):
        return {"role": "user", "parts": [{"text": text}]}

    @staticmethod
    def is_user_text(msg):
        return msg["role"] == "user" and bool(msg["parts"]) and "text" in msg["parts"][0]

    @staticmethod
    def visible(msg):
        text = "".join(p.get("text", "") for p in msg["parts"] if not p.get("thought"))
        return ("user" if msg["role"] == "user" else "assistant"), text

    @staticmethod
    def request(contents, sys_text):
        body = {
            "system_instruction": {"parts": [{"text": sys_text}]},
            "contents": contents,
            "tools": [{"function_declarations": DECLARATIONS}],
        }
        return body, {"x-goog-api-key": API_KEY}

    @staticmethod
    def usage(data):
        u = data.get("usageMetadata", {})
        return u.get("promptTokenCount"), u.get("candidatesTokenCount")

    @staticmethod
    def parse(data):
        """-> (message to store, reply text, [(call_id, name, args)]) or None if there is no answer."""
        candidates = data.get("candidates") or []
        if not candidates or "content" not in candidates[0]:
            return None, (candidates[0].get("finishReason") if candidates else None) or data.get("promptFeedback")
        content = candidates[0]["content"]
        content.setdefault("role", "model")
        content.setdefault("parts", [])  # keep verbatim: Gemini 3 needs thought signatures echoed back
        calls = [(p["functionCall"].get("id"), p["functionCall"]["name"], p["functionCall"].get("args") or {})
                 for p in content["parts"] if "functionCall" in p]
        text = "".join(p.get("text", "") for p in content["parts"] if not p.get("thought"))
        return (content, text, calls), None

    @staticmethod
    def tool_results(results):
        parts = []
        for call_id, name, result in results:
            fr = {"name": name, "response": {"result": result}}
            if call_id:
                fr["id"] = call_id
            parts.append({"functionResponse": fr})
        return [{"role": "user", "parts": parts}]

    @staticmethod
    def assistant_text(text):
        return {"role": "model", "parts": [{"text": text}]}


class OpenAICompatible:
    label = "LLM"
    TOOLS = [{"type": "function", "function": _lower_types(d)} for d in DECLARATIONS]

    @staticmethod
    def owns(msg):
        return "parts" not in msg

    @staticmethod
    def user_message(text):
        return {"role": "user", "content": text}

    @staticmethod
    def is_user_text(msg):
        return msg["role"] == "user"

    @staticmethod
    def visible(msg):
        if msg["role"] not in ("user", "assistant"):
            return msg["role"], ""
        content = msg.get("content") or ""
        if isinstance(content, list):  # some servers return content parts
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
        return msg["role"], content

    @staticmethod
    def request(contents, sys_text):
        body = {
            "model": MODEL,
            "messages": [{"role": "system", "content": sys_text}] + contents,
            "tools": OpenAICompatible.TOOLS,
        }
        if MAX_TOKENS:
            body["max_tokens"] = MAX_TOKENS
        return body, ({"Authorization": f"Bearer {API_KEY}"} if API_KEY else {})

    @staticmethod
    def usage(data):
        u = data.get("usage") or {}
        return u.get("prompt_tokens"), u.get("completion_tokens")

    @staticmethod
    def parse(data):
        choices = data.get("choices") or []
        if not choices or not choices[0].get("message"):
            return None, (choices[0].get("finish_reason") if choices else None) or data.get("error")
        msg = choices[0]["message"]
        msg = {k: v for k, v in msg.items() if v is not None}  # keep the rest verbatim (e.g. thought signatures)
        msg["role"] = "assistant"
        msg.setdefault("content", "")
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append((tc.get("id"), fn.get("name"), args if isinstance(args, dict) else {}))
        if not calls:
            msg.pop("tool_calls", None)
        return (msg, OpenAICompatible.visible(msg)[1], calls), None

    @staticmethod
    def tool_results(results):
        return [{"role": "tool", "tool_call_id": call_id, "content": json.dumps(result, ensure_ascii=False)}
                for call_id, _, result in results]

    @staticmethod
    def assistant_text(text):
        return {"role": "assistant", "content": text}


BACKEND = Gemini if PROVIDER == "gemini" else OpenAICompatible


# --------------------------------------------------------------------------- history

def load_history(user_id):
    row = query("SELECT contents FROM chat_history WHERE user_id = ?", (user_id,), one=True)
    contents = json.loads(row["contents"]) if row else []
    # History written by the other provider can't be replayed: start over.
    return contents if all(BACKEND.owns(m) for m in contents) else []


def save_history(user_id, contents):
    # Trim from the front, but always start at a plain user text turn so that
    # tool call / tool result pairs are never split.
    if len(contents) > MAX_HISTORY:
        contents = contents[-MAX_HISTORY:]
        while contents and not BACKEND.is_user_text(contents[0]):
            contents.pop(0)
    execute("INSERT INTO chat_history (user_id, contents) VALUES (?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET contents = excluded.contents",
            (user_id, json.dumps(contents, ensure_ascii=False)))


def reset_history(user_id):
    execute("DELETE FROM chat_history WHERE user_id = ?", (user_id,))


def visible_history(user_id):
    """Plain user/assistant text turns, for re-rendering the chat panel."""
    out = []
    for m in load_history(user_id):
        role, text = BACKEND.visible(m)
        if text and role in ("user", "assistant"):
            out.append({"role": role, "text": text})
    return out


# --------------------------------------------------------------------------- chat loop

def _generate(contents, sys_text, log):
    """One model call (with retries). `log(text)` reports progress to the chat UI."""
    body, headers = BACKEND.request(contents, sys_text)
    headers["Content-Type"] = "application/json"
    name = BACKEND.label
    for attempt in range(MAX_RETRIES + 1):
        t0 = time.monotonic()
        try:
            r = requests.post(API_URL, json=body, timeout=(10, REQUEST_TIMEOUT), headers=headers)
        except requests.RequestException as e:
            log(f"{name} request failed after {time.monotonic() - t0:.1f}s: {type(e).__name__}")
            if attempt < MAX_RETRIES:
                continue
            raise RuntimeError(f"{name} API unreachable or too slow ({type(e).__name__}). Try again.") from e
        dt = time.monotonic() - t0
        prompt_tokens, out_tokens = BACKEND.usage(r.json()) if r.status_code == 200 else (None, None)
        print(f"[{PROVIDER}] model={MODEL} status={r.status_code} {dt:.1f}s attempt={attempt} "
              f"prompt_tokens={prompt_tokens} out={out_tokens}"
              + (f" body={r.text[:200]!r}" if r.status_code != 200 else ""), flush=True)
        if r.status_code == 200:
            log(f"{name} answered in {dt:.1f}s ({prompt_tokens} prompt tokens)")
            return r.json()
        log(f"{name} returned HTTP {r.status_code} after {dt:.1f}s")
        if r.status_code in (404, 429, 500, 502, 503, 529) and attempt < MAX_RETRIES:
            time.sleep(2 ** attempt)
            continue
        raise RuntimeError(f"{name} API error {r.status_code}: {r.text[:300]}")


def _config_error():
    if PROVIDER == "gemini" and not API_KEY:
        return "The chatbot is not configured: AI_STUDIO_API_KEY (or LLM_API_KEY) is missing from .env."
    if PROVIDER == "openai" and not MODEL:
        return "The chatbot is not configured: LLM_MODEL is missing from .env."
    return None


def chat_events(user, message):
    """Runs one chat turn, yielding events as they happen:
    {"type": "log", "text"} | {"type": "tool", "name", "args", "result"} | {"type": "reply", "text"} |
    {"type": "error", "text"}
    """
    err = _config_error()
    if err:
        yield {"type": "error", "text": err}
        return

    contents = load_history(user["id"])
    contents.append(BACKEND.user_message(message))
    sys_text = system_prompt(user)
    pending = []  # log lines produced inside _generate
    log = lambda text: pending.append({"type": "log", "text": text})

    try:
        for step in range(MAX_STEPS):
            yield {"type": "log", "text": f"Calling {MODEL} (step {step + 1})…"}
            try:
                data = _generate(contents, sys_text, log)
            finally:
                yield from pending
                pending.clear()
            parsed, reason = BACKEND.parse(data)
            if parsed is None:
                yield {"type": "reply", "text": f"(The model returned no answer: {reason})"}
                break
            msg, text, calls = parsed
            contents.append(msg)
            if not calls:
                yield {"type": "reply", "text": text}
                break

            results = []
            for call_id, name, args in calls:
                result = call_tool(user, name, args)
                result = json.loads(json.dumps(result, default=str))
                yield {"type": "tool", "name": name, "args": args, "result": result}
                results.append((call_id, name, result))
            contents.extend(BACKEND.tool_results(results))
        else:
            text = "(Stopped: too many tool calls in one turn.)"
            contents.append(BACKEND.assistant_text(text))
            yield {"type": "reply", "text": text}
    except Exception as e:
        yield {"type": "error", "text": str(e)}
        # drop the unfinished turn so history stays valid (no dangling tool call)
        while contents and not BACKEND.is_user_text(contents[-1]):
            contents.pop()
        if contents:
            contents.pop()
    save_history(user["id"], contents)


def chat(user, message):
    """Non-streaming convenience wrapper."""
    out = {"reply": "", "tool_calls": [], "logs": []}
    for ev in chat_events(user, message):
        if ev["type"] == "tool":
            out["tool_calls"].append({k: ev[k] for k in ("name", "args", "result")})
        elif ev["type"] == "reply":
            out["reply"] = ev["text"]
        elif ev["type"] == "error":
            out["reply"] = f"Error: {ev['text']}"
        else:
            out["logs"].append(ev["text"])
    return out
