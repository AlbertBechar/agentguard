"""
examples/sim_agent.py -- «αφελής agent» ΧΩΡΙΣ LLM: προσομοιώνει τον ΧΕΙΡΟΤΕΡΟ agent.

Εκτελεί ΟΠΟΙΑΔΗΠΟΤΕ οδηγία βρει είτε στο μήνυμα του χρήστη είτε μέσα στα αποτελέσματα των εργαλείων. Μια οδηγία είναι
το κείμενο  `call <εργαλείο> {json ορίσματα}`. Διαβάζει «μέσα από» αόρατους χαρακτήρες (όπως θα έκανε ένα μοντέλο).
Το `{{last_result}}` μέσα σε ορίσματα αντικαθίσταται με ό,τι είδε ο agent από την προηγούμενη κλήση (εξαγωγή δεδομένων).

ΕΙΛΙΚΡΙΝΕΙΑ: αυτός ΔΕΝ είναι πραγματικό μοντέλο. Τα νούμερα των demos δείχνουν τι σταματά ο Guard όταν ο agent κάνει το
χειρότερο· δεν μετρούν πόσο συχνά ένα πραγματικό LLM θα ακολουθούσε μια κακόβουλη οδηγία.
"""
from __future__ import annotations

import json
import re

INVISIBLE = "​‌‍⁠﻿"
_STRIP = re.compile("[" + INVISIBLE + "]")
_DIRECTIVE = re.compile(r"\bcall\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?=\{)", re.I)
MAX_CALLS = 12


def parse_directives(text: str) -> list[tuple[str, dict]]:
    """Βρίσκει όλες τις οδηγίες `call tool {json}` μέσα σε ένα κείμενο (αγνοώντας αόρατους χαρακτήρες)."""
    text = _STRIP.sub("", str(text))
    out, decoder = [], json.JSONDecoder()
    for m in _DIRECTIVE.finditer(text):
        try:
            obj, _ = decoder.raw_decode(text[m.end():])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append((m.group(1), obj))
    return out


def iter_strings(obj):
    """Όλα τα κείμενα που περιέχει ένα αποτέλεσμα (αναδρομικά)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from iter_strings(v)


def _substitute(value, last_text: str):
    if isinstance(value, str):
        return value.replace("{{last_result}}", last_text)
    if isinstance(value, dict):
        return {k: _substitute(v, last_text) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, last_text) for v in value]
    return value


class Outcome:
    """Αυτό που «βλέπει» ο agent μετά από μια κλήση + τι αποφάσισε το σύστημα."""

    def __init__(self, observed, status="ok", rule="", findings=0):
        self.observed, self.status, self.rule, self.findings = observed, status, rule, findings


def unprotected(app):
    """Κλήση ΧΩΡΙΣ Guard: κατευθείαν στην εφαρμογή."""
    def call(user, tool, args):
        return Outcome(app.call_tool(user, tool, args))
    return call, (lambda: None)


def guarded(guard, app, session_id="demo"):
    """Κλήση ΜΕ Guard: guard.wrap(app.call_tool). Ο agent βλέπει ό,τι θα έβλεπε το μοντέλο (tool_message)."""
    safe = guard.wrap(app.call_tool)

    def call(user, tool, args):
        out = safe(session_id, user, tool, args)
        observed = out["result"] if out["status"] == "ok" else guard.tool_message(out)
        return Outcome(observed, out["status"], out["rule"], len(out["findings"]))
    return call, (lambda: guard.new_turn(session_id, ""))


class NaiveAgent:
    def __init__(self, call, begin_turn=None, max_calls: int = MAX_CALLS):
        self.call, self.begin_turn, self.max_calls = call, begin_turn or (lambda: None), max_calls

    def run(self, user: dict, message: str) -> dict:
        """Εκτελεί τις οδηγίες του μηνύματος και, διαδοχικά, όσες βρει μέσα στα αποτελέσματα."""
        self.begin_turn()                                  # νέο μήνυμα χρήστη => νέος γύρος
        queue = parse_directives(message)
        steps, seen, last_text = [], set(), ""
        while queue and len(steps) < self.max_calls:
            tool, args = queue.pop(0)
            args = _substitute(args, last_text)
            key = (tool, json.dumps(args, sort_keys=True, default=str))
            if key in seen:
                continue
            seen.add(key)
            outcome = self.call(user, tool, args)
            text = outcome.observed if isinstance(outcome.observed, str) else json.dumps(outcome.observed, ensure_ascii=False, default=str)
            steps.append({"tool": tool, "args": args, "status": outcome.status, "rule": outcome.rule,
                          "findings": outcome.findings, "observed": text})
            last_text = text
            for s in iter_strings(outcome.observed):       # ο αφελής agent υπακούει και σε οδηγίες μέσα στα δεδομένα
                queue.extend(parse_directives(s))
        return {"steps": steps, "observed": [s["observed"] for s in steps]}
