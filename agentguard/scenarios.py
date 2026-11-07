"""
agentguard/scenarios.py -- εκτέλεση σεναρίων-απαιτήσεων (μορφή agentguard-scenarios/1) πάνω σε PolicyEngine.

Ένα σενάριο είναι είτε «authorize» (expect allow/deny) είτε «redact» (expect_hidden / expect_visible).
Το `context` του σεναρίου είναι απλό dict με τα «γεγονότα»: έτσι τα σενάρια τρέχουν χωρίς καμία εφαρμογή ή βάση.
"""
from __future__ import annotations

import json

REDACTED = "[redacted]"


def _find(obj, key: str) -> list:
    out, k = [], key.lower()
    if isinstance(obj, dict):
        for name, value in obj.items():
            if str(name).lower() == k:
                out.append(value)
            out.extend(_find(value, key))
    elif isinstance(obj, (list, tuple)):
        for x in obj:
            out.extend(_find(x, key))
    return out


def run_scenario(engine, sc: dict) -> dict:
    base = {"id": sc.get("id"), "text": sc.get("text", ""), "kind": sc.get("kind")}
    try:
        if sc["kind"] == "authorize":
            d = engine.evaluate(sc["user"], sc["tool"], sc.get("args") or {}, sc.get("context") or {})
            ok = d["action"] == sc["expect"]
            return {**base, "ok": ok, "expected": sc["expect"], "actual": d["action"], "rule": d["rule"],
                    "reason": "" if ok else f"expected {sc['expect']}, engine said {d['action']} (rule {d['rule']})"}
        out = engine.redact(sc["user"], sc["tool"], sc.get("args") or {}, sc["result"], sc.get("context") or {})
        problems = []
        for key in sc.get("expect_hidden", []):
            if any(v != REDACTED for v in _find(out, key)):
                problems.append(f"{key} is visible but must be hidden")
        for key in sc.get("expect_visible", []):
            before, after = _find(sc["result"], key), _find(out, key)
            if not after or json.dumps(after, sort_keys=True, default=str) != json.dumps(before, sort_keys=True, default=str):
                problems.append(f"{key} was not kept visible with its original value")
        return {**base, "ok": not problems, "reason": "; ".join(problems)}
    except Exception as e:  # noqa: BLE001 - ένα χαλασμένο σενάριο δεν σταματά τα υπόλοιπα
        return {**base, "ok": False, "reason": f"error: {type(e).__name__}: {e}"}


def run_scenarios(engine, scenarios: list[dict]) -> dict:
    results = [run_scenario(engine, sc) for sc in scenarios]
    passed = sum(1 for r in results if r["ok"])
    return {"total": len(results), "passed": passed, "failed": [r for r in results if not r["ok"]], "results": results}


def load_scenarios(path) -> list[dict]:
    from pathlib import Path
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != "agentguard-scenarios/1":
        raise ValueError("not an agentguard-scenarios/1 file")
    return data["scenarios"]
