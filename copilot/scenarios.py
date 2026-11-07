"""
copilot/scenarios.py -- σενάρια-απαιτήσεις (μορφή agentguard-scenarios/1) και εκτέλεσή τους πάνω στον Engine.

Τα σενάρια παράγονται ΑΠΟ ΤΟ ΚΕΙΜΕΝΟ ΤΩΝ ΑΠΑΙΤΗΣΕΩΝ και τις απαντήσεις, ΟΧΙ από το πρόχειρο policy: είναι δεύτερη,
ανεξάρτητη ανάγνωση, γι' αυτό η σύγκρισή τους με το policy έχει νόημα. Συμπληρώνονται με ντετερμινιστικά σενάρια
από τον πίνακα εργαλείο × ρόλος (κάθε κελί «deny»).
Ένα σενάριο που αποτυγχάνει ΔΕΝ σημαίνει ότι το policy είναι λάθος (μπορεί να είναι λάθος το σενάριο): το review
το δείχνει ως «διαφωνία — αποφασίζει ο άνθρωπος».
"""
from __future__ import annotations

import json

from . import prompts
from .floor import issue
from .llm import LLMError

SCHEMA = "agentguard-scenarios/1"
MIN_LLM_SCENARIOS = 12
REDACTED = "[redacted]"


def validate_scenario(sc, roles, tool_names) -> str | None:
    """None αν το σενάριο είναι έγκυρο, αλλιώς ο λόγος (ελληνικά)."""
    if not isinstance(sc, dict):
        return "το σενάριο δεν είναι αντικείμενο"
    kind = sc.get("kind")
    if kind not in ("authorize", "redact"):
        return f"άγνωστο kind {kind!r}"
    user = sc.get("user")
    if not isinstance(user, dict) or "id" not in user or "role" not in user:
        return "ο χρήστης θέλει id και role"
    if roles and user["role"] not in roles:
        return f"άγνωστος ρόλος {user['role']!r}"
    if sc.get("tool") not in tool_names:
        return f"άγνωστο εργαλείο {sc.get('tool')!r}"
    if not isinstance(sc.get("args", {}), dict) or not isinstance(sc.get("context", {}), dict):
        return "τα args και context πρέπει να είναι αντικείμενα"
    if kind == "authorize":
        if sc.get("expect") not in ("allow", "deny"):
            return "το expect πρέπει να είναι allow ή deny"
        return None
    if not isinstance(sc.get("result"), (dict, list)):
        return "το redact σενάριο θέλει result (αντικείμενο ή λίστα)"
    hidden, visible = sc.get("expect_hidden", []), sc.get("expect_visible", [])
    if not (isinstance(hidden, list) and isinstance(visible, list)) or not (hidden or visible):
        return "το redact σενάριο θέλει expect_hidden και/ή expect_visible (λίστες)"
    if any(not _find(sc["result"], str(k)) for k in visible):
        return "κάθε expect_visible πεδίο πρέπει να υπάρχει στο result"
    return None


def _normalize(sc: dict, source: str) -> dict:
    out = {"id": str(sc.get("id") or ""), "kind": sc["kind"], "text": str(sc.get("text") or ""),
           "user": {**sc["user"]}, "tool": sc["tool"], "args": dict(sc.get("args") or {}),
           "context": dict(sc.get("context") or {}), "source": source}
    if sc["kind"] == "authorize":
        out["expect"] = sc["expect"]
    else:
        out.update({"result": sc["result"], "expect_hidden": [str(k) for k in sc.get("expect_hidden", [])],
                    "expect_visible": [str(k) for k in sc.get("expect_visible", [])]})
    return out


def matrix_scenarios(matrix: dict) -> list[dict]:
    """Ντετερμινιστικά σενάρια: κάθε κελί «deny» του πίνακα εργαλείο × ρόλος => deny με άδειο context."""
    out = []
    for tool, per_role in sorted(matrix.items()):
        for role, label in sorted(per_role.items()):
            if label == "deny":
                out.append({"id": f"M{len(out) + 1:02d}", "kind": "authorize", "source": "matrix",
                            "text": f"Ο ρόλος «{role}» δεν επιτρέπεται να καλεί το «{tool}»",
                            "user": {"id": f"u_{role}", "role": role}, "tool": tool, "args": {}, "context": {},
                            "expect": "deny"})
    return out


def generate_scenarios(intake: dict, decisions: dict, llm, matrix: dict | None = None) -> dict:
    """{"scenarios": [...], "issues": [...]}: από το LLM (αν υπάρχει) + ντετερμινιστικά από τον πίνακα."""
    issues: list[dict] = []
    scenarios: list[dict] = []
    roles = list(decisions.get("roles") or intake.get("roles") or [])
    names = {t["name"] for t in intake["tools"]}
    if llm is not None:
        eff = dict(intake, roles=roles)
        try:
            data = llm.complete_json(prompts.SCENARIOS_SYSTEM, prompts.scenarios_user(eff, decisions["qa"], MIN_LLM_SCENARIOS))
            raw = data.get("scenarios") if isinstance(data, dict) else None
            if not isinstance(raw, list):
                raise LLMError("η απάντηση δεν περιέχει λίστα «scenarios»")
            seen = set()
            for i, sc in enumerate(raw, 1):
                problem = validate_scenario(sc, roles, names)
                if problem:
                    issues.append(issue("info", "scenario.invalid", f"Αγνοήθηκε το σενάριο #{i} του LLM: {problem}."))
                    continue
                norm = _normalize(sc, "llm")
                if not norm["id"] or norm["id"] in seen:
                    norm["id"] = f"S{len(scenarios) + 1:02d}"
                seen.add(norm["id"])
                scenarios.append(norm)
            if len(scenarios) < MIN_LLM_SCENARIOS:
                issues.append(issue("warning", "scenario.few", f"Το LLM έδωσε μόνο {len(scenarios)} έγκυρα σενάρια (στόχος ≥ {MIN_LLM_SCENARIOS})."))
        except LLMError as e:
            issues.append(issue("warning", "scenario.llm_error", f"Δεν παράχθηκαν σενάρια από το LLM ({e}). Θα υπάρχουν μόνο τα ντετερμινιστικά."))
    ids = {s["id"] for s in scenarios}
    for sc in matrix_scenarios(matrix or {}):
        if sc["id"] in ids:
            sc["id"] = f"M{len(scenarios) + 1:02d}"
        scenarios.append(sc)
    return {"scenarios": scenarios, "issues": issues}


# ---------------------------------------------------------------------------
# Εκτέλεση
# ---------------------------------------------------------------------------

def _find(obj, key: str) -> list:
    """Όλες οι τιμές του κλειδιού `key` (χωρίς διάκριση πεζών/κεφαλαίων) οπουδήποτε μέσα στο obj."""
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


def _run_one(engine, sc: dict) -> dict:
    base = {"id": sc["id"], "text": sc.get("text", ""), "source": sc.get("source", ""), "kind": sc["kind"]}
    try:
        if sc["kind"] == "authorize":
            d = engine.evaluate(sc["user"], sc["tool"], sc.get("args") or {}, sc.get("context") or {})
            ok = d["action"] == sc["expect"]
            return {**base, "ok": ok, "expected": sc["expect"], "actual": d["action"], "rule": d["rule"],
                    "reason": "" if ok else f"αναμενόταν {sc['expect']}, ο μηχανισμός έδωσε {d['action']} (κανόνας: {d['rule']})"}
        out = engine.redact(sc["user"], sc["tool"], sc.get("args") or {}, sc["result"], sc.get("context") or {})
        problems = []
        for key in sc.get("expect_hidden", []):
            if any(v != REDACTED for v in _find(out, key)):
                problems.append(f"το «{key}» φαίνεται ενώ έπρεπε να είναι κρυμμένο")
        for key in sc.get("expect_visible", []):
            before, after = _find(sc["result"], key), _find(out, key)
            if not after or json.dumps(after, sort_keys=True, default=str) != json.dumps(before, sort_keys=True, default=str):
                problems.append(f"το «{key}» δεν διατηρήθηκε ορατό με την αρχική τιμή")
        return {**base, "ok": not problems, "expected": {"hidden": sc.get("expect_hidden", []), "visible": sc.get("expect_visible", [])},
                "actual": "redacted-output", "reason": "; ".join(problems)}
    except Exception as e:  # noqa: BLE001 - ένα χαλασμένο σενάριο δεν πρέπει να σταματά τα υπόλοιπα
        return {**base, "ok": False, "expected": None, "actual": "error", "reason": f"σφάλμα εκτέλεσης: {type(e).__name__}: {e}"}


def run_scenarios(engine, scenarios: list[dict]) -> dict:
    """{"total","passed","failed":[...],"results":[...],"by_source":{...}}"""
    results = [_run_one(engine, sc) for sc in scenarios]
    by_source: dict = {}
    for r in results:
        s = by_source.setdefault(r["source"] or "?", {"total": 0, "passed": 0})
        s["total"] += 1
        s["passed"] += 1 if r["ok"] else 0
    return {"total": len(results), "passed": sum(1 for r in results if r["ok"]),
            "failed": [r for r in results if not r["ok"]], "results": results, "by_source": by_source}


def to_file_object(scenarios: list[dict]) -> dict:
    """Η μορφή 3.5 (agentguard-scenarios/1) χωρίς τα εσωτερικά πεδία."""
    clean = [{k: v for k, v in sc.items() if k != "source"} for sc in scenarios]
    return {"schema": SCHEMA, "scenarios": clean}
