"""
copilot/generate.py -- πρόχειρο policy: LLM -> validate (έως 2 διορθώσεις) -> safety floor.

Αν δεν υπάρχει LLM ή αποτύχει, φτιάχνεται συντηρητική offline πολιτική από τα heuristics.
Επιστρέφει {"policy","issues","source","model","assumptions","open_questions","raw_policy","attempts"}.
Το LLM δεν αποφασίζει τίποτα την ώρα που τρέχει ο agent: εδώ γράφεται μόνο ένα ΠΡΟΧΕΙΡΟ που θα υπογράψει άνθρωπος.
"""
from __future__ import annotations

import copy

from app.policy_engine import SCHEMA, validate_policy

from . import prompts
from .dbschema import SchemaInfo
from .floor import apply_floor, issue, validate_issues
from .llm import LLMError, LLMFormatError

MAX_FIX_ATTEMPTS = 2


def build_offline_policy(intake: dict, analysis: dict, decisions: dict) -> dict:
    """Συντηρητικό πρόχειρο από heuristics: μόνο ανάγνωση ανοίγει, κάθε άλλο εργαλείο κλειστό, όλα τα ευαίσθητα κρυμμένα."""
    roles = list(decisions.get("roles") or intake.get("roles") or ["user", "admin"])
    rules = []
    for t in intake["tools"]:
        name, a = t["name"], analysis[t["name"]]
        if a["risk"] == "read":
            rules.append({"id": f"offline.read.{name}", "tools": [name], "roles": list(roles), "effect": "allow",
                          "reason": "read-only tool (offline draft: ownership checks must be added by a human)"})
        else:
            rules.append({"id": f"offline.closed.{name}", "tools": [name], "roles": ["*"], "effect": "deny",
                          "reason": f"{a['risk']} tool closed in the offline draft until a human decides"})
    sensitive = decisions.get("sensitive_fields")
    if sensitive is None:
        sensitive = sorted({f for a in analysis.values() for f in a["sensitive_params"] + a["sensitive_fields"]})
    return {"schema": SCHEMA, "app": (intake.get("company") or "app").split("—")[0].strip()[:40] or "app",
            "default_action": "deny", "meta": {"context_attributes": dict(intake.get("context_attributes") or {})},
            "roles": roles,
            "untrusted_tools": sorted(n for n, a in analysis.items() if a["returns_untrusted"]),
            "high_risk_tools": sorted(n for n, a in analysis.items() if a["risk"] != "read"),
            "rules": rules,
            "redaction_rules": {"always_redact_fields": sorted(set(sensitive))}}


def _unpack(data):
    """Δέχεται {"policy":{...},"assumptions":[...]} ή απευθείας το policy."""
    if not isinstance(data, dict):
        return None, [], []
    if isinstance(data.get("policy"), dict):
        policy = data["policy"]
    elif "rules" in data or "roles" in data or data.get("schema"):
        policy = data
    else:
        return None, [], []
    strs = lambda v: [str(x) for x in v] if isinstance(v, list) else []  # noqa: E731
    return policy, strs(data.get("assumptions")), strs(data.get("open_questions"))


def _prepare(policy: dict, intake: dict, decisions: dict) -> dict:
    p = copy.deepcopy(policy)
    p.setdefault("schema", SCHEMA)
    if not isinstance(p.get("roles"), list) or not p["roles"]:
        p["roles"] = list(decisions.get("roles") or intake.get("roles") or [])
    return p


def _errors_of(policy) -> list[str]:
    return [f'{v["path"] or "<root>"}: {v["message"]}' for v in validate_policy(policy) if v["level"] == "error"]


def generate_policy(intake: dict, analysis: dict, decisions: dict, schema: SchemaInfo | None, llm,
                    max_fix: int = MAX_FIX_ATTEMPTS) -> dict:
    issues: list[dict] = []
    policy, assumptions, open_questions, attempts, raw = None, [], [], 0, None
    last_errors: list[str] = []
    llm_policy = None
    if llm is not None:
        system = prompts.policy_system()
        user = prompts.policy_user(intake, analysis, decisions["qa"])
        for attempt in range(max_fix + 1):
            attempts += 1
            try:
                data = llm.complete_json(system, user)
            except LLMFormatError:
                # χαλασμένο JSON: ξαναρωτάμε (όπως και για λάθη του validate), μέχρι να εξαντληθούν οι επαναλήψεις
                if attempt == max_fix:
                    issues.append(issue("warning", "llm.invalid", "Το LLM δεν επέστρεψε έγκυρο JSON μετά από "
                                        f"{max_fix} επαναλήψεις: θα χρησιμοποιηθεί η offline πολιτική."))
                    break
                user = prompts.policy_user(intake, analysis, decisions["qa"],
                                           fix={"policy": {}, "errors": ["η προηγούμενη απάντηση δεν ήταν έγκυρο JSON αντικείμενο"]})
                continue
            except LLMError as e:
                issues.append(issue("warning", "llm.error", f"Το LLM απέτυχε ({e}): θα χρησιμοποιηθεί η offline πολιτική."))
                break
            cand, assumptions, open_questions = _unpack(data)
            errors = ["η απάντηση δεν είναι αντικείμενο policy"] if cand is None else _errors_of(_prepare(cand, intake, decisions))
            last_errors = errors
            if cand is not None and raw is None:
                raw = copy.deepcopy(cand)
            if not errors:
                policy = _prepare(cand, intake, decisions)
                llm_policy = copy.deepcopy(policy)          # το πρόχειρο του LLM ΠΡΙΝ το safety floor (για μέτρηση)
                break
            if attempt == max_fix:
                issues.append(issue("warning", "llm.invalid", f"Το πρόχειρο του LLM έμεινε άκυρο μετά από {max_fix} διορθώσεις "
                                    f"({errors[0]}): θα χρησιμοποιηθεί η offline πολιτική."))
                break
            user = prompts.policy_user(intake, analysis, decisions["qa"],
                                       fix={"policy": cand if cand is not None else (data if isinstance(data, dict) else {}),
                                            "errors": errors})
    source = "llm"
    if policy is None:
        unsafe = [e for e in last_errors if e.startswith("lookups")]
        if unsafe:
            # SQL που παραβιάζει τους κανόνες ασφαλείας ΔΕΝ περνά σιωπηλά: μπλοκάρει την έγκριση μέχρι να το δει άνθρωπος
            issues.append(issue("error", "llm.unsafe_lookup",
                                f"Το LLM πρότεινε lookup SQL που παραβιάζει τους κανόνες ασφαλείας ({unsafe[0]}) και δεν διορθώθηκε. "
                                "Χρησιμοποιήθηκε offline πολιτική, αλλά η έγκριση μπλοκάρεται μέχρι να ελεγχθεί το αίτημα."))
        source = "offline"
        policy = build_offline_policy(intake, analysis, decisions)
        assumptions, open_questions = [], []
        issues.append(issue("warning", "offline.draft", "Offline πρόχειρο από heuristics — χρειάζεται ανθρώπινη συμπλήρωση "
                            "(ανοίγουν μόνο εργαλεία ανάγνωσης· κάθε εγγραφή/εξωτερικό/επικίνδυνο είναι κλειστό)."))
    policy, floor_issues = apply_floor(policy, intake, analysis, decisions, schema)
    issues += floor_issues + [i for i in validate_issues(policy) if i["level"] in ("error", "warning")]
    model = getattr(llm, "label", None) if (llm is not None and source == "llm") else "offline"
    return {"policy": policy, "issues": issues, "source": source, "model": model, "assumptions": assumptions,
            "open_questions": open_questions, "raw_policy": raw, "llm_policy": llm_policy, "attempts": attempts}
