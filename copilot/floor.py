"""
copilot/floor.py -- το safety floor: ό,τι γράφει το LLM περνά από εδώ και ΜΟΝΟ σφίγγει, ποτέ δεν χαλαρώνει.

Εφαρμόζεται πάνω στο πρόχειρο policy (LLM ή offline) και:
 (α) καλύπτει κάθε εργαλείο με ≥ 1 ρητό κανόνα (αλλιώς ρητό deny `floor.uncovered.<tool>`)·
 (β) κλείνει τα dangerous εργαλεία (και όσα ο άνθρωπος απάντησε «σε κανέναν») εκτός αν ο άνθρωπος τα ανοίξει ρητά·
 (γ) ενώνει τις λίστες untrusted/high_risk με τα heuristics (το LLM δεν μπορεί να αφαιρέσει εργαλείο)·
 (δ) probe: high-risk εργαλείο × ρόλος που επιτρέπεται με ΑΔΕΙΟ context => error (εκτός αν επιβεβαιώθηκε)·
 (ε) `$ctx.x` χωρίς πηγή => `meta.context_attributes.x` ως requested + warning·
 (ζ) έλεγχος των lookups στο σχήμα της βάσης (πίνακες/στήλες, EXPLAIN).
Κάθε αλλαγή καταγράφεται ως issue {"level","code","tool"?,"rule"?,"message"} (ελληνικά).
"""
from __future__ import annotations

import copy
import re

from app.policy_engine import SCHEMA, PolicyEngine, validate_policy

from .dbschema import SchemaInfo

APPROVAL_META_KEYS = ("approved_by", "approved_at", "source_sha256", "generated_by")
_TABLE_REF = re.compile(r"\b(?:FROM|JOIN)\s+([`\"\[]?[A-Za-z_][\w]*[`\"\]]?(?:\.[`\"\[]?[A-Za-z_][\w]*[`\"\]]?)?)", re.I)


def issue(level: str, code: str, message: str, tool: str | None = None, rule: str | None = None, **extra) -> dict:
    d = {"level": level, "code": code, "message": message}
    if tool:
        d["tool"] = tool
    if rule:
        d["rule"] = rule
    d.update(extra)
    return d


def has_errors(issues: list[dict]) -> bool:
    return any(i["level"] == "error" for i in issues)


def validate_issues(policy) -> list[dict]:
    """Τα αποτελέσματα του validate_policy του Engine ως issues."""
    return [issue(v["level"], "validate", f'{v["path"] or "<root>"}: {v["message"]}', path=v["path"])
            for v in validate_policy(policy)]


def collect_ctx_names(node, found: set | None = None) -> set:
    found = set() if found is None else found
    if isinstance(node, str):
        if node.startswith("$ctx."):
            found.add(node[5:].split(".")[0])
    elif isinstance(node, dict):
        for v in node.values():
            collect_ctx_names(v, found)
    elif isinstance(node, list):
        for v in node:
            collect_ctx_names(v, found)
    return found


def _lookup_tables(sql: str) -> set:
    names = set()
    for m in _TABLE_REF.finditer(re.sub(r"'(?:[^']|'')*'", "''", sql)):
        names.add(m.group(1).split(".")[-1].strip('`"[]').lower())
    return names


def apply_floor(policy, intake: dict, analysis: dict, decisions: dict, schema: SchemaInfo | None = None):
    """Επιστρέφει (policy_νέο, issues). Δεν αλλάζει το αρχικό αντικείμενο."""
    issues: list[dict] = []
    schema = schema or SchemaInfo(None)
    policy = copy.deepcopy(policy) if isinstance(policy, dict) else {}
    names = [t["name"] for t in intake["tools"]]
    confirmed_open = set(decisions.get("confirmed_open") or [])

    # --- βασικά: schema, ρόλοι, default deny, καμία «πλαστή» έγκριση από το LLM
    if policy.get("schema") != SCHEMA:
        policy["schema"] = SCHEMA
    if not isinstance(policy.get("roles"), list) or not policy.get("roles"):
        policy["roles"] = list(decisions.get("roles") or intake.get("roles") or [])
        issues.append(issue("info", "floor.roles", "Το πρόχειρο δεν όριζε ρόλους· χρησιμοποιήθηκαν αυτοί της εισόδου."))
    if policy.get("default_action", "deny") != "deny":
        policy["default_action"] = "deny"
        issues.append(issue("info", "floor.default_action", "Το default_action ορίστηκε σε deny (ό,τι δεν επιτρέπεται ρητά απορρίπτεται)."))
    policy.setdefault("default_action", "deny")
    if not isinstance(policy.get("rules"), list):
        policy["rules"] = []
        issues.append(issue("error", "floor.rules", "Το πρόχειρο δεν είχε λίστα κανόνων."))
    meta = policy.get("meta") if isinstance(policy.get("meta"), dict) else {}
    for key in APPROVAL_META_KEYS:
        if key in meta:
            del meta[key]
            issues.append(issue("info", "floor.meta", f"Αφαιρέθηκε το meta.{key}: τα στοιχεία έγκρισης τα γράφει μόνο το approve()."))
    policy["meta"] = meta

    # --- (γ) ενοποίηση λιστών: μόνο προσθέτουμε
    for key, wanted, label in (("untrusted_tools", {n for n, a in analysis.items() if a["returns_untrusted"]}, "untrusted"),
                               ("high_risk_tools", {n for n, a in analysis.items() if a["risk"] != "read"}, "high-risk")):
        current = policy.get(key) if isinstance(policy.get(key), list) else []
        missing = sorted(wanted - set(current))
        policy[key] = list(current) + missing
        for tool in missing:
            issues.append(issue("info", f"floor.{key}", f"Το εργαλείο «{tool}» προστέθηκε στα {label} ({analysis[tool]['reasons']['untrusted' if label == 'untrusted' else 'risk']}).", tool=tool))

    # --- (β) dangerous και «σε κανέναν»: κλείνουν για όλους
    for tool in names:
        level = decisions.get("tool_access", {}).get(tool)
        dangerous = analysis[tool]["risk"] == "dangerous"
        already = any(isinstance(r, dict) and r.get("id") == f"floor.denied.{tool}" for r in policy["rules"])
        if ((dangerous and level not in ("privileged", "all")) or level == "none") and already:
            continue  # το floor έχει ήδη εφαρμοστεί (idempotent)
        if (dangerous and level not in ("privileged", "all")) or level == "none":
            stripped = 0
            for r in policy["rules"]:
                if isinstance(r, dict) and r.get("effect") == "allow" and isinstance(r.get("tools"), list) and tool in r["tools"]:
                    r["tools"] = [t for t in r["tools"] if t != tool]
                    stripped += 1
            policy["rules"] = [r for r in policy["rules"] if not (isinstance(r, dict) and r.get("effect") == "allow" and r.get("tools") == [])]
            policy["rules"].append({"id": f"floor.denied.{tool}", "tools": [tool], "roles": ["*"], "effect": "deny",
                                    "reason": "closed for everyone by the safety floor (dangerous or denied by the human)"})
            why = "επικίνδυνο εργαλείο" if dangerous and level != "none" else "ο άνθρωπος απάντησε «σε κανέναν»"
            issues.append(issue("info", "floor.denied", f"Το «{tool}» κλείνει για όλους ({why})"
                                + (f"· αφαιρέθηκε από {stripped} κανόνα(ες) allow." if stripped else "."),
                                tool=tool, rule=f"floor.denied.{tool}"))
        elif level == "privileged" and decisions.get("tool_roles", {}).get(tool):
            allowed = set(decisions["tool_roles"][tool])
            outside = [r for r in policy["roles"] if r not in allowed]
            rid = f"floor.roles.{tool}"
            if outside and not any(isinstance(r, dict) and r.get("id") == rid for r in policy["rules"]):
                policy["rules"].append({"id": rid, "tools": [tool], "roles": outside, "effect": "deny",
                                        "reason": "only the roles chosen by the human may call this tool"})
                issues.append(issue("info", "floor.roles", f"Το «{tool}» επιτρέπεται μόνο στους ρόλους που επέλεξε ο άνθρωπος "
                                    f"({', '.join(sorted(allowed))})· κλείνει για: {', '.join(outside)}.", tool=tool, rule=rid))
        elif level == "privileged":
            issues.append(issue("warning", "floor.privileged", f"Για το «{tool}» επιλέχθηκε «μόνο ο πιο προνομιούχος ρόλος»: "
                                "ελέγξτε στον πίνακα ότι το επιτρέπει μόνο ο κατάλληλος ρόλος.", tool=tool))

    # --- κανόνας allow για ΟΛΑ τα εργαλεία: σχεδόν σίγουρα prompt injection ή λάθος· μπλοκάρει την έγκριση
    for r in policy["rules"]:
        if isinstance(r, dict) and r.get("effect") == "allow" and isinstance(r.get("tools"), list) and "*" in r["tools"]:
            issues.append(issue("error", "floor.wildcard_allow",
                                f"Ο κανόνας «{r.get('id')}» επιτρέπει ΟΛΑ τα εργαλεία (tools: [\"*\"]). Το πρόχειρο δεν μπορεί να "
                                "εγκριθεί· ελέγξτε τις περιγραφές των εργαλείων για κακόβουλες οδηγίες.", rule=str(r.get("id"))))

    # --- (α) κάθε εργαλείο καλύπτεται από ≥ 1 ρητό κανόνα
    explicit = {t for r in policy["rules"] if isinstance(r, dict) and isinstance(r.get("tools"), list)
                for t in r["tools"] if t != "*"}
    for tool in names:
        if tool not in explicit:
            policy["rules"].append({"id": f"floor.uncovered.{tool}", "tools": [tool], "roles": ["*"], "effect": "deny",
                                    "reason": "no explicit rule was written for this tool: denied by the safety floor"})
            issues.append(issue("warning", "floor.uncovered", f"Το πρόχειρο δεν είχε κανόνα για το «{tool}»· προστέθηκε ρητό deny.",
                                tool=tool, rule=f"floor.uncovered.{tool}"))

    # --- (ε) γεγονότα $ctx.* χωρίς πηγή
    lookups = policy.get("lookups") if isinstance(policy.get("lookups"), dict) else {}
    provided = intake.get("context_attributes") or {}
    ctx_meta = meta.get("context_attributes") if isinstance(meta.get("context_attributes"), dict) else {}
    used = collect_ctx_names(policy.get("rules")) | collect_ctx_names(policy.get("redaction_rules"))
    for name in sorted(used):
        if name in lookups:
            continue
        if name in provided:
            ctx_meta[name] = provided[name]
            continue
        old = ctx_meta.get(name)
        desc = (old.get("description") if isinstance(old, dict) else old) or ""
        ctx_meta[name] = {"description": str(desc), "requested": True}
        issues.append(issue("warning", "floor.ctx_requested",
                            f"Ο developer πρέπει να υλοποιήσει το γεγονός «{name}» ($ctx.{name}): δεν δόθηκε ούτε έχει lookup.",
                            ctx=name))
    for name, desc in provided.items():
        ctx_meta.setdefault(name, desc)
    for name, lk in lookups.items():
        if isinstance(lk, dict):
            ctx_meta.setdefault(name, lk.get("description") or "")
    policy["meta"]["context_attributes"] = ctx_meta

    # --- (ζ) lookups πάνω στο σχήμα της βάσης
    known = schema.lower_tables()
    for name, lk in lookups.items():
        if not isinstance(lk, dict) or not isinstance(lk.get("sql"), str):
            continue  # το validate_policy το αναφέρει
        if not str(lk.get("description") or "").strip():
            issues.append(issue("warning", "lookup.no_description", f"Το lookup «{name}» δεν έχει περιγραφή.", lookup=name))
        if not known:
            issues.append(issue("error", "lookup.no_schema", f"Το lookup «{name}» δεν μπορεί να επαληθευτεί: δεν δόθηκε σχήμα βάσης (db_schema).", lookup=name))
            continue
        missing = sorted(t for t in _lookup_tables(lk["sql"]) if t not in known)
        if missing:
            issues.append(issue("error", "lookup.table_missing",
                                f"Το lookup «{name}» αναφέρεται σε πίνακα που δεν υπάρχει στο σχήμα: {', '.join(missing)}.", lookup=name))
            continue
        problem = schema.explain(lk["sql"]) if schema.loaded else None
        if not schema.loaded:
            issues.append(issue("warning", "lookup.not_checked", f"Το lookup «{name}» δεν ελέγχθηκε με EXPLAIN (το σχήμα δεν φορτώθηκε σε sqlite3).", lookup=name))
        elif problem:
            issues.append(issue("error", "lookup.explain_failed", f"Το lookup «{name}» αποτυγχάνει στο σχήμα: {problem}.", lookup=name))

    # --- (δ) probe με άδειο context
    hard = [v for v in validate_policy(policy) if v["level"] == "error"]
    if hard:
        issues.append(issue("warning", "probe.skipped", "Το probe παραλείφθηκε επειδή η πολιτική έχει errors· διορθώστε τα πρώτα."))
        return policy, issues
    engine = PolicyEngine(policy)
    for tool in sorted(set(policy.get("high_risk_tools", [])) & set(names)):
        for role in engine.roles:
            d = engine.evaluate({"id": "__probe__", "role": role}, tool, {}, {})
            if d["action"] != "allow":
                continue
            if tool in confirmed_open:
                issues.append(issue("warning", "probe.confirmed",
                                    f"Το «{tool}» επιτρέπεται στον ρόλο «{role}» χωρίς συνθήκη (επιβεβαιώθηκε από τον άνθρωπο).",
                                    tool=tool, rule=d["rule"], role=role))
            else:
                issues.append(issue("error", "probe.open",
                                    f"Το εργαλείο υψηλού ρίσκου «{tool}» επιτρέπεται στον ρόλο «{role}» χωρίς καμία συνθήκη "
                                    f"ιδιοκτησίας ή ορίου (κανόνας {d['rule']}). Προσθέστε συνθήκη ή επιβεβαιώστε ρητά "
                                    "στις απαντήσεις ότι είναι σκόπιμο.", tool=tool, rule=d["rule"], role=role))
    return policy, issues
