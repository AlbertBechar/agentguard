"""
copilot/contract.py -- το «συμβόλαιο ενσωμάτωσης»: τι πρέπει να δώσει η εταιρία και πώς συνδέει τον Guard.

* context_contract_md : λίστα όλων των $ctx.* που χρησιμοποιεί η πολιτική, με περιγραφή και πηγή (lookup ή resolver)
* resolver_stub_py    : αρχείο Python ΜΟΝΟ για τα γεγονότα που ΔΕΝ έχουν lookup (αλλιώς None: κανένα άχρηστο stub)
* snippet(lang)       : έτοιμος κώδικας (python / node / http) με τα πραγματικά ονόματα του API του Guard

Δεν εκτελούμε τίποτα από αυτά. Κείμενα που γράφει το LLM (περιγραφές) δεν μπαίνουν ποτέ μέσα σε docstrings/σχόλια
του παραγόμενου κώδικα· μπαίνουν μόνο ως repr() literals, ώστε να μη μπορούν να «σπάσουν» το αρχείο.
"""
from __future__ import annotations

import json
import re

from .floor import collect_ctx_names

STUB_MODULE = "resolver_stub"


def context_names_used(policy: dict) -> list[str]:
    names = collect_ctx_names(policy.get("rules")) | collect_ctx_names(policy.get("redaction_rules"))
    return sorted(names)


def _lookups(policy: dict) -> dict:
    lk = policy.get("lookups")
    return lk if isinstance(lk, dict) else {}


def resolver_needed(policy: dict) -> list[str]:
    """Γεγονότα που χρησιμοποιεί η πολιτική και δεν καλύπτονται από lookup."""
    return [n for n in context_names_used(policy) if n not in _lookups(policy)]


def _meta_entry(policy: dict, name: str) -> tuple[str, bool]:
    meta = policy.get("meta") if isinstance(policy.get("meta"), dict) else {}
    ctx = meta.get("context_attributes") if isinstance(meta.get("context_attributes"), dict) else {}
    entry = ctx.get(name)
    if isinstance(entry, dict):
        return str(entry.get("description") or ""), bool(entry.get("requested"))
    return str(entry or ""), False


def context_contract_md(policy: dict) -> str:
    used = context_names_used(policy)
    lines = ["# Συμβόλαιο γεγονότων ($ctx)", "",
             "Οι κανόνες της πολιτικής ρωτούν «γεγονότα» για κάθε κλήση (π.χ. ποιος είναι ο ιδιοκτήτης μιας εγγραφής). "
             "Κάθε γεγονός προέρχεται είτε από **lookup** (SQL μέσα στο policy.json, τρέχει μόνο ανάγνωση) είτε από "
             "**resolver** (μικρή συνάρτηση που γράφει ο developer σας). Αν ένα γεγονός λείπει, οι κανόνες που το "
             "χρειάζονται **απορρίπτουν** (fail-closed).", ""]
    if not used:
        return "\n".join(lines + ["Η πολιτική δεν χρησιμοποιεί κανένα γεγονός `$ctx`: δεν χρειάζεται lookup ούτε resolver."]) + "\n"
    lines += ["| Γεγονός | Τι σημαίνει | Πηγή |", "|---|---|---|"]
    for name in used:
        desc, requested = _meta_entry(policy, name)
        lk = _lookups(policy).get(name)
        if lk is not None:
            desc = desc or str((lk or {}).get("description") or "")
            source = "lookup (SQL, μόνο ανάγνωση)"
        else:
            source = "resolver — **ο developer πρέπει να το υλοποιήσει**" + (" (το ζήτησε το AI, δεν είχε δοθεί)" if requested else "")
        lines.append(f"| `$ctx.{name}` | {desc.replace('|', '/').replace(chr(10), ' ') or '—'} | {source} |")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# resolver stub
# ---------------------------------------------------------------------------

def _ident(name: str) -> str:
    ident = re.sub(r"\W", "_", name)
    return ("_" + ident) if ident[:1].isdigit() else ident


def resolver_stub_py(policy: dict) -> str | None:
    """Αρχείο Python με μία TODO συνάρτηση ανά γεγονός ΧΩΡΙΣ lookup. None αν δεν χρειάζεται κανένα."""
    names = resolver_needed(policy)
    if not names:
        return None
    out = ['"""Resolver stub (παράχθηκε από το Copilot).',
           "",
           "Υλοποιήστε τις συναρτήσεις _attr_* ώστε να επιστρέφουν την αληθινή τιμή του γεγονότος από τα δεδομένα σας.",
           "Όσο μια συνάρτηση δεν είναι υλοποιημένη (NotImplementedError), το γεγονός ΛΕΙΠΕΙ και οι κανόνες που το",
           'χρειάζονται απορρίπτουν (fail-closed).',
           '"""',
           "from __future__ import annotations", "", "DESCRIPTIONS = {"]
    for name in names:
        out.append(f"    {name!r}: {_meta_entry(policy, name)[0]!r},")
    out += ["}", ""]
    for name in names:
        fn = _ident(name)
        out += [f"def _attr_{fn}(user, tool, args):",
                f'    """TODO: return the value of the fact {fn!r} for this call (see DESCRIPTIONS)."""',
                f"    raise NotImplementedError({('TODO: implement the fact ' + name)!r})", "", ""]
    out.append("_ATTRIBUTES = {")
    for name in names:
        out.append(f"    {name!r}: _attr_{_ident(name)},")
    out += ["}", "", "",
            "def resolve(user, tool, args):",
            '    """Returns {fact_name: value} for the facts that are implemented."""',
            "    facts = {}",
            "    for name, fn in _ATTRIBUTES.items():",
            "        try:",
            "            facts[name] = fn(user, tool, args)",
            "        except NotImplementedError:",
            "            continue  # not implemented yet: the fact is missing, so rules that need it deny",
            "    return facts", ""]
    return "\n".join(out)


# ---------------------------------------------------------------------------
# snippets
# ---------------------------------------------------------------------------

def _example_tool(policy: dict, tools) -> tuple[str, list[str]]:
    names = [t["name"] for t in tools] if tools else sorted({x for r in policy.get("rules", []) if isinstance(r, dict)
                                                          for x in r.get("tools", []) if x != "*"})
    danger = set(policy.get("high_risk_tools") or [])
    pick = next((n for n in names if n not in danger), names[0] if names else "my_tool")
    params = []
    if tools:
        params = list(next((t for t in tools if t["name"] == pick), {}).get("params", {}))
    return pick, params


def snippet(lang: str, policy: dict, tools=None) -> str:
    if lang not in ("python", "node", "http"):
        raise ValueError("η γλώσσα πρέπει να είναι python, node ή http")
    tool, params = _example_tool(policy, tools)
    has_lookups = bool(_lookups(policy))
    needs_resolver = bool(resolver_needed(policy))
    args_json = json.dumps({p: "..." for p in params}, ensure_ascii=False)
    protected = ", ".join(sorted({x for r in policy.get("rules", []) if isinstance(r, dict) for x in r.get("tools", []) if x != "*"}))

    if lang == "python":
        imports = "from agentguard import Guard, sqlite_readonly" if has_lookups else "from agentguard import Guard"
        lines = [imports]
        if needs_resolver:
            lines.append(f"from {STUB_MODULE} import resolve")
        args = ['"policy.json"']
        if has_lookups:
            args.append('db=sqlite_readonly("company.db")')
        if needs_resolver:
            args.append("context_resolver=resolve")
        lines += [f"guard = Guard.from_policy({', '.join(args)})", "safe_call = guard.wrap(my_call_tool)"]
        lines += ["", f"# protected tools: {protected}",
                  f"# out = safe_call(session_id, user, {tool!r}, {args_json})   # user = {{'id': ..., 'role': ...}}",
                  "# call guard.new_turn(session_id, user_message) at the start of every user message"]
        return "\n".join(lines) + "\n"

    sqlite_flag = " --sqlite company.db" if has_lookups else ""
    ctx_note = ""
    if needs_resolver:
        ctx_note = ("  // the policy needs these facts and there is no lookup for them: send them in `context`\n"
                    f"  // {', '.join(resolver_needed(policy))}\n")
    if lang == "node":
        return (f"// Start the sidecar once:  python -m agentguard serve --policy policy.json --port 8787{sqlite_flag}\n"
                '// (optional: set AGENTGUARD_TOKEN and send "Authorization: Bearer <token>")\n'
                'const BASE = "http://127.0.0.1:8787";\n'
                "async function post(path, body) {\n"
                "  const r = await fetch(BASE + path, {method: \"POST\", headers: {\"Content-Type\": \"application/json\"},\n"
                "                                       body: JSON.stringify(body)});\n"
                "  return r.json();\n}\n\n"
                "// at the start of every user message:\n"
                "await post(\"/turn\", {session_id: sid, user_message: userMessage});\n\n"
                f"{ctx_note}"
                f"const args = {args_json};\n"
                f"const d = await post(\"/authorize\", {{session_id: sid, user, tool: {json.dumps(tool)}, args}});\n"
                "if (d.decision !== \"allow\") {\n"
                "  // \"deny\" or \"needs_approval\": do NOT run the tool; tell the user d.reason\n"
                "} else {\n"
                f"  const result = await runMyTool({json.dumps(tool)}, args);\n"
                f"  const safe = await post(\"/filter_result\", {{session_id: sid, user, tool: {json.dumps(tool)}, args, result}});\n"
                "  // give safe.result to the model, never the raw result\n}\n")
    body = json.dumps({"session_id": "s1", "user": {"id": "u1", "role": "ROLE"}, "tool": tool,
                       "args": {p: "..." for p in params}}, ensure_ascii=False)
    return (f"# Start the sidecar once:\n# python -m agentguard serve --policy policy.json --port 8787{sqlite_flag}\n\n"
            "curl -s -X POST http://127.0.0.1:8787/turn -H 'Content-Type: application/json' \\\n"
            "  -d '{\"session_id\": \"s1\", \"user_message\": \"hello\"}'\n\n"
            "curl -s -X POST http://127.0.0.1:8787/authorize -H 'Content-Type: application/json' \\\n"
            f"  -d '{body}'\n\n"
            "curl -s -X POST http://127.0.0.1:8787/filter_result -H 'Content-Type: application/json' \\\n"
            "  -d '{\"session_id\": \"s1\", \"user\": {\"id\": \"u1\", \"role\": \"ROLE\"}, "
            f"\"tool\": \"{tool}\", \"args\": {args_json}, \"result\": {{}}}}'\n"
            + (f"\n# facts without a lookup must be sent in the request as \"context\": {', '.join(resolver_needed(policy))}\n"
               if needs_resolver else ""))
