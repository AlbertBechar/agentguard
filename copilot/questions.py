"""
copilot/questions.py -- οι ερωτήσεις διευκρίνισης (≤ 8, με ασφαλές default) και η μετατροπή των απαντήσεων
σε «αποφάσεις» που διαβάζει το safety floor.

Οι ντετερμινιστικές ερωτήσεις παράγονται πάντα. Αν υπάρχει LLM, συμπληρώνει τις υπόλοιπες θέσεις (χωρίς διπλότυπα).
Κάθε ερώτηση: {"id","key","tool"?,"text","why","options":[...],"default"}.
"""
from __future__ import annotations

import re

from . import prompts
from .llm import LLMError

MAX_QUESTIONS = 8

_TEXTS = {
    "el": {
        "roles": ("Ποιοι ρόλοι χρηστών υπάρχουν στην εφαρμογή σας;", "Η πολιτική δίνει δικαιώματα ανά ρόλο.",
                  "user, admin"),
        "allow": ("Επιτρέπεται το εργαλείο «{tool}» ({risk}) σε κάποιον ρόλο;",
                  "Είναι {why}. Από προεπιλογή απαγορεύεται σε όλους."),
        "opt_role": "Ο ρόλος «{role}»", "only_roles": "Μόνο οι ρόλοι: {roles}",
        "opt_none": "Όχι, σε κανέναν", "opt_priv": "Μόνο στον πιο προνομιούχο ρόλο (π.χ. admin)",
        "opt_all": "Ναι, σε όλους τους ρόλους",
        "more": ("Πώς να αντιμετωπιστούν τα εργαλεία: {tools};", "Είναι επικίνδυνα ή στέλνουν δεδομένα προς τα έξω."),
        "sensitive": ("Ποια πεδία είναι ευαίσθητα και πρέπει να κρύβονται από όσους δεν δικαιούνται να τα δουν;",
                      "Προτείνονται από τα ονόματα και τις περιγραφές των εργαλείων. Μόνο όσα επιλέξετε κρύβονται."),
        "opt_sens_none": "Κανένα",
        "owner": ("Πώς καθορίζεται ο ιδιοκτήτης μιας εγγραφής (π.χ. ποιου πελάτη είναι ένας λογαριασμός);",
                  "Από αυτό εξαρτάται ποιος βλέπει ή αλλάζει ποιανού τα δεδομένα."),
        "opt_owner_none": "Δεν υπάρχει ιδιοκτησία / δεν ξέρω (μόνο ρόλοι)",
        "unconditional": ("Τα εργαλεία που αλλάζουν δεδομένα ({tools}) επιτρέπεται να τα καλεί κάποιος ρόλος χωρίς "
                          "επιπλέον έλεγχο (ιδιοκτησίας ή ορίου);",
                          "Αν όχι, κάθε επιτρεπτή κλήση πρέπει να έχει συνθήκη και το πρόχειρο δεν εγκρίνεται "
                          "μέχρι να προστεθεί."),
        "opt_unc_none": "Όχι, κάθε κλήση να έχει συνθήκη (πιο ασφαλές)",
        "opt_unc_priv": "Μόνο ο πιο προνομιούχος ρόλος, χωρίς συνθήκη",
        "opt_unc_all": "Ναι, όπως ορίζουν οι απαιτήσεις",
        "risk_words": {"dangerous": "επικίνδυνο", "external": "εξωτερικό"},
        "why_words": {"dangerous": "εκτέλεση αυθαίρετου κώδικα ή πρόσβαση σε αυθαίρετη διεύθυνση",
                      "external": "αποστολή δεδομένων προς τρίτους"},
    },
    "en": {
        "roles": ("Which user roles exist in your application?", "The policy grants permissions per role.", "user, admin"),
        "allow": ("May any role call the tool '{tool}' ({risk})?", "It is {why}. By default it is denied to everyone."),
        "opt_role": "The role '{role}'", "only_roles": "Only these roles: {roles}",
        "opt_none": "No, nobody", "opt_priv": "Only the most privileged role (e.g. admin)", "opt_all": "Yes, all roles",
        "more": ("How should these tools be treated: {tools}?", "They are dangerous or send data outside."),
        "sensitive": ("Which fields are sensitive and must be hidden from anyone not entitled to see them?",
                      "Suggested from tool names and descriptions. Only the ones you select are hidden."),
        "opt_sens_none": "None",
        "owner": ("How is the owner of a record decided (e.g. whose customer an account is)?",
                  "It decides who may see or change whose data."),
        "opt_owner_none": "No ownership / I don't know (roles only)",
        "unconditional": ("May a role call the data-changing tools ({tools}) without an extra ownership or limit check?",
                          "If not, every allowed call needs a condition and the draft cannot be approved until one exists."),
        "opt_unc_none": "No, every call needs a condition (safer)",
        "opt_unc_priv": "Only the most privileged role, without a condition",
        "opt_unc_all": "Yes, as the requirements say",
        "risk_words": {"dangerous": "dangerous", "external": "external"},
        "why_words": {"dangerous": "arbitrary code execution or access to arbitrary URLs", "external": "sending data to third parties"},
    },
}


def _t(lang: str) -> dict:
    return _TEXTS.get(lang, _TEXTS["el"])


def _norm(text: str) -> str:
    return re.sub(r"\W+", " ", str(text).casefold()).strip()


def _allow_options(t: dict, roles) -> tuple[list[str], dict]:
    """Επιλογές της ερώτησης «ποιοι ρόλοι επιτρέπονται»: τα 3 κλασικά + ΕΝΑ κουτί ανά ρόλο (πολλαπλή επιλογή).

    Οι πρώτες 3 θέσεις μένουν σταθερές (none / privileged / all)· οι ρόλοι έρχονται μετά, ώστε να λέγονται ΟΝΟΜΑΤΙΣΤΙΚΑ
    (π.χ. «teller» ΚΑΙ «admin»). Επιστρέφει (options, {κείμενο_επιλογής: ρόλος}).
    """
    role_opts = {t["opt_role"].format(role=r): r for r in (roles or [])}
    return [t["opt_none"], t["opt_priv"], t["opt_all"], *role_opts], role_opts


def build_deterministic(intake: dict, analysis: dict) -> list[dict]:
    t = _t(intake.get("language", "el"))
    qs: list[dict] = []
    if not intake.get("roles"):
        text, why, default = t["roles"]
        qs.append({"id": "", "key": "roles", "text": text, "why": why, "options": [], "default": default})

    allow_opts, role_opts = _allow_options(t, intake.get("roles"))
    risky = [n for n, a in analysis.items() if a["risk"] in ("dangerous", "external")]
    risky.sort(key=lambda n: (analysis[n]["risk"] != "dangerous", n))   # πρώτα τα επικίνδυνα
    for name in risky:
        risk = analysis[name]["risk"]
        qs.append({"id": "", "key": "allow_tool", "tool": name,
                   "text": t["allow"][0].format(tool=name, risk=t["risk_words"][risk]),
                   "why": t["allow"][1].format(why=t["why_words"][risk]),
                   "options": list(allow_opts), "role_options": dict(role_opts), "multi": True, "default": t["opt_none"]})

    sens = sorted({f for a in analysis.values() for f in a["sensitive_params"] + a["sensitive_fields"]})
    if sens:
        qs.append({"id": "", "key": "sensitive", "text": t["sensitive"][0], "why": t["sensitive"][1],
                   "options": sens + [t["opt_sens_none"]], "default": ", ".join(sens), "multi": True})

    id_tools = [x for x in intake["tools"] if analysis[x["name"]]["risk"] != "dangerous"
                and any(p.lower().endswith("_id") or p.lower() in ("id", "account", "ticket") for p in x["params"])]
    schema_cols = intake.get("owner_columns") or []
    if id_tools or schema_cols:
        opts = list(schema_cols) or sorted(intake.get("context_attributes") or {})
        qs.append({"id": "", "key": "owner", "text": t["owner"][0], "why": t["owner"][1],
                   "options": opts + [t["opt_owner_none"]], "default": opts[0] if opts else t["opt_owner_none"]})

    writes = [n for n, a in analysis.items() if a["risk"] == "write"]
    if writes:
        shown = ", ".join(writes[:6]) + ("…" if len(writes) > 6 else "")
        qs.append({"id": "", "key": "unconditional", "text": t["unconditional"][0].format(tools=shown),
                   "why": t["unconditional"][1],
                   "options": [t["opt_unc_none"], t["opt_unc_priv"], t["opt_unc_all"]], "default": t["opt_unc_none"]})
    return qs


def _cap(qs: list[dict], limit: int, lang: str, roles=None) -> list[dict]:
    """Αν οι ντετερμινιστικές ξεπερνούν το όριο, οι τελευταίες allow_tool συγχωνεύονται σε μία."""
    if len(qs) <= limit:
        return qs
    t = _t(lang)
    allow = [q for q in qs if q["key"] == "allow_tool"]
    others = [q for q in qs if q["key"] != "allow_tool"]
    keep = max(limit - len(others) - 1, 0)
    extra = allow[keep:]
    extra_names = {q["tool"] for q in extra}
    options, role_opts = _allow_options(t, roles)
    merged = {"id": "", "key": "allow_tools_more", "tools": [q["tool"] for q in extra],
              "text": t["more"][0].format(tools=", ".join(q["tool"] for q in extra)), "why": t["more"][1],
              "options": options, "role_options": role_opts, "multi": True, "default": t["opt_none"]}
    out, added = [], False
    for q in qs:                       # κρατάμε τη σειρά· οι «περισσευούμενες» γίνονται μία ερώτηση
        if q["key"] == "allow_tool" and q["tool"] in extra_names:
            if not added:
                out.append(merged)
                added = True
            continue
        out.append(q)
    return out[:limit]


def _clean_llm_question(raw, lang: str) -> dict | None:
    if not isinstance(raw, dict) or not str(raw.get("text") or "").strip():
        return None
    options = [str(o) for o in raw.get("options") or [] if str(o).strip()]
    default = raw.get("default")
    strictest = {"el": "Όχι / το πιο αυστηρό", "en": "No / the strictest"}.get(lang, "No / the strictest")
    if options:
        if default not in options:             # δεν υπάρχει ασφαλές default => προσθέτουμε την αυστηρή επιλογή
            options.append(strictest)
            default = strictest
    elif not str(default or "").strip():
        default = strictest
    return {"id": "", "key": "llm", "text": str(raw["text"]).strip(), "why": str(raw.get("why") or ""),
            "options": options, "default": str(default)}


def build_questions(intake: dict, analysis: dict, llm=None) -> list[dict]:
    """Έως 8 ερωτήσεις: πρώτα οι ντετερμινιστικές, μετά (αν υπάρχει LLM) οι δικές του, χωρίς διπλότυπα."""
    lang = intake.get("language", "el")
    qs = _cap(build_deterministic(intake, analysis), MAX_QUESTIONS, lang, intake.get("roles"))
    room = MAX_QUESTIONS - len(qs)
    if llm is not None and room > 0:
        try:
            data = llm.complete_json(prompts.QUESTIONS_SYSTEM,
                                     prompts.questions_user(intake, analysis, room, [q["text"] for q in qs]))
            seen = {_norm(q["text"]) for q in qs}
            for raw in (data.get("questions") or [])[:room * 2]:
                q = _clean_llm_question(raw, lang)
                if q and _norm(q["text"]) not in seen and room > 0:
                    seen.add(_norm(q["text"]))
                    qs.append(q)
                    room -= 1
        except (LLMError, AttributeError, TypeError):
            pass  # χωρίς LLM δουλεύουμε με τις ντετερμινιστικές
    qs = qs[:MAX_QUESTIONS]
    for i, q in enumerate(qs, 1):
        q["id"] = f"q{i}"
    return qs


# ---------------------------------------------------------------------------
# Απαντήσεις -> αποφάσεις
# ---------------------------------------------------------------------------

_NO = {"no", "none", "nobody", "όχι", "οχι", "κανένα", "κανενα", "κανέναν", "κανεναν", "n"}
_PRIV = {"privileged", "admin", "admins", "μόνο admin", "μονο admin"}
_ALL = {"all", "yes", "ναι", "σε όλους", "σε ολους", "everyone", "y"}


def _level(answer, options_codes: dict, default: str) -> str:
    """Μετατρέπει απάντηση σε 'none' | 'privileged' | 'all'. Ό,τι δεν αναγνωρίζεται => το πιο αυστηρό."""
    if answer is None:
        return default
    text = str(answer).strip()
    if text in options_codes:
        return options_codes[text]
    n = text.casefold()
    if n in _NO:
        return "none"
    if n in _PRIV:
        return "privileged"
    if n in _ALL:
        return "all"
    return "none"


def parse_access(raw, question: dict, t: dict, known_roles: list[str]) -> tuple[str, list[str]]:
    """Απάντηση του ανθρώπου -> (επίπεδο, ρόλοι). Επίπεδο: 'none' | 'privileged' | 'all'.

    Δέχεται ΠΟΛΛΑΠΛΕΣ επιλογές (λίστα) ή ελεύθερο κείμενο («teller, admin»). Αν επιλεγούν ρόλοι ονομαστικά, το επίπεδο είναι
    'privileged' με τη λίστα ρόλων (ή 'all' αν επιλέχθηκαν όλοι). Αναγνωρίζεται μόνο ό,τι υπάρχει στους γνωστούς ρόλους·
    «σε κανέναν» ή απάντηση που δεν αναγνωρίζεται => 'none' (το πιο αυστηρό).
    """
    codes_by_text = {t["opt_none"]: "none", t["opt_priv"]: "privileged", t["opt_all"]: "all"}
    role_by_text = dict(question.get("role_options") or {})
    by_name = {r.casefold(): r for r in known_roles}
    tokens = list(raw) if isinstance(raw, (list, tuple)) else ([raw] if str(raw) in codes_by_text or str(raw) in role_by_text
                                                                 else re.split(r"[,;\n]+", str(raw)))
    codes, roles = set(), []
    for tok in tokens:
        tok = str(tok).strip()
        if tok in codes_by_text:
            codes.add(codes_by_text[tok])
        elif tok in role_by_text:
            roles.append(role_by_text[tok])
        elif tok.strip("«»'\" ").casefold() in by_name:
            roles.append(by_name[tok.strip("«»'\" ").casefold()])
        elif tok.casefold() in _NO:
            codes.add("none")
        elif tok.casefold() in _ALL:
            codes.add("all")
        elif tok.casefold() in _PRIV:
            codes.add("privileged")
    roles = list(dict.fromkeys(roles))
    if "none" in codes or not (codes or roles):
        return "none", []                                   # αντίφαση ή άγνωστη απάντηση => το πιο αυστηρό
    if roles:
        return ("all" if known_roles and set(known_roles) <= set(roles) else "privileged"), roles
    return ("all" if "all" in codes else "privileged"), []


def decisions_from_answers(questions: list[dict], answers: dict, intake: dict) -> dict:
    """Δομημένες αποφάσεις (JSON-serializable) από τις απαντήσεις· οι αναπάντητες παίρνουν το ασφαλές default."""
    t = _t(intake.get("language", "el"))
    allow_codes = {t["opt_none"]: "none", t["opt_priv"]: "privileged", t["opt_all"]: "all"}
    unc_codes = {t["opt_unc_none"]: "none", t["opt_unc_priv"]: "privileged", t["opt_unc_all"]: "all"}
    dec = {"roles": list(intake.get("roles") or []), "tool_access": {}, "tool_roles": {}, "sensitive_fields": None,
           "owner": None, "unconditional": "none", "confirmed_open": [], "qa": []}
    for q in questions:
        raw = answers.get(q["id"], q["default"])
        dec["qa"].append({"id": q["id"], "text": q["text"], "answer": raw if isinstance(raw, str) else ", ".join(map(str, raw)),
                          "answered": q["id"] in answers})
        key = q["key"]
        if key == "roles" and not dec["roles"]:
            items = raw if isinstance(raw, list) else re.split(r"[,;\n]+", str(raw))
            dec["roles"] = [r.strip() for r in items if r.strip()]
        elif key in ("allow_tool", "allow_tools_more"):
            level, roles = parse_access(raw, q, t, dec["roles"])
            for name in ([q["tool"]] if key == "allow_tool" else q["tools"]):
                dec["tool_access"][name] = level
                if roles and level == "privileged":
                    dec["tool_roles"][name] = list(roles)
            if roles:                                        # ό,τι βλέπει το LLM/review: ονομαστικά οι ρόλοι που επέλεξε ο άνθρωπος
                dec["qa"][-1]["answer"] = t["only_roles"].format(roles=", ".join(roles)) if level == "privileged" else dec["qa"][-1]["answer"]
        elif key == "sensitive":
            items = raw if isinstance(raw, list) else re.split(r"[,;\n]+", str(raw))
            dec["sensitive_fields"] = [s.strip() for s in items if s.strip() and s.strip() != t["opt_sens_none"]]
        elif key == "owner":
            dec["owner"] = None if str(raw) == t["opt_owner_none"] else str(raw)
        elif key == "unconditional":
            dec["unconditional"] = _level(raw, unc_codes, "none")
    return dec


def confirmed_open_tools(decisions: dict, analysis: dict) -> set:
    """Εργαλεία για τα οποία ο άνθρωπος επιβεβαίωσε ρητά ότι ανοίγουν χωρίς επιπλέον συνθήκη."""
    open_tools = {n for n, level in decisions["tool_access"].items() if level in ("privileged", "all")}
    if decisions["unconditional"] in ("privileged", "all"):
        open_tools |= {n for n, a in analysis.items() if a["risk"] == "write"}
    return open_tools
