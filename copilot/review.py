"""
copilot/review.py -- το review στα απλά ελληνικά (markdown) που διαβάζει ο άνθρωπος πριν υπογράψει.

Περιέχει: (1) πίνακα εργαλείο × ρόλος, (2) τι θεωρήσαμε, (3) τι άλλαξε το safety floor, (4) προβλήματα,
(5) σενάρια που διαφωνούν, (6) κάθε lookup (SQL), (7) ερωτήσεις πριν την υπογραφή. Τα emoji επιτρέπονται εδώ (αρχείο .md).
"""
from __future__ import annotations

from .contract import _meta_entry, resolver_needed

BANNER = "⚠️ **Πρόχειρο από AI — ελέγξτε πριν εγκρίνετε.** Μόνο ο άνθρωπος που υπογράφει το εγκρίνει· το AI δεν αποφασίζει ποτέ την ώρα που τρέχει ο agent."


def _cell(text: str) -> str:
    return str(text).replace("|", "/").replace("\n", " ").strip()


def _matches(rule: dict, tool: str, role: str) -> bool:
    return ("*" in rule.get("tools", []) or tool in rule.get("tools", [])) and \
           ("*" in rule.get("roles", ["*"]) or role in rule.get("roles", ["*"]))


def _reasons(policy: dict, tool: str, role: str, effect: str, with_when: bool) -> list[str]:
    out = []
    for r in policy.get("rules", []):
        if isinstance(r, dict) and r.get("effect") == effect and _matches(r, tool, role) and bool(r.get("when")) == with_when:
            out.append(str(r.get("reason") or r.get("id")))
    return out


def matrix_table(policy: dict, matrix: dict) -> str:
    roles = list(policy.get("roles", []))
    lines = ["| Εργαλείο | " + " | ".join(roles) + " |", "|---|" + "---|" * len(roles)]
    for tool in sorted(matrix):
        cells = []
        for role in roles:
            label = matrix[tool].get(role, "deny")
            exceptions = _reasons(policy, tool, role, "deny", True)
            if label == "allow":
                cell = "✅ επιτρέπεται" + (f" (εξαιρέσεις: {'; '.join(exceptions)})" if exceptions else "")
            elif label == "conditional":
                why = _reasons(policy, tool, role, "allow", True)
                cell = "⚠️ υπό συνθήκη: " + ("; ".join(why) if why else "δείτε τους κανόνες")
            else:
                cell = "🔒 απαγορεύεται"
            cells.append(_cell(cell))
        lines.append(f"| `{tool}` | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _questions(policy: dict, matrix: dict, issues: list[dict], report: dict | None) -> list[str]:
    qs = ["Ο πίνακας της ενότητας 1 ταιριάζει με το πώς θέλετε να δουλεύει η εταιρία σας (κάθε εργαλείο, κάθε ρόλος);"]
    conditional = sorted({t for t, per in matrix.items() if "conditional" in per.values()})
    if conditional:
        qs.append("Οι συνθήκες των κελιών ⚠️ (π.χ. ιδιοκτησία, όρια) είναι σωστές για: " + ", ".join(f"`{t}`" for t in conditional[:6]) + ";")
    if policy.get("lookups"):
        qs.append("Διαβάσατε το SQL κάθε lookup (ενότητα 6) και ταιριάζει με το πραγματικό σχήμα της βάσης σας;")
    needed = resolver_needed(policy)
    if needed:
        qs.append("Ποιος θα υλοποιήσει τα γεγονότα που δεν έχουν lookup: " + ", ".join(f"`{n}`" for n in needed) + ";")
    confirmed = sorted({i["tool"] for i in issues if i.get("code") == "probe.confirmed" and i.get("tool")})
    if confirmed:
        qs.append("Επιβεβαιώνετε ότι αυτά τα εργαλεία υψηλού ρίσκου επιτρέπονται ΧΩΡΙΣ επιπλέον συνθήκη: " + ", ".join(f"`{t}`" for t in confirmed) + ";")
    if report and report.get("failed"):
        qs.append(f"Για τα {len(report['failed'])} σενάρια που διαφωνούν (ενότητα 5): ποιο είναι σωστό, το σενάριο ή η πολιτική;")
    for filler in ("Λείπει κάποιο ευαίσθητο πεδίο που πρέπει να κρύβεται από όσους δεν δικαιούνται να το δουν;",
                   "Είναι σωστοί και πλήρεις οι ρόλοι χρηστών;"):
        if len(qs) < 3:
            qs.append(filler)
    return qs[:5]


def review_md(intake: dict, policy: dict, matrix: dict, issues: list[dict], decisions: dict,
              scenarios_report: dict | None = None, assumptions=None, open_questions=None,
              source: str = "llm", model: str = "") -> str:
    out = [f"# Review πολιτικής ασφαλείας — {_cell(intake.get('company', ''))}", "", BANNER, "",
           f"*Πηγή πρόχειρου: {'LLM (' + model + ')' if source == 'llm' else 'offline πολιτική από heuristics (χωρίς LLM)'}.*", ""]

    out += ["## 1. Τι επιτρέπεται (εργαλείο × ρόλος)", "",
            "✅ επιτρέπεται · 🔒 απαγορεύεται · ⚠️ υπό συνθήκη (π.χ. μόνο ο ιδιοκτήτης, μέχρι ένα όριο)", "",
            matrix_table(policy, matrix) if matrix else "_Δεν υπάρχει πίνακας: η πολιτική έχει σφάλματα (ενότητα 4)._", ""]

    out += ["## 2. Τι θεωρήσαμε (παραδοχές και απαντήσεις)", ""]
    for qa in decisions.get("qa", []):
        out.append(f"- **{_cell(qa['text'])}** → {_cell(qa['answer'])}" + ("" if qa.get("answered") else " _(προεπιλογή, δεν απαντήθηκε)_"))
    for a in assumptions or []:
        out.append(f"- Παραδοχή του AI: {_cell(a)}")
    for q in open_questions or []:
        out.append(f"- Ανοιχτή ερώτηση του AI: {_cell(q)}")
    if not decisions.get("qa") and not assumptions:
        out.append("- _Καμία._")
    out.append("")

    changes = [i for i in issues if i["code"].startswith(("floor.", "probe.")) and i["code"] != "floor.ctx_requested"]
    out += ["## 3. Τι άλλαξε το safety floor", "",
            "Το safety floor μόνο **σφίγγει**: κλείνει ό,τι έμεινε ανοιχτό, ποτέ δεν χαλαρώνει κάτι.", ""]
    out += [f"- {_cell(i['message'])}" for i in changes] or ["- _Καμία αλλαγή._"]
    out.append("")

    out += ["## 4. Προβλήματα και προειδοποιήσεις", ""]
    errors = [i for i in issues if i["level"] == "error"]
    warnings = [i for i in issues if i["level"] == "warning"]
    for i in errors:
        out.append(f"- ❌ **ΣΦΑΛΜΑ (μπλοκάρει την έγκριση):** {_cell(i['message'])}")
    for i in warnings:
        out.append(f"- ⚠️ {_cell(i['message'])}")
    if not errors and not warnings:
        out.append("- _Κανένα._")
    out.append("")

    out += ["## 5. Σενάρια που διαφωνούν — αποφασίζει ο άνθρωπος", ""]
    if not scenarios_report:
        out.append("_Δεν έτρεξαν σενάρια._")
    else:
        out.append(f"Πέρασαν {scenarios_report['passed']} από {scenarios_report['total']}.")
        for f in scenarios_report.get("failed", []):
            out.append(f"- **{f['id']}** ({f.get('source', '')}): {_cell(f['text'])} — {_cell(f['reason'])}. "
                       "_Διαφωνία: μπορεί να είναι λάθος το σενάριο ή η πολιτική._")
    out.append("")

    out += ["## 6. Lookups (SQL που τρέχει στη βάση σας)", ""]
    lookups = policy.get("lookups") if isinstance(policy.get("lookups"), dict) else {}
    if not lookups:
        out.append("_Η πολιτική δεν έχει lookups._")
    for name, lk in lookups.items():
        lk = lk if isinstance(lk, dict) else {}
        desc, _ = _meta_entry(policy, name)
        out += [f"### `{name}`", f"{_cell(lk.get('description') or desc or '(χωρίς περιγραφή)')}", "",
                "```sql", str(lk.get("sql", "")).replace("```", "'''"), "```",
                f"Παράμετροι: `{lk.get('params', {})}` · επιστρέφει: `{lk.get('returns')}`. "
                "**Τρέχει μόνο ανάγνωση στη βάση σου.**", ""]
    out += ["## 7. Ερωτήσεις πριν υπογράψετε", ""]
    out += [f"{n}. {q}" for n, q in enumerate(_questions(policy, matrix, issues, scenarios_report), 1)]
    out.append("")
    return "\n".join(out)
