"""
copilot/heuristics.py -- ντετερμινιστική ανάλυση εργαλείων (χωρίς LLM).

Για κάθε εργαλείο προτείνει:
  risk               read | write | external | dangerous
  returns_untrusted  True αν επιστρέφει κείμενο γραμμένο από τρίτους (forum, μηνύματα, tickets, web...)
  sensitive_params   παράμετροι με ευαίσθητα ονόματα (password, iban, card...)
  sensitive_fields   ευαίσθητα πεδία που αναφέρει η περιγραφή ότι επιστρέφονται
και τον ΛΟΓΟ κάθε πρότασης (εξηγήσιμο). Είναι το «δάπεδο» του safety floor: το LLM δεν μπορεί να το χαλαρώσει.
"""
from __future__ import annotations

import re
import unicodedata

RISKS = ("read", "write", "external", "dangerous")

# --- λέξεις (EN) και ρίζες (EL, χωρίς τόνους) ------------------------------------------------------
_DANGEROUS_NAME = {"sql", "shell", "exec", "execute", "eval", "bash", "cmd", "sudo", "terminal", "command", "powershell"}
_DANGEROUS_DESC = re.compile(r"arbitrary (sql|command|code|query|shell)|raw sql|any sql|sql statement|shell command|"
                             r"execute (any|arbitrary)|τυχαι[οα] (sql|εντολ)|αυθαιρετ", re.I)
_FETCH_VERBS = {"fetch", "download", "curl", "browse", "scrape", "crawl", "request", "wget", "visit", "open"}
_URL_WORDS = {"url", "uri", "link", "endpoint", "webpage", "website", "web"}
_EXTERNAL = {"email", "mail", "sms", "notify", "notification", "webhook", "slack", "tweet", "send", "forward",
             "broadcast", "message", "dm", "call", "phone"}
_WRITE = {"create", "add", "insert", "update", "delete", "remove", "set", "grant", "revoke", "reset", "change", "edit",
          "modify", "enroll", "register", "post", "publish", "submit", "transfer", "pay", "close", "cancel", "approve",
          "reject", "grade", "assign", "write", "upload", "book", "prescribe", "rename", "move", "save", "store", "put",
          "patch", "merge", "invite", "ban", "block", "lock", "unlock", "reopen", "withdraw", "refund", "charge",
          "order", "buy", "sell", "borrow", "return", "checkout", "deploy", "destroy", "drop", "purge", "clear"}
_READ = {"get", "list", "read", "view", "show", "search", "find", "lookup", "describe", "count", "check", "fetch",
         "retrieve", "query", "browse", "display", "export", "inspect", "summarize", "summary", "explain", "preview",
         "history", "status", "info"}
_EL_STEMS = {
    "write": ("διαγραφ", "διεγραψ", "δημιουργ", "ενημερωσ", "αλλαξ", "προσθεσ", "αφαιρεσ", "υποβαλ", "μεταφερ",
              "κλεισ", "βαθμολογ", "δημοσιευσ", "εγγραψ", "ορισ", "επαναφερ", "εγκριν", "ακυρωσ"),
    "read": ("διαβασ", "δειξ", "λιστα", "αναζητ", "βρες", "προβολ", "εμφανισ", "ανακτησ", "περιγραψ"),
    "external": ("στειλ", "αποστολ", "ειδοποι", "προωθησ"),
    "dangerous": ("εκτελεσ", "εντολ"),
}

_UNTRUSTED = {"forum", "message", "messages", "msg", "ticket", "tickets", "comment", "comments", "review", "reviews",
              "memo", "note", "notes", "submission", "submissions", "announcement", "announcements", "material",
              "materials", "feedback", "chat", "inbox", "email", "emails", "mail", "post", "posts", "thread",
              "threads", "attachment", "attachments", "upload", "uploads", "web", "webpage", "page", "html",
              "url", "http", "assignment", "assignments", "attempt", "attempts", "answer", "answers", "question",
              "questions", "bio", "description", "remark", "remarks", "support"}
_UNTRUSTED_PHRASES = re.compile(r"written by (users?|students?|customers?|third|others|anyone)|user[- ]generated|"
                                r"free[- ]text|third[- ]part(y|ies)|από τρίτους|γραμμένο από|κείμενο (πελάτη|χρήστη)|"
                                r"untrusted|external content", re.I)
_UNTRUSTED_EL = ("φορουμ", "μηνυμ", "εισιτηρι", "σχολι", "ανακοινωσ", "υποβολ", "υλικ", "εργασι", "απαντησ")

_SENSITIVE = ("password", "passwd", "pwd", "iban", "card", "cvv", "cvc", "ssn", "amka", "token", "secret", "api_key",
              "apikey", "private_key", "credential", "salary", "diagnosis", "date_of_birth", "dob", "national_id",
              "id_card", "passport", "pin", "otp", "tax_id", "afm", "social_security", "insurance", "admin_notes")
_SENSITIVE_RE = re.compile(r"(?<![a-z])(" + "|".join(re.escape(s) for s in _SENSITIVE) + r")(?![a-z])")


def _norm(text: str) -> str:
    """Πεζά, χωρίς τόνους, ώστε οι ελληνικές ρίζες να ταιριάζουν ανεξάρτητα από τονισμό."""
    text = unicodedata.normalize("NFD", str(text))
    text = "".join(c for c in text if not unicodedata.combining(c))
    return text.casefold().replace("ς", "σ")


def _tokens(text: str) -> list[str]:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(text))   # camelCase -> camel Case
    return [t for t in re.split(r"[^0-9A-Za-zΑ-Ωα-ωάέήίόύώϊϋΐΰ]+", _norm(text)) if t]


def _stem_hit(tokens, kind):
    for t in tokens:
        for stem in _EL_STEMS[kind]:
            if _norm(t).startswith(stem):
                return t
    return None


def _first(items):
    return items[0] if items else None


# ---------------------------------------------------------------------------
# risk
# ---------------------------------------------------------------------------

def classify_risk(tool: dict) -> tuple[str, str]:
    name_toks = _tokens(tool.get("name", ""))
    desc = str(tool.get("description") or "")
    desc_toks = _tokens(desc)
    params = {p.lower() for p in (tool.get("params") or {})}
    method = (tool.get("http_method") or "").upper() or None

    hit = _first([t for t in name_toks if t in _DANGEROUS_NAME])
    if hit:
        return "dangerous", f"το όνομα περιέχει «{hit}» (εκτέλεση αυθαίρετου κώδικα/ερωτήματος)"
    if _DANGEROUS_DESC.search(desc):
        return "dangerous", "η περιγραφή αναφέρει αυθαίρετη εκτέλεση (SQL/εντολή/κώδικας)"
    if params & {"sql", "shell", "script", "code", "cmd", "command"}:
        return "dangerous", "δέχεται ως όρισμα ωμό SQL/εντολή/κώδικα"
    fetch = _first([t for t in name_toks if t in _FETCH_VERBS])
    if fetch and ((set(name_toks) & _URL_WORDS) or (params & {"url", "uri", "link", "endpoint"})):
        return "dangerous", f"«{fetch}» με αυθαίρετη διεύθυνση URL (SSRF / διαρροή δεδομένων)"
    if params & {"url", "uri"} and not (set(name_toks) & {"get", "list"}):
        return "dangerous", "δέχεται αυθαίρετη διεύθυνση URL"

    verb = name_toks[0] if name_toks else ""
    if _stem_hit([verb], "dangerous"):
        return "dangerous", "ρήμα εκτέλεσης εντολής στο όνομα"
    # 1) το πρώτο ρήμα του ονόματος αποφασίζει
    if verb in _EXTERNAL or _stem_hit([verb], "external"):
        return "external", f"το ρήμα «{verb}» στέλνει δεδομένα προς τα έξω"
    if verb in _WRITE or _stem_hit([verb], "write"):
        return "write", f"το ρήμα «{verb}» αλλάζει δεδομένα"
    if verb in _READ or _stem_hit([verb], "read"):
        return "read", f"το ρήμα «{verb}» διαβάζει δεδομένα"
    # 2) άλλες λέξεις του ονόματος
    for kind, vocab in (("external", _EXTERNAL), ("write", _WRITE), ("read", _READ)):
        hit = _first([t for t in name_toks if t in vocab])
        if hit:
            return kind, f"το όνομα περιέχει «{hit}»"
    # 3) το πρώτο ρήμα της περιγραφής
    dverb = desc_toks[0] if desc_toks else ""
    for kind, vocab in (("external", _EXTERNAL), ("write", _WRITE), ("read", _READ)):
        if dverb in vocab or _stem_hit([dverb], kind):
            return kind, f"η περιγραφή ξεκινά με «{dverb}»"
    # 4) μέθοδος HTTP
    if method == "GET":
        return "read", "μέθοδος HTTP GET (ανάγνωση)"
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return "write", f"μέθοδος HTTP {method}"
    # 5) άγνωστο: συντηρητικά write
    return "write", "δεν αναγνωρίστηκε ρήμα· θεωρείται write για ασφάλεια"


# ---------------------------------------------------------------------------
# untrusted και sensitive
# ---------------------------------------------------------------------------

def _returns_untrusted(tool: dict, risk: str) -> tuple[bool, str]:
    name_toks = _tokens(tool.get("name", ""))
    desc = str(tool.get("description") or "")
    desc_toks = _tokens(desc)
    method = (tool.get("http_method") or "").upper()
    fetch = _first([t for t in name_toks if t in _FETCH_VERBS | {"http", "url", "web", "browse"}])
    if fetch:
        return True, f"φέρνει περιεχόμενο από το διαδίκτυο («{fetch}»)"
    if risk in ("write", "external") and method != "GET":
        return False, "εργαλείο εγγραφής/αποστολής (δεν υποθέτουμε ότι επιστρέφει ξένο κείμενο)"
    m = _UNTRUSTED_PHRASES.search(desc)
    if m:
        return True, f"η περιγραφή λέει ότι το κείμενο γράφεται από τρίτους («{m.group(0)}»)"
    for t in name_toks + desc_toks:
        if t in _UNTRUSTED:
            return True, f"αναφέρει «{t}» (περιεχόμενο που γράφουν χρήστες/τρίτοι)"
        if any(_norm(t).startswith(s) for s in _UNTRUSTED_EL):
            return True, f"αναφέρει «{t}» (περιεχόμενο που γράφουν χρήστες/τρίτοι)"
    return False, "δεν βρέθηκε ένδειξη ξένου κειμένου"


def _sensitive_in(text: str) -> list[str]:
    norm = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(text)).lower()
    return sorted({m.group(1) for m in _SENSITIVE_RE.finditer(norm.replace("-", "_"))})


def _sensitive_idents(text: str) -> list[str]:
    """Πλήρη ονόματα πεδίων (π.χ. card_number) από την περιγραφή· λέξεις προτάσεων με κεφαλαίο αγνοούνται."""
    out = set()
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", str(text)):
        if ident[0].isupper() and ident.isalpha():
            continue  # π.χ. «Pin a post»: αρχή πρότασης, όχι όνομα πεδίου
        if _sensitive_in(ident):
            out.add(ident)
    return sorted(out)


def analyze_tool(tool: dict) -> dict:
    risk, risk_reason = classify_risk(tool)
    untrusted, untrusted_reason = _returns_untrusted(tool, risk)
    sparams = sorted(p for p in (tool.get("params") or {}) if _sensitive_in(p))
    sfields = [f for f in _sensitive_idents(tool.get("description", "")) if f not in sparams]
    reason_sensitive = ("ευαίσθητα ονόματα παραμέτρων: " + ", ".join(sparams) if sparams else "") + \
                       ("; " if sparams and sfields else "") + \
                       ("η περιγραφή αναφέρει ευαίσθητα πεδία: " + ", ".join(sfields) if sfields else "")
    return {"name": tool["name"], "risk": risk, "returns_untrusted": untrusted,
            "sensitive_params": sparams, "sensitive_fields": sfields,
            "reasons": {"risk": risk_reason, "untrusted": untrusted_reason,
                        "sensitive": reason_sensitive or "δεν βρέθηκαν ευαίσθητα ονόματα"}}


def analyze_tools(tools: list[dict]) -> dict:
    """{όνομα_εργαλείου: ανάλυση}."""
    return {t["name"]: analyze_tool(t) for t in tools}


def high_risk_names(analysis: dict) -> set:
    """Εργαλεία που το δάπεδο θεωρεί υψηλού ρίσκου (write, external, dangerous)."""
    return {n for n, a in analysis.items() if a["risk"] != "read"}


def untrusted_names(analysis: dict) -> set:
    return {n for n, a in analysis.items() if a["returns_untrusted"]}


def measure(analysis: dict, expected_high_risk, expected_untrusted) -> dict:
    """Recall και false positives απέναντι σε γνωστή «αλήθεια» (π.χ. οι λίστες του v1)."""
    hr, un = high_risk_names(analysis), untrusted_names(analysis)
    eh, eu = set(expected_high_risk), set(expected_untrusted)

    def part(found, expected):
        hit, miss, fp = sorted(found & expected), sorted(expected - found), sorted(found - expected)
        return {"expected": len(expected), "found": len(found), "true_positives": len(hit),
                "recall": round(len(hit) / len(expected), 3) if expected else None,
                "missed": miss, "false_positives": fp}
    return {"tools": len(analysis), "high_risk": part(hr, eh), "untrusted": part(un, eu)}


def measurement_report(eclass_tools, eclass_policy: dict, demobank_tools) -> dict:
    """Η μέτρηση που μπαίνει στο docs/GENERALIZATION.md (ξαναϋπολογίζεται από τεστ, άρα δεν «ξεφεύγει»).

    eClass: «αλήθεια» = οι λίστες HIGH_RISK/UNTRUSTED του v1 (όπως είναι στο app/eclass_policy.json).
    DemoBank: «αλήθεια» = ο πίνακας της ενότητας 6 του εγγράφου (write/external/dangerous και untrusted).
    """
    return {
        "eclass": measure(analyze_tools(eclass_tools), eclass_policy["high_risk_tools"], eclass_policy["untrusted_tools"]),
        "demobank": measure(analyze_tools(demobank_tools),
                            ["transfer_funds", "update_contact", "send_email", "close_account", "run_sql", "fetch_url"],
                            ["list_transactions", "read_support_ticket", "fetch_url"]),
        "note": "high_risk = write+external+dangerous. Τα false positives του eClass είναι εργαλεία που το v1 δεν "
                "βάζει στα HIGH_RISK (run_sql/fetch_url τα απαγορεύει η policy αλλιώς· post_forum, submit_assignment, "
                "submit_exercise είναι εγγραφές).",
    }
