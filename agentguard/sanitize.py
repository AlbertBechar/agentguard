"""Αντίγραφο του app/sanitize.py (v1) για ανεξαρτησία του πακέτου agentguard (μόνο standard library).
Αν αλλάξει το πρωτότυπο, το τεστ tests/test_ag_sanitize.py αποτυγχάνει μέχρι να ενημερωθεί το αντίγραφο.
"""
"""Sanitizer for untrusted text (written by other users: forum, messages, ...).

Step 1: sanitize_untrusted(text) -> (clean_text, findings)

It removes text that a human cannot see but an AI reads:
  - markdown comments   [//]: # (...)   and   [//]: <> (...)
  - HTML comments       <!-- ... -->
  - <script>...</script>
  - elements hidden with style="display:none" / visibility:hidden / hidden attr
  - zero-width (invisible) characters and control characters

It does NOT remove normal visible text.
Step 2: injection_score(text) -> float (0.0 .. 1.0), a simple heuristic.

Only the standard library is used.
"""
import re
import unicodedata

# Invisible characters: zero-width space/non-joiner/joiner, word joiner, BOM.
ZERO_WIDTH_CHARS = "​‌‍⁠﻿"
_ZERO_WIDTH_RE = re.compile("[" + ZERO_WIDTH_CHARS + "]+")

# Control characters, except \t (0x09), \n (0x0A) and \r (0x0D).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")

# A markdown "link reference definition" used as a comment, on its own line:
#   [//]: # (hidden)    [//]: <> (hidden)    [//]: # "hidden"    [//]: # 'hidden'
_MD_COMMENT_RE = re.compile(
    r"^[ \t]*\[//\]:[ \t]*(?:#|<>)[ \t]*(?:\(.*\)|\".*\"|'.*')[ \t]*(?:\r?\n|$)",
    re.MULTILINE,
)

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

_SCRIPT_RE = re.compile(r"<script\b.*?</script\s*>", re.IGNORECASE | re.DOTALL)

# The OPENING tag of a hidden element: <tag ... style="...display:none..." ...>
# (also visibility:hidden, and the plain "hidden" attribute).
_HIDDEN_OPEN_RE = re.compile(
    r"<(\w+)\b[^>]*?"
    r"(?:style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^\"']*[\"']"
    r"|\shidden(?=[\s=>/]))"
    r"[^>]*>",
    re.IGNORECASE,
)


def _strip_hidden_html(text: str, findings: list) -> str:
    """Remove hidden HTML elements, including nested elements of the same tag.

    We find the opening tag, then COUNT opening/closing tags of the same name
    to find the matching closing tag (so <div hidden><div>x</div> y</div> is
    removed completely). If there is no closing tag, the browser would hide
    everything until the end, so we remove until the end too.
    """
    while True:
        m = _HIDDEN_OPEN_RE.search(text)
        if not m:
            return text
        tag_re = re.compile(r"<(/?)%s\b[^>]*>" % re.escape(m.group(1)), re.IGNORECASE)
        depth = 1
        end = len(text)
        for t in tag_re.finditer(text, m.end()):
            depth += -1 if t.group(1) else 1
            if depth == 0:
                end = t.end()
                break
        findings.append(
            {"type": "hidden_html", "snippet": _snippet(text[m.start():end]), "score": SCORE_HIDDEN_HTML}
        )
        text = text[:m.start()] + text[end:]

# Scores: how suspicious is it that this thing was hidden? (0..1)
SCORE_MD_COMMENT = 0.7
SCORE_HTML_COMMENT = 0.6
SCORE_HIDDEN_HTML = 0.7
SCORE_SCRIPT = 0.8
SCORE_ZERO_WIDTH = 0.4

SNIPPET_MAX = 80


def _snippet(text: str) -> str:
    """First <= 80 characters of the removed text, on one line."""
    one_line = " ".join(text.split())
    return one_line[:SNIPPET_MAX]


def _strip_pattern(text: str, regex, ftype: str, score: float, findings: list) -> str:
    """Remove every match of `regex` from `text`, adding one finding per match."""

    def _replace(match):
        findings.append({"type": ftype, "snippet": _snippet(match.group(0)), "score": score})
        return ""

    return regex.sub(_replace, text)


def _describe_invisible(chars: str) -> str:
    """Human readable snippet for invisible chars, e.g. 'U+200B x3'."""
    parts = []
    for ch in sorted(set(chars)):
        parts.append("U+%04X x%d" % (ord(ch), chars.count(ch)))
    return ", ".join(parts)[:SNIPPET_MAX]


def sanitize_untrusted(text: str) -> tuple:
    """Return (clean_text, findings).

    findings = list of {"type": str, "snippet": str (<= 80 chars), "score": float}
    types: hidden_markdown_comment | html_comment | zero_width | hidden_html | script
    (control characters are reported as "zero_width" too: both are invisible).
    """
    if not isinstance(text, str) or not text:
        return text, []

    findings = []

    # 1. Invisible characters first, so they cannot be used to break the
    #    patterns below (e.g. "[/​/]: # (...)").
    invisible = "".join(_ZERO_WIDTH_RE.findall(text)) + "".join(_CONTROL_RE.findall(text))
    if invisible:
        findings.append(
            {"type": "zero_width", "snippet": _describe_invisible(invisible), "score": SCORE_ZERO_WIDTH}
        )
        text = _ZERO_WIDTH_RE.sub("", text)
        text = _CONTROL_RE.sub("", text)

    # 2. Hidden blocks. <script> and hidden elements before comments, so a
    #    comment inside them is not reported twice.
    text = _strip_pattern(text, _SCRIPT_RE, "script", SCORE_SCRIPT, findings)
    text = _strip_hidden_html(text, findings)
    text = _strip_pattern(text, _HTML_COMMENT_RE, "html_comment", SCORE_HTML_COMMENT, findings)
    text = _strip_pattern(text, _MD_COMMENT_RE, "hidden_markdown_comment", SCORE_MD_COMMENT, findings)

    return text, findings


# ---------------------------------------------------------------------------
# Step 2: injection_score
# ---------------------------------------------------------------------------
# Each entry = (regex, weight). Patterns are written in lowercase and WITHOUT
# Greek accents, because the text is normalized the same way before matching
# (see _normalize). Strong phrases get a high weight, weak ones a low weight,
# so one innocent word (e.g. "system prompt") alone stays under 0.3.
_INJECTION_PATTERNS = [
    # --- English ---
    (r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(of\s+)?(the\s+|your\s+|my\s+)?"
     r"(previous|prior|above|earlier|preceding)\s+(instructions?|rules?|prompts?|directions?)", 0.7),
    (r"\b(forget|ignore)\s+(all\s+)?your\s+(instructions?|rules?)", 0.7),
    (r"\byou\s+are\s+now\b", 0.25),
    (r"\bsystem\s+prompt\b", 0.25),
    (r"\b(reveal|print|show|output|repeat)\s+(me\s+)?(the\s+|your\s+)?(system\s+prompt|instructions)", 0.4),
    (r"\bas\s+the\s+(teacher|professor|admin|administrator|system)\b", 0.25),
    (r"\b(do\s+not|don'?t)\s+tell\s+(the\s+|any\s+)?(user|student|teacher|admin|anyone|anybody)", 0.6),
    (r"\bset\s+(all|every|everyone'?s?)\s+(the\s+|of\s+the\s+)?(final\s+)?grades?\b", 0.6),
    (r"\bset\s+(the\s+)?(final\s+)?grades?\s+(to|=)", 0.5),
    (r"\bsend\b[^\n]{0,80}\bto\b[^\n]{0,40}\S+@\S+", 0.6),
    (r"\b(developer|dan|jailbreak|god)\s+mode\b|\bjailbreak\b", 0.4),
    (r"\b(dear|hey|attention|hello)[ ,]+(ai|assistant|athena|chatbot|bot)\b", 0.4),
    (r"\b(run_sql|fetch_url|set_final_grade|set_component_grade|grade_submission|"
     r"reset_password|update_user|delete_user|send_message)\b", 0.4),
    (r"!\[[^\]]*\]\(\s*https?://", 0.35),          # markdown image to an external URL
    # --- Greek (no accents, lowercase) ---
    (r"(αγνοησ\w*|ξεχασ\w*|παραβλεψ\w*)\s+(ολες\s+)?(τις\s+)?(προηγουμενες|παλιες|υπολοιπες|ολες)?\s*"
     r"(οδηγιες|εντολες|κανονες)", 0.7),
    (r"\bεισαι\s+τωρα\b", 0.25),
    (r"\bβαλε\s+σε\s+ολους\b", 0.6),
    (r"(αλλαξε|διορθωσε|θεσε)\s+(ολους\s+)?τους\s+βαθμους", 0.5),
    (r"\bμην\s+(το\s+)?πεις\s+(στον|στην|σε|του|της)\s+(χρηστη|φοιτητη|καθηγητη|κανεναν|κανενα)", 0.6),
    (r"\bστειλε\s+(μου\s+)?τα\s+στοιχεια", 0.5),
    (r"\bστειλε\b[^\n]{0,80}\S+@\S+", 0.6),
    (r"\bως\s+(καθηγητης|διαχειριστης|admin)\b", 0.25),
    (r"\bπροτροπη\s+συστηματος\b|\bοδηγιες\s+συστηματος\b", 0.25),
]
_COMPILED_PATTERNS = [(re.compile(p), w) for p, w in _INJECTION_PATTERNS]


def _normalize(text: str) -> str:
    """Make text easier to match: lowercase, no accents, no invisible chars.

    "Αγνόησε" -> "αγνοησε",  "IGNORE" -> "ignore",  "ig<ZWSP>nore" -> "ignore".
    """
    text = _ZERO_WIDTH_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    text = unicodedata.normalize("NFKD", text.casefold())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    # casefold() turns the Greek final sigma (ς) into σ, so "τις" became "τισ".
    # Put ς back at the end of words, so our patterns ("τις", "οδηγιες") match.
    return re.sub(r"σ\b", "ς", text)


def injection_score(text: str) -> float:
    """How much does `text` look like a prompt injection? 0.0 (no) .. 1.0 (very).

    Sum of the weights of the DIFFERENT patterns found, capped at 1.0.
    This is only a hint for audit/UI. It is NOT a defense on its own:
    an attacker can rephrase and avoid every pattern.
    """
    if not isinstance(text, str) or not text:
        return 0.0
    normalized = _normalize(text)
    total = sum(weight for regex, weight in _COMPILED_PATTERNS if regex.search(normalized))
    return round(min(1.0, total), 2)


# ---------------------------------------------------------------------------
# Step 3: wrap_untrusted and sanitize_result
# ---------------------------------------------------------------------------
WRAP_MIN_LENGTH = 40      # only strings LONGER than this get wrapped (ids, names, dates stay as they are)
MAX_DEPTH = 20            # protection against absurdly deep results

# Any "<<UNTRUSTED_DATA" / "<<END_UNTRUSTED_DATA" typed by an attacker (any case, extra spaces).
_FAKE_MARKER_RE = re.compile(r"<<(\s*/?\s*(?:END_)?UNTRUSTED_DATA)", re.IGNORECASE)


def _neutralize_markers(text: str) -> str:
    """Break fake markers inside the text: '<<END_UNTRUSTED_DATA>>' -> '[[END_UNTRUSTED_DATA>>'."""
    return _FAKE_MARKER_RE.sub(r"[[\1", text)


def wrap_untrusted(text: str, source: str) -> str:
    """Wrap text in an 'UNTRUSTED DATA' envelope, so the AI treats it as data, not instructions."""
    safe_source = re.sub(r"[^A-Za-z0-9_.-]", "", str(source))[:40] or "unknown"
    body = _neutralize_markers(text if isinstance(text, str) else str(text))
    return "<<UNTRUSTED_DATA source=%s>>\n%s\n<<END_UNTRUSTED_DATA>>" % (safe_source, body)


def _sanitize_value(value, source: str, findings: list, scores: list, depth: int):
    """Recursively sanitize every string inside dicts / lists / tuples. Never raises."""
    if depth > MAX_DEPTH:
        return value
    try:
        if isinstance(value, str):
            clean, found = sanitize_untrusted(value)
            findings.extend(found)
            # score the ORIGINAL text: the hidden part is exactly what we want to rate
            scores.append(injection_score(value))
            scores.extend(f["score"] for f in found)
            if len(clean) > WRAP_MIN_LENGTH:
                clean = wrap_untrusted(clean, source)
            return clean
        if isinstance(value, dict):
            return {k: _sanitize_value(v, source, findings, scores, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [_sanitize_value(v, source, findings, scores, depth + 1) for v in value]
        if isinstance(value, tuple):
            return tuple(_sanitize_value(v, source, findings, scores, depth + 1) for v in value)
    except Exception:
        # unknown shape or unexpected error: leave this value as it is
        return value
    return value   # numbers, None, booleans, other types: unchanged


def sanitize_result(tool: str, result, source: str) -> tuple:
    """Sanitize a whole tool result. Returns (new_result, findings, max_score).

    - every string: hidden text removed (sanitize_untrusted) and rated (injection_score)
    - only strings longer than 40 chars are wrapped (so ids / names / dates stay intact)
    - the original `result` is not modified
    """
    findings = []
    scores = []
    new_result = _sanitize_value(result, source, findings, scores, 0)
    return new_result, findings, max(scores) if scores else 0.0
