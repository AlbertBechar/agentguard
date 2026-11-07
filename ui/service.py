"""
ui/service.py -- η λογική του web UI, ΧΩΡΙΣ FastAPI (τεστάρεται μόνη της· το ui/server.py την καλεί).

Αρχές:
* Κάθε σφάλμα προς τον χρήστη είναι UIError με ελληνικό μήνυμα και σταθερό κωδικό (ποτέ stack trace).
* Το κλειδί AI_STUDIO_API_KEY διαβάζεται ΜΟΝΟ από το περιβάλλον (μέσω copilot.llm) και δεν εμφανίζεται πουθενά·
  κάθε κείμενο σφάλματος περνά από scrub().
* Τα εργαλεία από τον browser είναι ΜΗ ΕΜΠΙΣΤΟ κείμενο: το copilot.tooldefs.load_tools θεωρεί «διαδρομή αρχείου» κάθε
  string που δεν αρχίζει με [ ή {, γι' αυτό εδώ κάνουμε ΠΑΝΤΑ json.loads πρώτα και δίνουμε μόνο list/dict.
* Όλα τα νούμερα (επιθέσεις, σενάρια) προέρχονται από πραγματική εκτέλεση του repo· τίποτα δεν επινοείται εδώ.
"""
from __future__ import annotations

import copy
import json
import os
import re
import secrets
import shutil
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard.lookups import LookupContext  # noqa: E402
from app.policy_engine import PolicyEngine, validate_policy  # noqa: E402
from copilot.dbschema import SchemaError  # noqa: E402
from copilot.evaluate import answers_for  # noqa: E402
from copilot import prompts  # noqa: E402
from copilot.heuristics import analyze_tools  # noqa: E402
from copilot.llm import LLMError, ReplayLLM, default_llm  # noqa: E402
from copilot.questions import MAX_QUESTIONS, build_questions  # noqa: E402
from copilot.session import ApprovalRefused, CopilotSession  # noqa: E402
from copilot.tooldefs import ToolDefError, load_tools  # noqa: E402
from examples.demobank import run_demo  # noqa: E402
from examples.demobank.app import DemoBankApp  # noqa: E402

from . import demo_presets as presets  # noqa: E402

OUT_ROOT = ROOT / "out" / "ui"                       # εκτός git (το out/ είναι στο .gitignore)
RESULTS_FILE = Path(__file__).resolve().parent / "static" / "data" / "results.json"

MODES = ("replay", "live", "offline")
DOWNLOADS = {"policy.json": "application/json", "approval.json": "application/json"}   # λευκή λίστα
SNIPPET_LANGS = ("python", "node", "http")
SESSION_TTL = 2 * 3600
MAX_SESSIONS = 20
HISTORY_MAX = 10

MAX_TOOLS_CHARS = 1_500_000
MAX_TEXT = {"company": 200, "agent": 2_000, "requirements": 20_000, "db_schema": 100_000}
MAX_ARGS_CHARS = 20_000
MAX_PROMPT_CHARS = 80_000

_KEY_LIKE = re.compile(r"AIza[0-9A-Za-z_\-]{20,}")
_CTX_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_FIELD_EL = {"company": "εταιρία", "agent": "βοηθός", "requirements": "απαιτήσεις", "roles": "ρόλοι",
             "context_attributes": "γεγονότα πλαισίου", "db_schema": "δομή βάσης", "tools": "εργαλεία"}


# ---------------------------------------------------------------------------
# Σφάλματα και μυστικά
# ---------------------------------------------------------------------------

def scrub(text) -> str:
    """Αφαιρεί το κλειδί Gemini (και ό,τι μοιάζει με κλειδί Google) από ένα κείμενο."""
    text = str(text)
    key = os.environ.get("AI_STUDIO_API_KEY", "")
    if key:
        text = text.replace(key, "***")
    return _KEY_LIKE.sub("***", text)


class UIError(Exception):
    """Σφάλμα προς τον χρήστη: κωδικός, ελληνικό μήνυμα, HTTP status και (προαιρετικά) λίστα λόγων."""

    def __init__(self, code: str, message: str, status: int = 400, reasons=None, items=None):
        self.code, self.message, self.status = code, scrub(message), status
        self.reasons = [scrub(r) for r in reasons] if reasons else None
        self.items = items
        super().__init__(self.message)

    def payload(self) -> dict:
        err = {"code": self.code, "message": self.message}
        out: dict = {"error": err}
        if self.reasons is not None:
            err["reasons"] = self.reasons
            out["reasons"] = self.reasons
        if self.items is not None:
            err["items"] = self.items
        return out


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Έλεγχος εισόδων
# ---------------------------------------------------------------------------

def _text(body: dict, field: str, label: str, required: bool = True) -> str | None:
    value = body.get(field)
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise UIError("input_invalid", f"Συμπλήρωσε το πεδίο «{label}».", 422)
        return None
    if not isinstance(value, str):
        raise UIError("input_invalid", f"Το πεδίο «{label}» πρέπει να είναι κείμενο.", 422)
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    if len(value) > MAX_TEXT[field]:
        raise UIError("input_too_big", f"Το πεδίο «{label}» είναι πολύ μεγάλο (όριο {MAX_TEXT[field]} χαρακτήρες).", 413)
    return value.strip()


def _roles(value) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(r, str) for r in value):
        raise UIError("input_invalid", "Οι ρόλοι πρέπει να είναι λίστα από κείμενα.", 422)
    roles = list(dict.fromkeys(r.strip() for r in value if r.strip()))
    if len(roles) > 20 or any(len(r) > 60 for r in roles):
        raise UIError("input_invalid", "Οι ρόλοι είναι υπερβολικά πολλοί ή μεγάλοι (έως 20 ρόλοι, 60 χαρακτήρες ο καθένας).", 422)
    return roles or None


def _context_attributes(value) -> dict | None:
    if value is None or value == {}:
        return None
    if not isinstance(value, dict) or len(value) > 30:
        raise UIError("input_invalid", "Τα γεγονότα πλαισίου πρέπει να είναι λεξικό {όνομα: περιγραφή} (έως 30).", 422)
    out = {}
    for k, v in value.items():
        if not isinstance(k, str) or not _CTX_NAME.match(k) or not isinstance(v, str) or len(v) > 300:
            raise UIError("input_invalid", f"Μη έγκυρο γεγονός πλαισίου «{str(k)[:40]}».", 422)
        out[k] = v
    return out


def _tools_object(text):
    """Κείμενο JSON -> λίστα/λεξικό. ΠΟΤΕ δεν επιστρέφει string (θα διαβαζόταν ως διαδρομή αρχείου από το load_tools)."""
    if isinstance(text, (list, dict)):
        obj = text
    else:
        if not isinstance(text, str) or not text.strip():
            raise UIError("tools_empty", "Δεν δόθηκαν εργαλεία. Κόλλησε τον ορισμό τους (JSON) ή φόρτωσε ένα αρχείο.", 422)
        if len(text) > MAX_TOOLS_CHARS:
            raise UIError("tools_too_big", "Ο ορισμός των εργαλείων είναι πολύ μεγάλος (όριο 1,5 εκατ. χαρακτήρες).", 413)
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            raise UIError("tools_not_json", f"Τα εργαλεία δεν είναι έγκυρο JSON (γραμμή {e.lineno}, στήλη {e.colno}): {e.msg}.", 422) from None
    if not isinstance(obj, (list, dict)):
        raise UIError("tools_invalid", "Τα εργαλεία πρέπει να είναι λίστα ή αντικείμενο JSON (π.χ. [{\"name\": ...}]).", 422)
    return obj


def parse_tools(text) -> dict:
    """Με τον ίδιο φορτωτή που χρησιμοποιεί το Copilot. Επιστρέφει όσα βρήκε ή UIError με κατανοητό μήνυμα."""
    obj = _tools_object(text)
    try:
        tools = load_tools(obj)
    except ToolDefError as e:
        raise UIError("tools_invalid", str(e), 422) from None
    formats: dict = {}
    for t in tools:
        formats[t["source_format"]] = formats.get(t["source_format"], 0) + 1
    return {"count": len(tools), "formats": formats,
            "tools": [{"name": t["name"], "description": (t["description"] or "")[:300], "http_method": t["http_method"],
                       "source_format": t["source_format"],
                       "params": [{"name": p, "type": s["type"], "required": s["required"]} for p, s in t["params"].items()]}
                      for t in tools]}


# ---------------------------------------------------------------------------
# Συνεδρίες στη μνήμη
# ---------------------------------------------------------------------------

class _Entry:
    def __init__(self, sid, session, mode, llm, out_dir, preset):
        self.sid, self.session, self.mode, self.llm, self.out_dir, self.preset = sid, session, mode, llm, Path(out_dir), preset
        self.lock = threading.RLock()
        self.created = self.touched = time.monotonic()
        self.approved: dict | None = None
        self.history: list[dict] = []
        self.demo_app: DemoBankApp | None = None

    @property
    def demobank(self) -> bool:
        return self.preset == "demobank"


def _rm_out(path: Path) -> None:
    """Σβήνει ΜΟΝΟ φάκελο που είναι άμεσο παιδί του OUT_ROOT (δικός μας φάκελος συνεδρίας)."""
    try:
        p, root = Path(path).resolve(), OUT_ROOT.resolve()
        if p.parent == root and p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
    except OSError:
        pass


def _dispose(entry: _Entry) -> None:
    if entry.demo_app is not None:
        try:
            entry.demo_app.close()
        except Exception:  # noqa: BLE001
            pass
        entry.demo_app = None
    _rm_out(entry.out_dir)


class SessionStore:
    """sid -> _Entry. Λήξη μετά από `ttl` δευτερόλεπτα αδράνειας, το πολύ `max_sessions` (διώχνεται η παλαιότερη σε χρήση)."""

    def __init__(self, ttl: float = SESSION_TTL, max_sessions: int = MAX_SESSIONS, clock=time.monotonic):
        self.ttl, self.max_sessions, self.clock = ttl, max_sessions, clock
        self._items: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        for sid in [s for s, e in self._items.items() if now - e.touched > self.ttl]:
            _dispose(self._items.pop(sid))

    def add(self, entry: _Entry) -> None:
        with self._lock:
            now = self.clock()
            self._purge(now)
            while len(self._items) >= self.max_sessions:
                oldest = min(self._items.values(), key=lambda e: e.touched)
                _dispose(self._items.pop(oldest.sid))
            entry.touched = now
            self._items[entry.sid] = entry

    def get(self, sid) -> _Entry:
        with self._lock:
            now = self.clock()
            self._purge(now)
            entry = self._items.get(sid) if isinstance(sid, str) else None
            if entry is None:
                raise UIError("session_not_found", "Η συνεδρία δεν υπάρχει ή έληξε (λήγει μετά από 2 ώρες αδράνειας). Ξεκίνα ξανά από το πρώτο βήμα.", 404)
            entry.touched = now
            return entry

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def clear(self) -> None:
        with self._lock:
            for e in self._items.values():
                _dispose(e)
            self._items.clear()


STORE = SessionStore()
_ATTACK_LOCK = threading.Lock()
_REFS: dict = {}


# ---------------------------------------------------------------------------
# Κατάσταση, presets
# ---------------------------------------------------------------------------

def status() -> dict:
    return {"live_available": bool(os.environ.get("AI_STUDIO_API_KEY")), "replay_available": presets.replay_available(),
            "demobank_available": presets.demobank_available()}


def list_presets() -> list[dict]:
    return presets.presets()


def _preset_intake(pid: str) -> dict:
    """Το intake που θα έφτιαχνε το Copilot για ένα preset (cache). Χρησιμεύει για αναγνώριση «είναι η DemoBank;»."""
    if pid not in _REFS:
        p = presets.demobank_preset() if pid == "demobank" else presets.democlinic_preset()
        tools_obj = json.loads(p["tools_text"])
        s = CopilotSession.new(company=p["company"], agent=p["agent"], tools=tools_obj, requirements=p["requirements"],
                               roles=p["roles"], context_attributes=p["context_attributes"], db_schema=p["db_schema"], llm="offline")
        _REFS[pid] = s.intake
    return _REFS[pid]


def _intake_diff(intake: dict, ref: dict) -> list[str]:
    return [k for k in _FIELD_EL if intake.get(k) != ref.get(k)]


def _match_preset(intake: dict) -> str | None:
    for pid in (("demobank",) if presets.demobank_available() else ()) + ("democlinic",):
        try:
            if not _intake_diff(intake, _preset_intake(pid)):
                return pid
        except (ValueError, OSError):
            continue
    return None


# ---------------------------------------------------------------------------
# Δημιουργία συνεδρίας
# ---------------------------------------------------------------------------

def _make_llm(mode: str):
    if mode == "live":
        llm = default_llm()
        if llm is None:
            raise UIError("no_api_key", "Το ζωντανό Gemini χρειάζεται τη μεταβλητή περιβάλλοντος AI_STUDIO_API_KEY, που δεν βρέθηκε. "
                          "Όρισέ την πριν ξεκινήσεις τον server (οδηγίες στο Studio) ή διάλεξε «Replay» (μόνο DemoBank) ή «Χωρίς AI».", 409)
        return llm
    if mode == "offline":
        return "offline"
    try:
        return ReplayLLM(presets.REPLAY_FILE)
    except LLMError as e:
        raise UIError("replay_unavailable", f"Το αρχείο replay δεν είναι διαθέσιμο: {e}", 409) from None


def _check_replay_data(intake: dict) -> None:
    try:
        diff = _intake_diff(intake, _preset_intake("demobank"))
    except (OSError, ValueError):
        raise UIError("demobank_missing", "Τα αρχεία της δοκιμαστικής DemoBank (examples/demobank) δεν διαβάζονται, "
                      "άρα το replay δεν μπορεί να χρησιμοποιηθεί.", 409) from None
    if diff:
        raise UIError("replay_data_mismatch",
                      "Το replay είναι καταγραφή πραγματικής εκτέλεσης μόνο για τη δοκιμαστική εφαρμογή DemoBank (όχι πραγματική εταιρία)· "
                      "δεν περιέχει απαντήσεις για άλλα δεδομένα και θα έδινε απαντήσεις για διαφορετική εφαρμογή. "
                      f"Στη φόρμα διαφέρουν: {', '.join(_FIELD_EL[k] for k in diff)}. "
                      "Διάλεξε «Ζωντανό Gemini» ή «Χωρίς AI» για τα δικά σου δεδομένα.", 422)


def _cut(text: str) -> tuple[str, bool]:
    return (text, False) if len(text) <= MAX_PROMPT_CHARS else (text[:MAX_PROMPT_CHARS], True)


def _public_questions(entry: _Entry) -> list[dict]:
    out = []
    for q in entry.session.questions():
        out.append({"id": q["id"], "key": q["key"], "tool": q.get("tool"), "text": q["text"], "why": q.get("why", ""),
                    "options": list(q.get("options") or []), "default": q.get("default"), "multi": bool(q.get("multi")),
                    "human_decision": q["key"] in ("allow_tool", "allow_tools_more", "unconditional")})
    return out


def _questions_stage(entry: _Entry) -> dict | None:
    """Το στάδιο «ερωτήσεις» ΑΚΡΙΒΩΣ όπως θα σταλεί. Το session.dry_run() του Copilot το δείχνει με «max 8» και κενό
    «already_asked», ενώ η πραγματική κλήση (copilot/questions.py::build_questions) ζητά μόνο όσες θέσεις περισσεύουν και
    στέλνει τις ντετερμινιστικές ερωτήσεις ως «already_asked». Εδώ ξαναχτίζεται με τις ίδιες δημόσιες συναρτήσεις.
    None = δεν θα γίνει καθόλου κλήση (οι ντετερμινιστικές ερωτήσεις γεμίζουν το όριο)."""
    intake = entry.session.intake
    analysis = analyze_tools(intake["tools"])
    deterministic = build_questions(intake, analysis, None)
    room = MAX_QUESTIONS - len(deterministic)
    if room <= 0:
        return None
    return {"stage": "questions", "system": prompts.QUESTIONS_SYSTEM,
            "user": prompts.questions_user(intake, analysis, room, [q["text"] for q in deterministic])}


def _public_dry_run(entry: _Entry) -> list[dict]:
    stages = [st for st in entry.session.dry_run() if st.get("stage") != "questions"]
    q = _questions_stage(entry)
    stages = ([q] if q else []) + stages
    out = []
    for st in stages:
        system, c1 = _cut(str(st.get("system", "")))
        user, c2 = _cut(str(st.get("user", "")))
        out.append({"stage": st.get("stage", ""), "system": system, "user": user, "truncated": c1 or c2})
    if q is None:
        out.insert(0, {"stage": "questions", "system": "", "truncated": False,
                       "user": "(Δεν θα σταλεί τίποτα για τις ερωτήσεις: οι ντετερμινιστικές ερωτήσεις καλύπτουν ήδη το όριο.)"})
    return out


def create_session(body: dict) -> dict:
    if not isinstance(body, dict):
        raise UIError("input_invalid", "Το αίτημα πρέπει να είναι αντικείμενο JSON.", 422)
    mode = body.get("mode")
    if mode not in MODES:
        raise UIError("input_invalid", "Διάλεξε μηχανή: «replay», «live» ή «offline».", 422)
    company = _text(body, "company", "εταιρία")
    agent = _text(body, "agent", "τι κάνει ο βοηθός")
    requirements = _text(body, "requirements", "απαιτήσεις")
    db_schema = _text(body, "db_schema", "δομή βάσης", required=False)
    roles, ctx = _roles(body.get("roles")), _context_attributes(body.get("context_attributes"))
    tools_obj = _tools_object(body.get("tools"))
    try:
        load_tools(tools_obj)                                  # κατανοητό σφάλμα πριν δημιουργηθεί οτιδήποτε
    except ToolDefError as e:
        raise UIError("tools_invalid", str(e), 422) from None
    llm = _make_llm(mode)
    sid = secrets.token_urlsafe(16)
    out_dir = OUT_ROOT / sid
    try:
        session = CopilotSession.new(company=company, agent=agent, tools=tools_obj, requirements=requirements, roles=roles,
                                     context_attributes=ctx, db_schema=db_schema, llm=llm, out_dir=str(out_dir))
    except SchemaError as e:
        raise UIError("schema_invalid", str(e), 422) from None
    except ToolDefError as e:
        raise UIError("tools_invalid", str(e), 422) from None
    except ValueError as e:
        raise UIError("input_invalid", str(e), 422) from None
    preset = _match_preset(session.intake)
    if mode == "replay":
        _check_replay_data(session.intake)
    entry = _Entry(sid, session, mode, llm if mode != "offline" else None, out_dir, preset)
    with entry.lock:
        res = {"sid": sid, "mode": mode, "llm_label": session.state["llm_label"], "preset": preset,
               "dry_run": _public_dry_run(entry), "questions": None}
        if mode != "live":          # στο live ΔΕΝ καλείται το LLM πριν ο χρήστης δει το «Τι θα σταλεί στο AI» (βλ. get_questions)
            res.update(_questions_payload(entry))
    STORE.add(entry)
    return res


def _questions_payload(entry: _Entry) -> dict:
    questions = _public_questions(entry)
    out = {"questions": questions}
    if entry.mode == "replay":
        by_id = {q["id"] for q in questions}
        out["recorded_answers"] = {qid: ans for qid, ans in answers_for(entry.session).items() if qid in by_id}
    return out


def get_questions(sid: str) -> dict:
    """Οι ερωτήσεις. Στο live εδώ γίνεται (για πρώτη φορά) η κλήση προς το LLM."""
    entry = STORE.get(sid)
    with entry.lock:
        return _questions_payload(entry)


def get_dry_run(sid: str) -> list[dict]:
    """ΑΚΡΙΒΩΣ ό,τι θα σταλεί στο LLM με τις τρέχουσες απαντήσεις. Δεν καλεί LLM."""
    entry = STORE.get(sid)
    with entry.lock:
        return _public_dry_run(entry)


# ---------------------------------------------------------------------------
# Απαντήσεις, παραγωγή πρόχειρου
# ---------------------------------------------------------------------------

def _drop_approval(entry: _Entry) -> None:
    entry.approved = None
    for name in DOWNLOADS:
        try:
            (entry.out_dir / name).unlink()
        except OSError:
            pass


def submit_answers(sid: str, answers) -> dict:
    entry = STORE.get(sid)
    if not isinstance(answers, dict) or len(answers) > 40:
        raise UIError("input_invalid", "Οι απαντήσεις πρέπει να είναι λεξικό {id ερώτησης: απάντηση}.", 422)
    clean = {}
    for qid, value in answers.items():
        ok = isinstance(value, str) and len(value) <= 2_000
        if isinstance(value, list):
            ok = len(value) <= 40 and all(isinstance(v, str) and len(v) <= 500 for v in value)
        if not isinstance(qid, str) or not ok:
            raise UIError("input_invalid", f"Μη έγκυρη απάντηση για την ερώτηση «{str(qid)[:20]}».", 422)
        clean[qid] = value
    with entry.lock:
        res = entry.session.answer(clean)
        if res["accepted"]:
            _drop_approval(entry)
    return res


def _count(issues: list[dict], level: str) -> int:
    return sum(1 for i in issues if i.get("level") == level)


def _rules_for(policy: dict, tool: str, role: str) -> list[dict]:
    out = []
    for r in policy.get("rules", []):
        tools, roles = r.get("tools", ["*"]), r.get("roles", ["*"])
        if ("*" in tools or tool in tools) and ("*" in roles or role in roles):
            out.append({"id": r.get("id"), "effect": r.get("effect"), "reason": str(r.get("reason", "")), "conditional": bool(r.get("when"))})
    return out


def _matrix_detail(policy: dict, matrix: dict) -> dict:
    return {tool: {role: {"label": label, "rules": _rules_for(policy, tool, role)} for role, label in roles.items()}
            for tool, roles in matrix.items()}


def _lookups(policy: dict) -> list[dict]:
    lk = policy.get("lookups")
    if not isinstance(lk, dict):
        return []
    return [{"name": name, "description": str(v.get("description", "")), "sql": str(v.get("sql", "")),
             "params": v.get("params") or {}, "returns": str(v.get("returns", ""))} for name, v in lk.items() if isinstance(v, dict)]


def _clinic() -> dict:
    if "clinic_preset" not in _REFS:
        _REFS["clinic_preset"] = presets.democlinic_preset()
    return _REFS["clinic_preset"]


def _example_args(entry: _Entry, tool_def: dict) -> dict:
    pre = {"demobank": presets.DEMOBANK_ARGS}.get(entry.preset)
    if pre is None and entry.preset == "democlinic":
        pre = _clinic()["example_args"]
    if pre and tool_def["name"] in pre:
        return copy.deepcopy(pre[tool_def["name"]])
    params = tool_def.get("params") or {}
    chosen = {p: s for p, s in params.items() if s.get("required")} or params
    ex = {"integer": 1, "number": 1, "boolean": True, "array": [], "object": {}}
    return {p: ex.get(s.get("type"), "example") for p, s in chosen.items()}


def _user_id(entry: _Entry, role: str) -> str:
    users = presets.DEMOBANK_USERS if entry.preset == "demobank" else (
        _clinic()["example_users"] if entry.preset == "democlinic" else {})
    return users.get(role) or f"user-{role}"


def _try_hints(entry: _Entry, policy: dict, matrix: dict) -> dict:
    tools = {t["name"]: t for t in entry.session.intake["tools"]}
    high, untrusted = set(policy.get("high_risk_tools", [])), set(policy.get("untrusted_tools", []))
    roles = list(policy.get("roles", []))
    tool_list = [{"name": n, "description": (t["description"] or "")[:200], "high_risk": n in high, "untrusted": n in untrusted,
                  "example_args": _example_args(entry, t)} for n, t in tools.items()]
    probes = []
    for name in sorted(high | untrusted, key=lambda n: (n not in high, n)):
        if name not in matrix or name not in tools:
            continue
        cells = matrix[name]
        denied = next((r for r in roles if cells.get(r) == "deny"), None)
        if denied and name in high:
            probes.append({"label": f"Ως «{denied}» κάλεσε «{name}» (δεν έχει δικαίωμα)", "role": denied, "tool": name,
                           "args": _example_args(entry, tools[name]), "user_id": _user_id(entry, denied), "after_untrusted": False})
        allowed = [r for r in roles if cells.get(r) in ("allow", "conditional")]
        if allowed and name in high and untrusted:
            r = allowed[-1]
            probes.append({"label": f"Ως «{r}» κάλεσε «{name}» αφού διαβάστηκε μη έμπιστο κείμενο", "role": r, "tool": name,
                           "args": _example_args(entry, tools[name]), "user_id": _user_id(entry, r), "after_untrusted": True})
    return {"roles": roles, "user_ids": {r: _user_id(entry, r) for r in roles}, "tools": tool_list, "probes": probes[:8]}


def _present_result(entry: _Entry, res: dict) -> dict:
    st = entry.session.state["result"]
    policy, issues, report = res["policy"], res["issues"], res["scenarios_report"]
    policy_errors = [v for v in validate_policy(policy) if v["level"] == "error"]
    llm = entry.llm
    replay = {"fallback_used": llm.fallback_used, "calls": len(llm.sent)} if isinstance(llm, ReplayLLM) else None
    return {
        "policy": policy, "issues": issues, "matrix": res["matrix"], "matrix_detail": _matrix_detail(policy, res["matrix"]),
        "review_md": res["review_md"], "files": [{"name": n, "size": len(t.encode("utf-8"))} for n, t in res["files"].items()],
        "scenarios": {"total": report["total"], "passed": report["passed"], "by_source": report["by_source"],
                      "results": [{"id": r["id"], "text": r["text"], "ok": r["ok"], "kind": r["kind"], "expected": r["expected"],
                                   "actual": r["actual"], "rule": r.get("rule", ""), "reason": r["reason"]} for r in report["results"]]},
        "disagreements": [{"id": r["id"], "text": r["text"], "expected": r["expected"], "actual": r["actual"],
                           "rule": r.get("rule", ""), "reason": r["reason"]} for r in report["failed"]],
        "summary": {"errors": _count(issues, "error"), "warnings": _count(issues, "warning"), "info": _count(issues, "info"),
                    "scenarios_passed": report["passed"], "scenarios_total": report["total"],
                    "can_approve": not any(i["level"] == "error" for i in issues) and not policy_errors},
        "source": st["source"], "model": st["model"], "llm_label": entry.session.state["llm_label"], "mode": entry.mode,
        "replay": replay, "lookups": _lookups(policy), "roles": list(policy.get("roles", [])),
        "high_risk_tools": list(policy.get("high_risk_tools", [])), "untrusted_tools": list(policy.get("untrusted_tools", [])),
        "try_hints": _try_hints(entry, policy, res["matrix"]), "stage": "draft", "stage_el": "πρόχειρο",
    }


def _fresh_replay(entry: _Entry) -> None:
    """Το ReplayLLM «καταναλώνει» κάθε καταγραφή μία φορά. Για να είναι κάθε generate() αναπαραγώγιμο (και ο χρήστης να
    μπορεί να γυρίσει πίσω και να ξαναδοκιμάσει), δίνουμε νέο ReplayLLM και ξαναπαίζουμε πρώτα το στάδιο των ερωτήσεων,
    ακριβώς όπως θα έκανε μια φρέσκια εκτέλεση (ερωτήσεις -> πρόχειρο -> σενάρια)."""
    try:
        fresh = ReplayLLM(presets.REPLAY_FILE)
    except LLMError as e:
        raise UIError("replay_unavailable", f"Το αρχείο replay δεν είναι διαθέσιμο: {e}", 409) from None
    clean = dict(entry.session.to_dict(), questions=None, answers={}, result=None, approval=None)
    CopilotSession.from_dict(clean, llm=fresh).questions()
    entry.session.llm = entry.llm = fresh


def generate(sid: str) -> dict:
    entry = STORE.get(sid)
    with entry.lock:
        _drop_approval(entry)
        if entry.mode == "replay":
            _fresh_replay(entry)
        res = entry.session.generate()
        return _present_result(entry, res)


# ---------------------------------------------------------------------------
# Έγκριση, snippets, λήψεις
# ---------------------------------------------------------------------------

def _fix_step(reason: str) -> str:
    if "confirm" in reason or "όνομα" in reason:
        return "approve"
    if "generate" in reason or "πρόχειρο" in reason:
        return "check"
    return "questions"


def approve(sid: str, by, confirm) -> dict:
    entry = STORE.get(sid)
    with entry.lock:
        by = by.strip()[:100] if isinstance(by, str) else by
        try:
            res = entry.session.approve(by, confirm, out_dir=entry.out_dir)
        except ApprovalRefused as e:
            raise UIError("approval_refused", "Η έγκριση δεν έγινε: " + (e.reasons[0] if e.reasons else "άγνωστος λόγος") +
                          (f" (και άλλοι {len(e.reasons) - 1})" if len(e.reasons) > 1 else ""), 409, reasons=e.reasons,
                          items=[{"text": scrub(r), "fix": _fix_step(r)} for r in e.reasons]) from None
        try:
            policy = json.loads((entry.out_dir / "policy.json").read_text(encoding="utf-8"))
            approval = json.loads((entry.out_dir / "approval.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise UIError("approval_files_missing", "Η έγκριση έγινε αλλά τα αρχεία δεν διαβάζονται. Δοκίμασε ξανά.", 500) from None
        entry.approved = {"policy": policy, "approval": approval, "by": approval.get("approved_by"), "at": res["approved_at"]}
        sc = approval.get("scenarios") or {}
        return {"approved": True, "approved_by": approval.get("approved_by"), "approved_at": res["approved_at"],
                "policy_sha256": res["policy_sha256"], "source_sha256": res["source_sha256"],
                "files": [{"name": n, "size": (entry.out_dir / n).stat().st_size} for n in DOWNLOADS],
                "scenarios": {"passed": sc.get("passed", 0), "total": sc.get("total", 0)}}


def snippet(sid: str, lang: str) -> dict:
    if lang not in SNIPPET_LANGS:
        raise UIError("input_invalid", "Διάλεξε γλώσσα: python, node ή http.", 404)
    entry = STORE.get(sid)
    with entry.lock:
        if entry.session.state["result"] is None:
            raise UIError("no_draft", "Πρώτα γράψε τους κανόνες (βήμα «Έλεγχος»).", 409)
        code = entry.session.snippet(lang)
    sidecar = (ROOT / "agentguard" / "__main__.py").is_file()
    if lang == "python":
        note = "Python είναι η μόνη γλώσσα που υποστηρίζεται σήμερα."
    else:
        note = ("Κείμενο που δεν έχει εκτελεστεί ή δοκιμαστεί: σήμερα υποστηρίζεται μόνο Python. "
                + ("" if sidecar else "Ο sidecar server (python -m agentguard serve) που αναφέρει δεν υπάρχει ακόμα σε αυτό το αποθετήριο."))
    return {"lang": lang, "code": code, "tested": False if lang != "python" else None, "note": note.strip(),
            "stage": "approved" if entry.approved else "draft"}


def download(sid: str, name) -> tuple[bytes, str, str]:
    """(περιεχόμενο, όνομα αρχείου, media type). Το όνομα ελέγχεται ΜΟΝΟ από τη λευκή λίστα· ποτέ διαδρομή του χρήστη."""
    if not isinstance(name, str) or name not in DOWNLOADS:
        raise UIError("download_not_allowed", "Επιτρέπονται μόνο τα αρχεία policy.json και approval.json.", 404)
    entry = STORE.get(sid)
    with entry.lock:
        if entry.approved is None:
            raise UIError("not_approved", "Τα αρχεία παράγονται μόνο μετά την έγκριση.", 409)
        try:
            data = (entry.out_dir / name).read_bytes()
        except OSError:
            raise UIError("file_missing", "Το αρχείο δεν βρέθηκε. Ξανακάνε την έγκριση.", 404) from None
    return data, name, DOWNLOADS[name]


# ---------------------------------------------------------------------------
# «Δοκίμασε»
# ---------------------------------------------------------------------------

_RULE_EL = {
    "default": "Κανένας κανόνας δεν επιτρέπει αυτή την κλήση, οπότε ισχύει η προεπιλογή: απαγορεύεται.",
    "security.invalid_user": "Ο χρήστης πρέπει να έχει αναγνωριστικό και ρόλο.",
    "security.unknown_role": "Ο ρόλος δεν υπάρχει στην πολιτική, άρα η κλήση δεν επιτρέπεται.",
    "security.unknown_tool": "Το εργαλείο δεν αναφέρεται στην πολιτική, άρα δεν επιτρέπεται.",
    "security.invalid_args": "Τα ορίσματα της κλήσης δεν είναι έγκυρα, άρα η κλήση απορρίπτεται.",
    "policy.internal_error": "Παρουσιάστηκε σφάλμα κατά την αξιολόγηση· για ασφάλεια η κλήση απορρίπτεται.",
}
_TAINT_EL = ("Ο κανόνας επιτρέπει την κλήση, αλλά το εργαλείο είναι υψηλού κινδύνου και στην ίδια συνομιλία διαβάστηκε μη έμπιστο "
             "περιεχόμενο. Ο Guard σταματά και ζητά έγκριση από άνθρωπο (κανόνας taint.high_risk).")


class _TryContext:
    """Γεγονότα για τον έλεγχο: πρώτα όσα έδωσε ο χρήστης, μετά (μόνο DemoBank) τα lookups πάνω στη δοκιμαστική βάση."""

    def __init__(self, manual: dict, lookup_ctx: LookupContext | None):
        self.manual, self.lookup_ctx, self.from_db = manual, lookup_ctx, []

    def get(self, name):
        if name in self.manual:
            return self.manual[name]
        if self.lookup_ctx is not None and self.lookup_ctx.has(name):
            if name not in self.from_db:
                self.from_db.append(name)
            return self.lookup_ctx.get(name)
        return None


def _try_user(body: dict, entry: _Entry) -> dict:
    user = body.get("user")
    if user is not None:
        if not isinstance(user, dict) or not isinstance(user.get("role"), str) or not user["role"].strip():
            raise UIError("input_invalid", "Ο χρήστης πρέπει να έχει «role» (κείμενο).", 422)
        return {**user, "id": str(user.get("id") or _user_id(entry, user["role"])), "role": user["role"].strip()}
    role = body.get("role")
    if not isinstance(role, str) or not role.strip():
        raise UIError("input_invalid", "Διάλεξε ρόλο για τη δοκιμή.", 422)
    uid = body.get("user_id")
    return {"id": str(uid).strip()[:100] if isinstance(uid, (str, int)) and str(uid).strip() else _user_id(entry, role.strip()),
            "role": role.strip()}


def _json_object(value, label: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise UIError("input_invalid", f"Το «{label}» πρέπει να είναι αντικείμενο JSON {{…}}.", 422)
    if len(json.dumps(value, default=str)) > MAX_ARGS_CHARS:
        raise UIError("input_too_big", f"Το «{label}» είναι πολύ μεγάλο.", 413)
    return value


def try_decision(sid: str, body: dict) -> dict:
    """Η απόφαση της ΜΗΧΑΝΗΣ πάνω στην τρέχουσα πολιτική (πρόχειρο ή εγκεκριμένη). Τίποτα δεν εκτελείται."""
    if not isinstance(body, dict):
        raise UIError("input_invalid", "Το αίτημα πρέπει να είναι αντικείμενο JSON.", 422)
    entry = STORE.get(sid)
    with entry.lock:
        st = entry.session.state["result"]
        if st is None:
            raise UIError("no_draft", "Δεν υπάρχει πολιτική ακόμα. Γράψε πρώτα τους κανόνες (βήμα «Έλεγχος»).", 409)
        approved = entry.approved is not None
        policy = entry.approved["policy"] if approved else st["policy"]
        tool = body.get("tool")
        if not isinstance(tool, str) or not tool.strip() or len(tool) > 200:
            raise UIError("input_invalid", "Διάλεξε εργαλείο.", 422)
        tool = tool.strip()
        user = _try_user(body, entry)
        args = _json_object(body.get("args"), "ορίσματα")
        manual = _json_object(body.get("ctx"), "περιβάλλον")
        after_untrusted = bool(body.get("after_untrusted"))
        try:
            engine = PolicyEngine(policy)
        except ValueError as e:
            raise UIError("policy_invalid", f"Η πολιτική δεν είναι έγκυρη και δεν μπορεί να δοκιμαστεί: {e}", 409) from None
        findings: list = []
        lookup_ctx = None
        if entry.demobank and isinstance(policy.get("lookups"), dict) and policy["lookups"]:
            if entry.demo_app is None:
                entry.demo_app = DemoBankApp()
            lookup_ctx = LookupContext(policy["lookups"], entry.demo_app.readonly_connection(), user, tool, args, findings)
        ctx = _TryContext(manual, lookup_ctx)
        out = engine.explain(user, tool, args, ctx)
        high, untrusted = tool in engine.high_risk_tools, tool in engine.untrusted_tools
        decision, rule, reason_el, note = out["action"], out["rule"], _RULE_EL.get(out["rule"]), None
        if decision == "allow" and high:
            if after_untrusted:
                decision, rule, reason_el = "needs_approval", "taint.high_risk", _TAINT_EL
            else:
                note = ("Αν στην ίδια συνομιλία έχει διαβαστεί μη έμπιστο περιεχόμενο, ο Guard θα ζητούσε έγκριση ανθρώπου "
                        "για αυτό το εργαλείο υψηλού κινδύνου.")
        result = {"decision": decision, "engine_action": out["action"], "rule": rule, "reason": out.get("reason", ""),
                  "reason_el": reason_el, "matched_rules": out.get("matched_rules", []), "high_risk": high, "untrusted": untrusted,
                  "after_untrusted": after_untrusted, "note": note, "user": user, "tool": tool, "args": args,
                  "stage": "approved" if approved else "draft", "stage_el": "εγκεκριμένο" if approved else "πρόχειρο",
                  "facts": {"manual": sorted(manual), "demo_db": list(ctx.from_db)},
                  "lookup_errors": [f.get("lookup") for f in findings if f.get("type") == "lookup_error"]}
        entry.history.insert(0, {"at": _now_iso(), "role": user["role"], "tool": tool, "args": args, "decision": decision,
                                 "rule": rule, "stage": result["stage"], "after_untrusted": after_untrusted})
        del entry.history[HISTORY_MAX:]
        result["history"] = copy.deepcopy(entry.history)
        return result


# ---------------------------------------------------------------------------
# Ζωντανή επίθεση (μόνο DemoBank) και αποτελέσματα
# ---------------------------------------------------------------------------

def _how(item: dict) -> tuple[str, str]:
    g = item["with_guard"]
    if g["success"]:
        return "succeeded", f"η επίθεση πέτυχε ({g['detail']})"
    if g["status"] == "ok":
        if g.get("findings"):
            return "neutralised", f"εξουδετερώθηκε ({g['findings']} ευρήματα καθαρισμού)"
        return "harmless", f"επιτράπηκε, χωρίς ζημιά: {g['detail']}"
    rule = f" ({g['rule']})" if g.get("rule") else ""
    return g["status"], f"{g['status']}{rule}"


def attack_run(body: dict) -> dict:
    if not isinstance(body, dict):
        raise UIError("input_invalid", "Το αίτημα πρέπει να είναι αντικείμενο JSON.", 422)
    source = body.get("source")
    if source == "reference":
        policy, label = None, "Η χειρόγραφη reference πολιτική"
    elif source == "session":
        entry = STORE.get(body.get("sid"))
        with entry.lock:
            if not entry.demobank:
                raise UIError("attack_not_available", "Η ζωντανή επίθεση υπάρχει μόνο για τη δοκιμαστική DemoBank· "
                              "δοκίμασε τη δική σου εφαρμογή στο «Δοκίμασε».", 409)
            if entry.approved is None:
                raise UIError("not_approved", "Η πολιτική του Copilot δεν έχει εγκριθεί ακόμα. Εγκρίνε την πρώτα.", 409)
            policy, label = copy.deepcopy(entry.approved["policy"]), "Η πολιτική που εγκρίθηκε από το Copilot"
    else:
        raise UIError("input_invalid", "Διάλεξε πηγή πολιτικής: «reference» ή «session».", 422)
    started = time.monotonic()
    with _ATTACK_LOCK:
        try:
            report = run_demo.run(policy)
        except (ValueError, OSError) as e:
            raise UIError("attack_failed", f"Η επίθεση δεν μπόρεσε να τρέξει: {e}", 500) from None
    for kind in ("attacks", "normal"):
        for item in report[kind]:
            item["how_kind"], item["how_text"] = _how(item)
    return {"source": source, "source_label": label, "summary": run_demo.summarize(report), "attacks": report["attacks"],
            "normal": report["normal"], "problems": run_demo.problems(report), "ran_at": _now_iso(),
            "elapsed_s": round(time.monotonic() - started, 2),
            "ran_with": "examples.demobank.run_demo.run(policy=" + ("None" if policy is None else "<εγκεκριμένη πολιτική>") + ")"}


def results() -> dict:
    try:
        return json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise UIError("results_missing", "Τα αποτελέσματα δεν έχουν παραχθεί ακόμα (τρέξε ui/build_results.py).", 404) from None
    except (OSError, ValueError):
        raise UIError("results_invalid", "Το αρχείο αποτελεσμάτων δεν διαβάζεται.", 500) from None
