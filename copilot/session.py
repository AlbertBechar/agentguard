"""
copilot/session.py -- CopilotSession: το API που θα καλεί αργότερα το web UI (ενότητα 3.4 / 5.3 του εγγράφου).

Κανόνες: καμία μέθοδος δεν κάνει input()/print(). Όλα τα αποτελέσματα είναι JSON-serializable (list/dict/str/num/bool/None).
Το policy.json γράφεται ΜΟΝΟ από approve(), και μόνο αν: confirm == "yes", υπάρχει όνομα υπογράφοντος, το validate
δεν έχει errors και κανένα issue επιπέδου error. Το πρόχειρο γράφεται ως policy.draft.json.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from app.policy_engine import PolicyEngine, validate_policy

from . import contract, prompts
from .dbschema import SchemaInfo, sanitize_schema
from .floor import has_errors
from .generate import generate_policy
from .heuristics import analyze_tools
from .llm import default_llm
from .questions import build_questions, confirmed_open_tools, decisions_from_answers
from .review import review_md
from .scenarios import generate_scenarios, run_scenarios, to_file_object
from .tooldefs import load_tools

STATE_VERSION = 1
EMPTY_REPORT = {"total": 0, "passed": 0, "failed": [], "results": [], "by_source": {}}


class ApprovalRefused(Exception):
    """Το approve() αρνήθηκε. .reasons = λίστα με τους λόγους (ελληνικά)."""

    def __init__(self, reasons):
        self.reasons = list(reasons)
        super().__init__("; ".join(self.reasons))


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _sha256(obj) -> str:
    return hashlib.sha256(_canonical(obj).encode("utf-8")).hexdigest()


def slugify(text: str) -> str:
    slug = re.sub(r"[^\w]+", "-", str(text).split("—")[0], flags=re.U).strip("-_").lower()
    return slug[:40] or "company"


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def _json_text(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def _resolve_llm(llm):
    if llm is False or llm == "offline":
        return None
    return default_llm() if llm is None else llm


class CopilotSession:
    def __init__(self, state: dict, llm=None):
        self.state = state
        self.llm = llm
        self._schema = SchemaInfo(state["intake"].get("db_schema"))

    # ------------------------------------------------------------------ δημιουργία / σειριοποίηση

    @classmethod
    def new(cls, company, agent, tools, requirements, roles=None, context_attributes=None, db_schema=None,
            llm=None, language="el", out_dir=None):
        for name, value in (("company", company), ("agent", agent), ("requirements", requirements)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Το «{name}» πρέπει να είναι μη κενό κείμενο.")
        if language not in ("el", "en"):
            raise ValueError("Η γλώσσα πρέπει να είναι «el» ή «en».")
        tool_list = load_tools(tools)                                   # ToolDefError αν η είσοδος είναι κακή
        if roles is not None and (not isinstance(roles, (list, tuple)) or not all(isinstance(r, str) and r.strip() for r in roles)):
            raise ValueError("Οι ρόλοι πρέπει να είναι λίστα από κείμενα.")
        schema_text = sanitize_schema(db_schema) if db_schema else None  # SchemaError αν περιέχει κάτι άλλο εκτός από CREATE
        info = SchemaInfo(schema_text)
        ctx = {str(k): str(v) for k, v in (context_attributes or {}).items()}
        intake = {"company": company.strip(), "agent": agent.strip(), "requirements": requirements.strip(),
                  "language": language, "roles": [r.strip() for r in roles] if roles else None, "context_attributes": ctx,
                  "db_schema": schema_text, "tools": tool_list, "owner_columns": info.owner_columns()}
        llm = _resolve_llm(llm)
        state = {"version": STATE_VERSION, "intake": intake, "questions": None, "answers": {}, "result": None,
                 "approval": None, "out_dir": str(out_dir) if out_dir else None,
                 "llm_label": getattr(llm, "label", "offline") if llm is not None else "offline"}
        return cls(state, llm)

    def to_dict(self) -> dict:
        return copy.deepcopy(self.state)

    @classmethod
    def from_dict(cls, d: dict, llm=None):
        if not isinstance(d, dict) or d.get("version") != STATE_VERSION or "intake" not in d:
            raise ValueError("Μη έγκυρη κατάσταση συνεδρίας (to_dict).")
        return cls(copy.deepcopy(d), _resolve_llm(llm))

    # ------------------------------------------------------------------ βοηθητικά

    @property
    def intake(self) -> dict:
        return self.state["intake"]

    def _analysis(self) -> dict:
        return analyze_tools(self.intake["tools"])

    def _decisions(self) -> dict:
        qs = self.state["questions"] if self.state["questions"] is not None else build_questions(self.intake, self._analysis(), None)
        dec = decisions_from_answers(qs, self.state["answers"], self.intake)
        dec["confirmed_open"] = sorted(confirmed_open_tools(dec, self._analysis()))
        return dec

    def _effective_intake(self, dec: dict) -> dict:
        return dict(self.intake, roles=dec["roles"] or self.intake["roles"])

    def out_dir(self, out_dir=None) -> Path:
        chosen = out_dir or self.state.get("out_dir")
        return Path(chosen) if chosen else Path("out") / slugify(self.intake["company"])

    # ------------------------------------------------------------------ ροή

    def questions(self) -> list[dict]:
        if self.state["questions"] is None:
            self.state["questions"] = build_questions(self.intake, self._analysis(), self.llm)
        return copy.deepcopy(self.state["questions"])

    def answer(self, answers: dict) -> dict:
        qs = self.questions()
        known = {q["id"] for q in qs}
        if not isinstance(answers, dict):
            raise ValueError("Οι απαντήσεις πρέπει να είναι λεξικό {id: απάντηση}.")
        accepted, unknown = [], []
        for qid, value in answers.items():
            if qid in known:
                self.state["answers"][qid] = value
                accepted.append(qid)
            else:
                unknown.append(qid)
        if accepted:
            self.state["result"] = None       # το πρόχειρο έχει παλιώσει
            self.state["approval"] = None
        return {"accepted": accepted, "unknown": unknown}

    def generate(self) -> dict:
        self.questions()
        analysis = self._analysis()
        dec = self._decisions()
        intake = self._effective_intake(dec)
        gen = generate_policy(intake, analysis, dec, self._schema, self.llm)
        policy, issues = gen["policy"], list(gen["issues"])
        try:
            engine = PolicyEngine(policy)
        except ValueError:
            engine = None                      # τα errors βρίσκονται ήδη στα issues
        matrix = engine.matrix() if engine else {}
        report, scenarios = dict(EMPTY_REPORT), []
        if engine is not None:
            sg = generate_scenarios(intake, dec, self.llm, matrix)
            scenarios, issues = sg["scenarios"], issues + sg["issues"]
            report = run_scenarios(engine, scenarios)
        md = review_md(intake, policy, matrix, issues, dec, report if engine else None, gen["assumptions"],
                       gen["open_questions"], gen["source"], gen["model"])
        files = {"policy.draft.json": _json_text(policy), "review.md": md,
                 "context_contract.md": contract.context_contract_md(policy),
                 "scenarios.json": _json_text(to_file_object(scenarios))}
        stub = contract.resolver_stub_py(policy)
        if stub:
            files["resolver_stub.py"] = stub
        self.state["result"] = {"policy": policy, "issues": issues, "scenarios_report": report, "review_md": md,
                                "matrix": matrix, "files": files, "source": gen["source"], "model": gen["model"],
                                "confirmed_open": dec["confirmed_open"], "qa": dec["qa"]}
        self.state["approval"] = None
        return {k: copy.deepcopy(self.state["result"][k]) for k in
                ("policy", "issues", "scenarios_report", "review_md", "matrix", "files")}

    def _result(self) -> dict:
        if self.state["result"] is None:
            self.generate()
        return self.state["result"]

    def review_md(self) -> str:
        return self._result()["review_md"]

    def snippet(self, lang: str) -> str:
        r = self._result()
        return contract.snippet(lang, r["policy"], self.intake["tools"])

    def dry_run(self) -> list[dict]:
        """ΑΚΡΙΒΩΣ ό,τι θα σταλεί στο LLM (δεν καλεί LLM). Απόδειξη ότι δεν φεύγουν δεδομένα πελατών."""
        dec = self._decisions()
        return prompts.dry_run(self._effective_intake(dec), self._analysis(), dec)

    def save_draft(self, out_dir=None) -> list[str]:
        """Γράφει τα αρχεία πρόχειρου (policy.draft.json, review.md, ...). ΔΕΝ γράφει ποτέ policy.json."""
        r, base = self._result(), self.out_dir(out_dir)
        paths = []
        for name, text in r["files"].items():
            _write_text(base / name, text)
            paths.append(str(base / name))
        return paths

    # ------------------------------------------------------------------ έγκριση

    def approve(self, by, confirm, out_dir=None) -> dict:
        reasons = []
        if confirm != "yes":
            reasons.append("Η έγκριση απαιτεί ρητά confirm == \"yes\".")
        if not isinstance(by, str) or not by.strip():
            reasons.append("Λείπει το όνομα του ανθρώπου που υπογράφει (by).")
        r = self.state["result"]
        if r is None:
            reasons.append("Δεν υπάρχει πρόχειρο: τρέξτε πρώτα generate().")
        else:
            reasons += [f"Σφάλμα: {i['message']}" for i in r["issues"] if i["level"] == "error"]
            reasons += [f"Σφάλμα πολιτικής {v['path']}: {v['message']}" for v in validate_policy(r["policy"]) if v["level"] == "error"]
        if reasons:
            raise ApprovalRefused(reasons)
        try:
            PolicyEngine(r["policy"])
        except ValueError as e:
            raise ApprovalRefused([f"Ο μηχανισμός δεν φορτώνει την πολιτική: {e}"]) from None

        draft = r["policy"]
        source_hash = _sha256(draft)
        approved_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        final = copy.deepcopy(draft)
        meta = final.setdefault("meta", {})
        meta.update({"generated_by": "offline" if r["source"] == "offline" else f"copilot:{r['model']}",
                     "approved_by": by.strip(), "approved_at": approved_at, "source_sha256": source_hash})
        again = [v for v in validate_policy(final) if v["level"] == "error"]
        if again:
            raise ApprovalRefused([f"Σφάλμα πολιτικής {v['path']}: {v['message']}" for v in again])
        report = r["scenarios_report"]
        approval = {"approved_by": by.strip(), "approved_at": approved_at, "source_sha256": source_hash,
                    "policy_sha256": _sha256(final), "generated_by": meta["generated_by"], "llm": r["model"],
                    "issues": r["issues"], "confirmed_open_tools": r["confirmed_open"], "answers": r["qa"],
                    "scenarios": {"total": report["total"], "passed": report["passed"], "failed": report["failed"]}}
        base = self.out_dir(out_dir)
        _write_text(base / "policy.draft.json", _json_text(draft))
        _write_text(base / "policy.json", _json_text(final))
        _write_text(base / "approval.json", _json_text(approval))
        self.state["approval"] = {"approved_by": by.strip(), "approved_at": approved_at, "policy_sha256": approval["policy_sha256"]}
        return {"approved": True, "policy_path": str(base / "policy.json"), "approval_path": str(base / "approval.json"),
                "source_sha256": source_hash, "policy_sha256": approval["policy_sha256"], "approved_at": approved_at}
