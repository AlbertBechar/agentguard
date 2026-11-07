"""
agentguard/guard.py -- ο γενικός Guard (ανεξάρτητος από την εφαρμογή): taint, έγκριση ανθρώπου, sanitize, audit.

Κάνει για οποιαδήποτε εφαρμογή ό,τι κάνει το v1 Guard για το eClass, πάνω στον γενικό PolicyEngine. (Το eClass και
αυτός ο Guard μοιράζονται τον Engine, όχι ολόκληρο τον κώδικα.) Σειρά λογικής του call() (ενότητα 3.2):
  (1) context από lookups / resolver (σφάλμα => deny guard.context_error)
  (2) engine.evaluate  -> deny => denied
  (3) high-risk εργαλείο ΚΑΙ η συνεδρία είναι tainted => needs_approval (έγκριση ανθρώπου)
  (4) execute (εξαίρεση => error, χωρίς αποτέλεσμα)
  (5) untrusted εργαλείο: sanitize του αποτελέσματος + taint
  (6) engine.redact
Fail-closed: κάθε εξαίρεση (resolver, engine, execute, sanitize) δίνει error/denied και ΠΟΤΕ αποτέλεσμα.
"""
from __future__ import annotations

import copy
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.policy_engine import PolicyEngine

from .lookups import LookupContext
from .sanitize import sanitize_result

ARG_CUT = 200
MODES = ("enforce", "monitor")


class ContextError(RuntimeError):
    """Ο resolver της εταιρίας απέτυχε."""


class _CallContext:
    """Συνδυάζει: lookups => context_resolver => None (ενότητα 3.2). Υπολογίζει κατά παραγγελία και μία φορά ανά κλήση."""

    _UNSET = object()

    def __init__(self, lookup_ctx: LookupContext, resolver, user, tool, args):
        self.lookup_ctx, self.resolver = lookup_ctx, resolver
        self.user, self.tool, self.args = user, tool, args
        self._resolved = self._UNSET
        self.failed = False

    def get(self, name):
        if self.lookup_ctx.has(name):
            return self.lookup_ctx.get(name)
        if self.resolver is None:
            return None
        if self._resolved is self._UNSET:
            try:
                self._resolved = self.resolver(self.user, self.tool, self.args)
            except Exception as e:  # noqa: BLE001
                self.failed = True
                raise ContextError(type(e).__name__) from None
        res = self._resolved
        return res.get(name) if hasattr(res, "get") else None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Guard:
    def __init__(self, engine: PolicyEngine, db=None, context_resolver=None, audit_path="audit.jsonl",
                 mode="enforce", approval_handler=None):
        if mode not in MODES:
            raise ValueError("mode must be 'enforce' or 'monitor'")
        self.engine = engine
        self.lookups = engine.policy.get("lookups") if isinstance(engine.policy.get("lookups"), dict) else {}
        self.db, self.context_resolver = db, context_resolver
        self.audit_path = Path(audit_path) if audit_path else None
        self.mode = mode
        self.approval_handler = approval_handler
        self._lock = threading.RLock()
        self._sessions: dict = {}
        self._pending: dict = {}
        self._events: list[dict] = []
        self.audit_errors = 0

    @classmethod
    def from_policy(cls, policy, db=None, context_resolver=None, audit_path="audit.jsonl", mode="enforce",
                    approval_handler=None) -> "Guard":
        """policy: διαδρομή αρχείου ή έτοιμο dict. Πολιτική με errors => ValueError (δεν δουλεύουμε με άκυρη πολιτική)."""
        engine = PolicyEngine(policy) if isinstance(policy, dict) else PolicyEngine.from_file(policy)
        return cls(engine, db, context_resolver, audit_path, mode, approval_handler)

    # ------------------------------------------------------------------ συνεδρίες και taint

    def _session(self, session_id) -> dict:
        with self._lock:
            return self._sessions.setdefault(str(session_id), {"tainted": False})

    def new_turn(self, session_id, user_message: str = "") -> None:
        """Νέο μήνυμα χρήστη: καθαρίζει το taint αυτής της συνεδρίας."""
        self._session(session_id)["tainted"] = False

    def is_tainted(self, session_id) -> bool:
        return bool(self._session(session_id)["tainted"])

    # ------------------------------------------------------------------ audit

    def _audit(self, event: dict) -> None:
        event = {"ts": _now(), **event}
        with self._lock:
            self._events.append(event)
            if self.audit_path is not None:
                try:
                    self.audit_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(self.audit_path, "a", encoding="utf-8", newline="\n") as f:
                        f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
                except OSError:
                    self.audit_errors += 1  # η απόφαση δεν αλλάζει· το σφάλμα καταγράφεται στη μνήμη

    def audit_events(self, session_id=None) -> list[dict]:
        with self._lock:
            return copy.deepcopy([e for e in self._events if session_id is None or e.get("session_id") == str(session_id)])

    @staticmethod
    def _args_text(args) -> str:
        try:
            return json.dumps(args, ensure_ascii=False, default=str)[:ARG_CUT]
        except Exception:  # noqa: BLE001
            return "<unserializable>"[:ARG_CUT]

    # ------------------------------------------------------------------ κύρια λογική

    def _out(self, status, result=None, reason="", rule="", approval_id=None, tainted=False, findings=None, would_be=None) -> dict:
        return {"status": status, "result": result, "reason": reason, "rule": rule, "approval_id": approval_id,
                "tainted": bool(tainted), "findings": list(findings or []), "would_be": would_be}

    def _record(self, session_id, user, tool, args, out, event="call", **extra) -> dict:
        self._audit({"event": event, "session_id": str(session_id),
                     "user_id": user.get("id") if isinstance(user, dict) else None,
                     "user_role": user.get("role") if isinstance(user, dict) else None,
                     "tool": tool, "args": self._args_text(args),
                     "decision": {"ok": "allow", "denied": "deny"}.get(out["status"], out["status"]),
                     "rule": out["rule"], "reason": out["reason"], "tainted": out["tainted"], "mode": self.mode,
                     "would_be": out["would_be"], "findings": [f.get("type") for f in out["findings"]], **extra})
        return out

    def call(self, session_id, user, tool, args, execute) -> dict:
        try:
            return self._call(session_id, user, tool, args, execute)
        except Exception as e:  # noqa: BLE001 - fail-closed: δεν περνά τίποτα αν σπάσει ο ίδιος ο Guard
            out = self._out("error", reason="internal error", rule="guard.error", tainted=self._safe_taint(session_id))
            try:
                self._record(session_id, user, tool, args, out, error=type(e).__name__)
            except Exception:  # noqa: BLE001
                pass
            return out

    def _safe_taint(self, session_id) -> bool:
        try:
            return self.is_tainted(session_id)
        except Exception:  # noqa: BLE001
            return False

    def _call(self, session_id, user, tool, args, execute) -> dict:
        sess = self._session(session_id)
        findings: list = []
        if args is None:
            args = {}
        if not isinstance(user, dict) or "id" not in user or "role" not in user:
            return self._record(session_id, user, tool, args, self._out("denied", reason="invalid user context", rule="guard.invalid_user", tainted=sess["tainted"]))
        if not isinstance(args, dict) or not isinstance(tool, str):
            return self._record(session_id, user, tool, args, self._out("denied", reason="invalid arguments", rule="guard.invalid_args", tainted=sess["tainted"]))
        if not callable(execute):
            return self._record(session_id, user, tool, args, self._out("error", reason="no executor", rule="guard.error", tainted=sess["tainted"]))

        ctx = _CallContext(LookupContext(self.lookups, self.db, user, tool, args, findings), self.context_resolver, user, tool, args)
        decision = self.engine.evaluate(user, tool, args, ctx)                       # (1)+(2)
        if ctx.failed:
            decision = {"action": "deny", "reason": "could not determine the facts needed to authorize this call", "rule": "guard.context_error"}
        monitor = self.mode == "monitor"
        would_be = None
        if decision["action"] != "allow":
            if not monitor:
                return self._record(session_id, user, tool, args, self._out("denied", reason=decision["reason"], rule=decision["rule"],
                                                                            tainted=sess["tainted"], findings=findings))
            would_be = "deny"
        elif tool in self.engine.high_risk_tools and sess["tainted"]:               # (3)
            if monitor:
                would_be = "needs_approval"
            else:
                gate = self._approval_gate(session_id, user, tool, args, execute, findings)
                if gate is not None:
                    return gate
        elif monitor:
            would_be = "allow"
        return self._execute_and_filter(session_id, user, tool, args, execute, ctx, findings, would_be)

    def _approval_gate(self, session_id, user, tool, args, execute, findings):
        """None => εγκρίθηκε επιτόπου (συνεχίζουμε)· αλλιώς το out (denied / needs_approval)."""
        request = {"approval_id": "ap-" + uuid.uuid4().hex[:12], "session_id": str(session_id),
                   "user": {"id": user["id"], "role": user["role"]}, "tool": tool, "args": copy.deepcopy(args),
                   "reason": "high-risk action after untrusted content was read", "created_at": _now()}
        verdict = None
        if self.approval_handler is not None:
            try:
                verdict = self.approval_handler(copy.deepcopy(request))
            except Exception:  # noqa: BLE001
                return self._record(session_id, user, tool, args, self._out("denied", reason="approval could not be obtained",
                                                                            rule="approval.error", tainted=True, findings=findings))
        if verdict is True:
            self._audit({"event": "approval_resolved", "session_id": str(session_id), "approval_id": request["approval_id"],
                         "approved": True, "by": "approval_handler", "tool": tool, "user_id": user["id"]})
            return None
        if verdict is False:
            return self._record(session_id, user, tool, args, self._out("denied", reason="rejected by the approver", rule="approval.rejected",
                                                                        tainted=True, findings=findings), approval_id=request["approval_id"])
        with self._lock:
            self._pending[request["approval_id"]] = dict(request, execute=execute)
        return self._record(session_id, user, tool, args, self._out("needs_approval", reason=request["reason"], rule="taint.high_risk",
                                                                    approval_id=request["approval_id"], tainted=True, findings=findings))

    def _execute_and_filter(self, session_id, user, tool, args, execute, ctx, findings, would_be) -> dict:
        sess = self._session(session_id)
        monitor = self.mode == "monitor"
        try:
            result = execute(user, tool, args)                                          # (4)
        except Exception as e:  # noqa: BLE001
            out = self._out("error", reason="the tool failed", rule="guard.execute_error", tainted=sess["tainted"],
                            findings=findings, would_be=would_be)
            return self._record(session_id, user, tool, args, out, error=type(e).__name__)
        shown = result
        if tool in self.engine.untrusted_tools:                                         # (5)
            sess["tainted"] = True                                                      # πρώτα το taint: fail-closed ακόμα κι αν σπάσει ο sanitizer
            try:
                shown, f, _score = sanitize_result(tool, result, source=tool)
                findings += f
            except Exception as e:  # noqa: BLE001
                out = self._out("error", reason="the result could not be made safe", rule="guard.sanitize_error", tainted=True,
                                findings=findings, would_be=would_be)
                return self._record(session_id, user, tool, args, out, error=type(e).__name__)
        redacted = self.engine.redact(user, tool, args, shown, ctx)                      # (6)
        extra = {}
        if monitor:                                                                     # monitor: δεν αλλάζει το αποτέλεσμα, μόνο καταγράφει
            extra["would_redact"] = redacted != result
            final = result
        else:
            final = redacted
        out = self._out("ok", result=final, tainted=sess["tainted"], findings=findings, would_be=would_be)
        return self._record(session_id, user, tool, args, out, **extra)

    def wrap(self, execute):
        """Επιστρέφει function(session_id, user, tool, args) -> out που περνά κάθε κλήση από τον Guard."""
        def safe_call(session_id, user, tool, args):
            return self.call(session_id, user, tool, args, execute)
        return safe_call

    # ------------------------------------------------------------------ εγκρίσεις

    def pending_approvals(self) -> list[dict]:
        with self._lock:
            return [{k: copy.deepcopy(v) for k, v in item.items() if k != "execute"} | {"status": "pending"}
                    for item in self._pending.values()]

    def resolve_approval(self, approval_id, approved: bool, by: str) -> dict:
        if not isinstance(by, str) or not by.strip():
            return self._out("error", reason="the approver must be named", rule="approval.invalid")
        with self._lock:
            item = self._pending.pop(str(approval_id), None)
        if item is None:
            return self._out("error", reason="unknown or already resolved approval id", rule="approval.unknown")
        user, tool, args, sid = {**item["user"]}, item["tool"], item["args"], item["session_id"]
        self._audit({"event": "approval_resolved", "session_id": sid, "approval_id": item["approval_id"], "approved": bool(approved),
                     "by": by.strip(), "tool": tool, "user_id": user["id"]})
        if approved is not True:
            return self._record(sid, user, tool, args, self._out("denied", reason=f"rejected by {by.strip()}", rule="approval.rejected",
                                                                 approval_id=item["approval_id"], tainted=self.is_tainted(sid)), event="call_after_approval")
        findings: list = []
        ctx = _CallContext(LookupContext(self.lookups, self.db, user, tool, args, findings), self.context_resolver, user, tool, args)
        decision = self.engine.evaluate(user, tool, args, ctx)                          # ξανά έλεγχος πολιτικής τη στιγμή της εκτέλεσης
        if ctx.failed or decision["action"] != "allow":
            rule = "guard.context_error" if ctx.failed else decision["rule"]
            return self._record(sid, user, tool, args, self._out("denied", reason="no longer allowed by the policy", rule=rule,
                                                                 approval_id=item["approval_id"], tainted=self.is_tainted(sid), findings=findings),
                                event="call_after_approval")
        out = self._execute_and_filter(sid, user, tool, args, item["execute"], ctx, findings, None)
        out["approval_id"] = item["approval_id"]
        return out

    # ------------------------------------------------------------------ μήνυμα προς το μοντέλο

    def tool_message(self, out: dict) -> str:
        """Κείμενο ασφαλές για το μοντέλο: καμία εσωτερική λεπτομέρεια (εξαιρέσεις, SQL, ονόματα κανόνων σφάλματος)."""
        status = out.get("status")
        if status == "ok":
            try:
                return json.dumps(out.get("result"), ensure_ascii=False, default=str)
            except Exception:  # noqa: BLE001
                return "The tool result could not be shown."
        if status == "needs_approval":
            return ("This action needs approval from a human. Nothing has been done yet. "
                    "Tell the user. Do not retry and do not look for another way.")
        if status == "denied":
            rule = str(out.get("rule", ""))
            if rule.startswith(("guard.", "policy.internal")):
                return "blocked by policy: this action could not be authorized."
            return f"blocked by policy: {out.get('reason') or 'not allowed'}"
        return "The action failed and no result is available."
