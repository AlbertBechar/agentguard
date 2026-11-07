"""
policy_engine.py -- γενικός, δηλωτικός μηχανισμός πολιτικής (Layer 1).

Ο μηχανισμός ΔΕΝ ξέρει τίποτα για συγκεκριμένη εφαρμογή, βάση δεδομένων ή web framework.
Διαβάζει ένα αρχείο πολιτικής (schema "agentguard-policy/1") και απαντά σε τρία ερωτήματα:
  * evaluate: επιτρέπεται ή όχι η κλήση του εργαλείου;
  * redact:   τι πρέπει να κρυφτεί/αφαιρεθεί από το αποτέλεσμα;
  * validate_policy: είναι σωστό το ίδιο το αρχείο πολιτικής;

Αρχές:
  * Μόνο standard library. Καμία χρήση eval/exec: η πολιτική είναι δεδομένα, όχι κώδικας.
  * Fail-closed: ό,τι λείπει ή σκάει οδηγεί σε άρνηση (evaluate) ή απόκρυψη (redact).
  * Stateless: δεν κρατά taint, εγκρίσεις ή log (αυτά είναι δουλειά του Guard).

Το «context» που περνά ο καλών είναι είτε απλό dict είτε αντικείμενο με μέθοδο .get(name)
που υπολογίζει τα γεγονότα (π.χ. «ποιος είναι ο ιδιοκτήτης») μόνο όταν χρειαστούν (lazy).

Χρήση από γραμμή εντολών:
    python policy_engine.py validate --policy FILE
    python policy_engine.py matrix   --policy FILE
    python policy_engine.py evaluate --policy FILE      (JSON από stdin)
    python policy_engine.py redact   --policy FILE      (JSON από stdin)
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import re
import sys
from pathlib import Path

SCHEMA = "agentguard-policy/1"
REDACTED = "[redacted]"

UNARY_OPS = {"is_true", "is_false", "exists", "not_exists"}
BINARY_OPS = {"equals", "not_equals", "in", "not_in", "subset_of", "contains", "lt", "lte", "gt", "gte"}
ALL_OPS = UNARY_OPS | BINARY_OPS

LOOKUP_RETURNS = {"scalar", "list", "row", "exists"}
FORBIDDEN_SQL_WORDS = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "ATTACH", "DETACH", "PRAGMA",
                       "REPLACE", "VACUUM", "REINDEX", "TRUNCATE", "GRANT", "EXEC", "CALL"]

_MAX_DEPTH = 200  # προστασία από υπερβολικά βαθιά φωλιασμένα αποτελέσματα


# ---------------------------------------------------------------------------
# Τελεστέα και τελεστές
# ---------------------------------------------------------------------------

def _scalar_text(v):
    """Κείμενο για σύγκριση ισότητας (7 == "7", True == 1). None αν δεν είναι απλή τιμή."""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(int(v)) if v.is_integer() else repr(v)
    if isinstance(v, str):
        return v
    return None


def _eq(a, b) -> bool:
    sa, sb = _scalar_text(a), _scalar_text(b)
    if sa is not None and sb is not None:
        return sa == sb
    if a is None or b is None:
        return False
    return a == b


def _num(v):
    """Αριθμός από int/float/αριθμητικό κείμενο. bool και None δεν είναι αριθμοί."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        x = float(v)
    elif isinstance(v, str):
        try:
            x = float(v.strip())
        except ValueError:
            return None
    else:
        return None
    return x if math.isfinite(x) else None


def _is_list(v) -> bool:
    return isinstance(v, (list, tuple, set, frozenset))


def _truthy_flag(v):
    """True/False αν η τιμή είναι «λογική» (bool, 0/1, "true"/"false"), αλλιώς None."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return True if v == 1 else (False if v == 0 else None)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1"):
            return True
        if s in ("false", "0"):
            return False
    return None


def _apply_op(op: str, a, b) -> bool:
    """Εφαρμόζει τελεστή. ΚΑΝΟΝΑΣ fail-closed: τελεστέο None => false (εκτός από exists/not_exists)."""
    if op == "not_exists":
        return a is None
    if op == "exists":
        return a is not None
    if a is None:
        return False
    if op == "is_true":
        return _truthy_flag(a) is True
    if op == "is_false":
        return _truthy_flag(a) is False
    if b is None:
        return False
    if op == "equals":
        return _eq(a, b)
    if op == "not_equals":
        return not _eq(a, b)
    if op == "in":
        return _is_list(b) and any(_eq(a, x) for x in b)
    if op == "not_in":
        return _is_list(b) and not any(_eq(a, x) for x in b)
    if op == "subset_of":
        return _is_list(a) and _is_list(b) and all(any(_eq(x, y) for y in b) for x in a)
    if op == "contains":
        if _is_list(a):
            return any(_eq(x, b) for x in a)
        if isinstance(a, str):
            t = _scalar_text(b)
            return t is not None and t in a
        if isinstance(a, dict):
            return _scalar_text(b) in a
        return False
    if op in ("lt", "lte", "gt", "gte"):
        x, y = _num(a), _num(b)
        if x is None or y is None:
            return False
        return {"lt": x < y, "lte": x <= y, "gt": x > y, "gte": x >= y}[op]
    raise ValueError(f"unknown operator {op!r}")


class _Scope:
    """Τα δεδομένα στα οποία «κοιτάζουν» οι αναφορές $user/$args/$ctx/$row/$item."""

    def __init__(self, user, args, context, row=None, item=None):
        self.user = user if isinstance(user, dict) else {}
        self.args = args if isinstance(args, dict) else {}
        self.context = context
        self.row = row
        self.item = item

    def ctx_get(self, name):
        if self.context is None:
            return None
        return self.context.get(name)


def _dig(value, parts):
    for p in parts:
        if isinstance(value, dict):
            value = value.get(p)
        elif isinstance(value, (list, tuple)) and p.isdigit() and int(p) < len(value):
            value = value[int(p)]
        else:
            return None
    return value


def _resolve(operand, sc: _Scope):
    """Μετατρέπει ένα τελεστέο σε τιμή. Αναφορές: $user.x $args.x $args_keys $ctx.x $row.x $item.x."""
    if isinstance(operand, str) and operand.startswith("$"):
        if operand.startswith("$$"):
            return operand[1:]  # $$abc => σταθερό κείμενο "$abc"
        if operand == "$args_keys":
            return sorted(str(k) for k, v in sc.args.items() if v is not None)
        root, _, rest = operand[1:].partition(".")
        parts = rest.split(".") if rest else []
        if root == "ctx":
            if not parts:
                return None
            return _dig(sc.ctx_get(parts[0]), parts[1:])
        base = {"user": sc.user, "args": sc.args, "row": sc.row, "item": sc.item}.get(root)
        return _dig(base, parts)  # άγνωστη ρίζα => None => false
    return operand


def _eval_condition(cond: dict, sc: _Scope) -> bool:
    op = cond.get("op")
    a = _resolve(cond.get("left"), sc)
    b = _resolve(cond.get("right"), sc) if op in BINARY_OPS else None
    return _apply_op(op, a, b)


def _eval_item(item, sc: _Scope) -> bool:
    if not isinstance(item, dict):
        raise ValueError("invalid condition item")
    if "any_of" in item:
        return any(_eval_items(group, sc) for group in item["any_of"])
    if "not" in item:
        inner = item["not"]
        return not (_eval_items(inner, sc) if isinstance(inner, list) else _eval_item(inner, sc))
    return _eval_condition(item, sc)


def _eval_items(items, sc: _Scope) -> bool:
    """Λίστα στοιχείων = AND (με short-circuit, ώστε το lazy context να ρωτιέται όσο λιγότερο γίνεται)."""
    for it in items:
        if not _eval_item(it, sc):
            return False
    return True


def _eval_groups(groups, sc: _Scope) -> bool:
    """Λίστα ομάδων: OR ανάμεσα στις ομάδες, AND μέσα σε κάθε ομάδα (visible_if / drop_if)."""
    return any(_eval_items(g, sc) for g in groups)


def _matches(entry: dict, tool: str, role) -> bool:
    tools = entry.get("tools", ["*"])
    roles = entry.get("roles", ["*"])
    return ("*" in tools or tool in tools) and ("*" in roles or role in roles)


# ---------------------------------------------------------------------------
# Ο μηχανισμός
# ---------------------------------------------------------------------------

class PolicyEngine:
    def __init__(self, policy: dict):
        problems = [p for p in validate_policy(policy) if p["level"] == "error"]
        if problems:
            text = "; ".join(f'{p["path"] or "<root>"}: {p["message"]}' for p in problems[:10])
            raise ValueError("invalid policy: " + text)
        self.policy = copy.deepcopy(policy)
        self.roles: list = list(self.policy["roles"])
        self.untrusted_tools: set = set(self.policy.get("untrusted_tools", []))
        self.high_risk_tools: set = set(self.policy.get("high_risk_tools", []))
        self.default_action: str = self.policy.get("default_action", "deny")
        self._rules: list = self.policy["rules"]
        self._redaction: dict = self.policy.get("redaction_rules", {}) or {}
        self._tools: set = set(self.tools())

    @classmethod
    def from_file(cls, path) -> "PolicyEngine":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    # --- εργαλεία / ρόλοι --------------------------------------------------

    def tools(self) -> list[str]:
        """Ταξινομημένη λίστα εργαλείων που αναφέρονται σε κανόνες ή λίστες."""
        names = set(self.policy.get("untrusted_tools", [])) | set(self.policy.get("high_risk_tools", []))
        for r in self.policy.get("rules", []):
            names.update(t for t in r.get("tools", []) if t != "*")
        return sorted(names)

    def matrix(self) -> dict:
        """Στατικός πίνακα {tool: {role: allow|conditional|deny}} από τους κανόνες, χωρίς context."""
        out = {}
        for tool in self.tools():
            out[tool] = {}
            for role in self.roles:
                rules = [r for r in self._rules if _matches(r, tool, role)]
                if any(r["effect"] == "deny" and not r.get("when") for r in rules):
                    label = "deny"
                elif any(r["effect"] == "allow" and not r.get("when") for r in rules):
                    label = "allow"
                elif any(r["effect"] == "allow" and r.get("when") for r in rules):
                    label = "conditional"
                else:
                    label = "deny"
                out[tool][role] = label
        return out

    # --- απόφαση -----------------------------------------------------------

    def _decide(self, user, tool, args, context, matched=None) -> dict:
        if not isinstance(user, dict) or "role" not in user or "id" not in user:
            return {"action": "deny", "reason": "Invalid user context", "rule": "security.invalid_user"}
        role = user["role"]
        if role not in self.roles:
            return {"action": "deny", "reason": "Unknown role", "rule": "security.unknown_role"}
        if tool not in self._tools:
            return {"action": "deny", "reason": f"Unknown tool: {tool}", "rule": "security.unknown_tool"}
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return {"action": "deny", "reason": "Invalid arguments", "rule": "security.invalid_args"}

        sc = _Scope(user, args, context)
        candidates = [r for r in self._rules if _matches(r, tool, role)]

        def fired(rule) -> bool:
            return _eval_items(rule.get("when") or [], sc)

        decision = None
        # 1) deny-overrides: κάθε deny κανόνας που ισχύει νικά, με σειρά εμφάνισης στο αρχείο
        for r in candidates:
            if r["effect"] == "deny" and fired(r):
                if matched is not None:
                    matched.append(r["id"])
                if decision is None:
                    decision = {"action": "deny", "reason": r.get("reason", ""), "rule": r["id"]}
                if matched is None:
                    return decision
        # 2) αλλιώς, ο πρώτος allow που ισχύει
        for r in candidates:
            if r["effect"] == "allow" and fired(r):
                if matched is not None:
                    matched.append(r["id"])
                if decision is None:
                    decision = {"action": "allow", "reason": r.get("reason", ""), "rule": r["id"]}
                if matched is None:
                    return decision
        if decision is not None:
            return decision
        # 3) αλλιώς η προεπιλογή (deny)
        return {"action": self.default_action, "reason": "no rule allows this call", "rule": "default"}

    def evaluate(self, user: dict, tool: str, args: dict, context) -> dict:
        try:
            return self._decide(user, tool, args, context)
        except Exception:  # fail-closed
            return {"action": "deny", "reason": "internal error", "rule": "policy.internal_error"}

    def explain(self, user: dict, tool: str, args: dict, context) -> dict:
        matched: list = []
        try:
            out = self._decide(user, tool, args, context, matched)
        except Exception:
            out = {"action": "deny", "reason": "internal error", "rule": "policy.internal_error"}
            matched = []
        out = dict(out)
        out["matched_rules"] = matched
        return out

    # --- redaction ---------------------------------------------------------

    def redact(self, user: dict, tool: str, args: dict, result, context):
        try:
            return self._redact(user, tool, args, result, context)
        except Exception:  # fail-closed: κρύβουμε ολόκληρο το αποτέλεσμα
            return REDACTED

    def _redact(self, user, tool, args, result, context):
        if result is None or isinstance(result, (str, int, float, bool)):
            return result
        if not isinstance(result, (dict, list, tuple)):
            return result  # άγνωστο σχήμα: δεν σκάμε
        role = user.get("role") if isinstance(user, dict) else None
        result = copy.deepcopy(result)
        base = _Scope(user, args, context)

        # 1) row_filters
        for flt in self._redaction.get("row_filters", []) or []:
            if _matches(flt, tool, role):
                result = self._apply_row_filter(result, flt, base)

        # 2+3) always_redact_fields και restricted_fields (αναδρομικά)
        always = {str(f).lower() for f in self._redaction.get("always_redact_fields", []) or []}
        restricted = [e for e in self._redaction.get("restricted_fields", []) or [] if _matches(e, tool, role)]
        return self._walk(result, base, always, restricted, 0)

    def _apply_row_filter(self, result, flt, base: _Scope):
        groups = flt.get("drop_if") or []

        def drop(x) -> bool:
            return _eval_groups(groups, _Scope(base.user, base.args, base.context, item=x))

        def filter_target(t):
            if isinstance(t, list):
                return [x for x in t if not drop(x)]
            if isinstance(t, dict):
                return {"error": "not found"} if drop(t) else t
            return t

        path = flt.get("result_path")
        if path is None:
            return filter_target(result)
        parts = str(path).split(".")
        node = result
        for p in parts[:-1]:
            if not isinstance(node, dict) or p not in node:
                return result
            node = node[p]
        if isinstance(node, dict) and parts[-1] in node:
            node[parts[-1]] = filter_target(node[parts[-1]])
        return result

    def _walk(self, value, base: _Scope, always: set, restricted: list, depth: int):
        if depth > _MAX_DEPTH:
            raise ValueError("result too deeply nested")
        if isinstance(value, dict):
            row_scope = _Scope(base.user, base.args, base.context, row=value)
            out = {}
            for k, v in value.items():
                lk = str(k).lower()
                hide = lk in always
                if not hide:
                    for e in restricted:
                        if any(lk == str(f).lower() for f in e.get("fields", [])):
                            if not _eval_groups(e.get("visible_if") or [], row_scope):
                                hide = True
                                break
                out[k] = REDACTED if hide else self._walk(v, base, always, restricted, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            return [self._walk(x, base, always, restricted, depth + 1) for x in value]
        return value


# ---------------------------------------------------------------------------
# Έλεγχος του αρχείου πολιτικής
# ---------------------------------------------------------------------------

_REF_RE = re.compile(r"^\$([A-Za-z_]+)(?:\.(.+))?$")
_PARAM_REF_RE = re.compile(r"^\$(user|args)\.[A-Za-z_][A-Za-z0-9_]*$")
_PLACEHOLDER_RE = re.compile(r"(?<![:\w]):([A-Za-z_][A-Za-z0-9_]*)")


def _issue(out, level, path, message):
    out.append({"level": level, "path": path, "message": message})


def _check_operand(value, path, roots, out):
    if isinstance(value, str) and value.startswith("$") and not value.startswith("$$"):
        m = _REF_RE.match(value)
        root = m.group(1) if m else None
        if root is None or root not in roots:
            _issue(out, "error", path, f"άγνωστη ρίζα αναφοράς {value!r} (επιτρέπονται: "
                                       + ", ".join("$" + r for r in sorted(roots)) + ")")
        elif root == "args_keys" and m.group(2):
            _issue(out, "error", path, "το $args_keys δεν παίρνει πεδίο")
        elif root != "args_keys" and not m.group(2):
            _issue(out, "error", path, f"η αναφορά {value!r} θέλει πεδίο, π.χ. ${root}.όνομα")
    elif isinstance(value, dict):
        _issue(out, "error", path, "το τελεστέο δεν μπορεί να είναι αντικείμενο")


def _check_items(items, path, roots, out):
    if not isinstance(items, list):
        _issue(out, "error", path, "πρέπει να είναι λίστα στοιχείων")
        return
    for i, it in enumerate(items):
        _check_item(it, f"{path}[{i}]", roots, out)


def _check_item(it, path, roots, out):
    if not isinstance(it, dict):
        _issue(out, "error", path, "το στοιχείο συνθήκης πρέπει να είναι αντικείμενο")
        return
    if "any_of" in it:
        groups = it["any_of"]
        if not isinstance(groups, list) or not all(isinstance(g, list) for g in groups):
            _issue(out, "error", f"{path}.any_of", "το any_of θέλει λίστα από λίστες στοιχείων")
            return
        for gi, g in enumerate(groups):
            _check_items(g, f"{path}.any_of[{gi}]", roots, out)
        return
    if "not" in it:
        inner = it["not"]
        if isinstance(inner, list):
            _check_items(inner, f"{path}.not", roots, out)
        else:
            _check_item(inner, f"{path}.not", roots, out)
        return
    op = it.get("op")
    if op not in ALL_OPS:
        _issue(out, "error", f"{path}.op", f"άγνωστος τελεστής {op!r}")
        return
    if "left" not in it:
        _issue(out, "error", f"{path}.left", "λείπει το αριστερό τελεστέο (left)")
    else:
        _check_operand(it["left"], f"{path}.left", roots, out)
    if op in BINARY_OPS:
        if "right" not in it:
            _issue(out, "error", f"{path}.right", f"ο τελεστής {op} θέλει δεξί τελεστέο (right)")
        else:
            _check_operand(it["right"], f"{path}.right", roots, out)


def _check_groups(groups, path, roots, out):
    if not isinstance(groups, list) or not all(isinstance(g, list) for g in groups):
        _issue(out, "error", path, "πρέπει να είναι λίστα από ομάδες (κάθε ομάδα είναι λίστα συνθηκών)")
        return
    for gi, g in enumerate(groups):
        _check_items(g, f"{path}[{gi}]", roots, out)


def _str_list(value, path, out, allow_star=False):
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        _issue(out, "error", path, "πρέπει να είναι λίστα από μη κενά κείμενα")
        return False
    return True


def _collect_ctx_refs(node, found: set):
    """Βρίσκει όλα τα ονόματα $ctx.<όνομα> που χρησιμοποιεί η πολιτική."""
    if isinstance(node, str):
        if node.startswith("$ctx."):
            found.add(node[5:].split(".")[0])
    elif isinstance(node, dict):
        for v in node.values():
            _collect_ctx_refs(v, found)
    elif isinstance(node, list):
        for v in node:
            _collect_ctx_refs(v, found)


def _check_lookups(lookups, out):
    if not isinstance(lookups, dict):
        _issue(out, "error", "lookups", "το lookups πρέπει να είναι αντικείμενο {όνομα: ορισμός}")
        return
    for name, lk in lookups.items():
        p = f"lookups.{name}"
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(name)):
            _issue(out, "error", p, "το όνομα του lookup πρέπει να είναι αναγνωριστικό (γράμματα, αριθμοί, _)")
        if not isinstance(lk, dict):
            _issue(out, "error", p, "ο ορισμός του lookup πρέπει να είναι αντικείμενο")
            continue
        if lk.get("returns") not in LOOKUP_RETURNS:
            _issue(out, "error", f"{p}.returns", "το returns πρέπει να είναι scalar, list, row ή exists")
        params = lk.get("params", {})
        if not isinstance(params, dict):
            _issue(out, "error", f"{p}.params", "το params πρέπει να είναι αντικείμενο {παράμετρος: αναφορά}")
            params = {}
        for pname, ref in params.items():
            if not (isinstance(ref, str) and _PARAM_REF_RE.match(ref)):
                _issue(out, "error", f"{p}.params.{pname}",
                       "επιτρέπονται μόνο αναφορές $user.<πεδίο> ή $args.<πεδίο>")
        sql = lk.get("sql")
        if not isinstance(sql, str) or not sql.strip():
            _issue(out, "error", f"{p}.sql", "λείπει το SQL")
            continue
        s = sql.strip()
        if not re.match(r"(?i)^select\b", s):
            _issue(out, "error", f"{p}.sql", "το SQL πρέπει να ξεκινά με SELECT")
        if ";" in s:
            _issue(out, "error", f"{p}.sql", "απαγορεύεται το ';' (μόνο ένα statement)")
        if "--" in s or "/*" in s or "*/" in s:
            _issue(out, "error", f"{p}.sql", "απαγορεύονται τα σχόλια (-- και /* */)")
        for word in FORBIDDEN_SQL_WORDS:
            if re.search(rf"(?i)\b{word}\b", s):
                _issue(out, "error", f"{p}.sql", f"απαγορευμένη λέξη {word} (επιτρέπεται μόνο ανάγνωση)")
        if "?" in s or re.search(r"%s|%\(|\$\d+", s):
            _issue(out, "error", f"{p}.sql", "επιτρέπονται μόνο επώνυμες παράμετροι :όνομα (όχι ?, %s, $1)")
        no_literals = re.sub(r"'(?:[^']|'')*'", "''", s)
        placeholders = set(_PLACEHOLDER_RE.findall(no_literals))
        for ph in sorted(placeholders - set(params)):
            _issue(out, "error", f"{p}.sql", f"η παράμετρος :{ph} δεν έχει καταχώρηση στο params")
        for pn in sorted(set(params) - placeholders):
            _issue(out, "error", f"{p}.params.{pn}", f"η παράμετρος {pn} δεν χρησιμοποιείται στο SQL")


def validate_policy(policy: dict) -> list[dict]:
    """Επιστρέφει λίστα [{"level","path","message"}]. Κενή λίστα = εντάξει."""
    out: list = []
    if not isinstance(policy, dict):
        _issue(out, "error", "", "η πολιτική πρέπει να είναι αντικείμενο JSON")
        return out
    if policy.get("schema") != SCHEMA:
        _issue(out, "error", "schema", f"το schema πρέπει να είναι {SCHEMA!r}")
    for key in ("roles", "rules"):
        if key not in policy:
            _issue(out, "error", key, f"λείπει το κλειδί {key!r}")
    da = policy.get("default_action", "deny")
    if da not in ("deny", "allow"):
        _issue(out, "error", "default_action", "το default_action πρέπει να είναι deny ή allow")
    elif da == "allow":
        _issue(out, "warning", "default_action", "το default_action=allow επιτρέπει ό,τι δεν απαγορεύεται ρητά (επικίνδυνο)")

    roles = policy.get("roles")
    role_set: set = set()
    if "roles" in policy:
        if _str_list(roles, "roles", out):
            role_set = set(roles)
            if len(role_set) != len(roles):
                _issue(out, "error", "roles", "υπάρχουν διπλοί ρόλοι")
            if "*" in role_set:
                _issue(out, "error", "roles", "το '*' δεν μπορεί να είναι όνομα ρόλου")

    for key in ("untrusted_tools", "high_risk_tools"):
        if key in policy:
            _str_list(policy[key], key, out)
    untrusted = policy.get("untrusted_tools", []) if isinstance(policy.get("untrusted_tools"), list) else []
    high_risk = policy.get("high_risk_tools", []) if isinstance(policy.get("high_risk_tools"), list) else []
    if not untrusted:
        _issue(out, "warning", "untrusted_tools", "δεν ορίζεται κανένα untrusted εργαλείο: δεν θα γίνεται ποτέ taint")

    # --- rules
    rules = policy.get("rules")
    rule_tools: set = set()
    seen_ids: dict = {}
    allow_tools: set = set()
    when_roots = {"user", "args", "args_keys", "ctx"}
    if isinstance(rules, list):
        for i, r in enumerate(rules):
            p = f"rules[{i}]"
            if not isinstance(r, dict):
                _issue(out, "error", p, "ο κανόνας πρέπει να είναι αντικείμενο")
                continue
            rid = r.get("id")
            if not isinstance(rid, str) or not rid:
                _issue(out, "error", f"{p}.id", "λείπει το id του κανόνα")
            elif rid in seen_ids:
                _issue(out, "warning", f"{p}.id", f"διπλό id κανόνα {rid!r} (πρώτη εμφάνιση: rules[{seen_ids[rid]}])")
            else:
                seen_ids[rid] = i
            tools = r.get("tools")
            if "tools" not in r or not _str_list(tools, f"{p}.tools", out):
                if "tools" not in r:
                    _issue(out, "error", f"{p}.tools", "λείπει το tools")
                tools = []
            rule_tools.update(t for t in tools if t != "*")
            rroles = r.get("roles", ["*"])
            if not _str_list(rroles, f"{p}.roles", out):
                rroles = []
            for ro in rroles:
                if ro != "*" and role_set and ro not in role_set:
                    _issue(out, "error", f"{p}.roles", f"ο ρόλος {ro!r} δεν υπάρχει στα roles")
            effect = r.get("effect")
            if effect not in ("allow", "deny"):
                _issue(out, "error", f"{p}.effect", "το effect πρέπει να είναι allow ή deny")
            if "when" in r:
                _check_items(r["when"], f"{p}.when", when_roots, out)
            if effect == "allow":
                allow_tools.update(tools)
                if "*" in rroles and not r.get("when"):
                    hr = [t for t in tools if t in high_risk or t == "*"]
                    if hr:
                        _issue(out, "warning", p, "κανόνας allow για όλους τους ρόλους και χωρίς when σε εργαλείο υψηλού ρίσκου")
    elif "rules" in policy:
        _issue(out, "error", "rules", "το rules πρέπει να είναι λίστα")

    for t in high_risk:
        if t not in allow_tools and "*" not in allow_tools:
            _issue(out, "warning", "high_risk_tools", f"το εργαλείο υψηλού ρίσκου {t!r} δεν έχει κανέναν κανόνα allow")

    # --- redaction_rules
    red = policy.get("redaction_rules", {})
    redaction_tools: set = set()
    if red is not None and not isinstance(red, dict):
        _issue(out, "error", "redaction_rules", "το redaction_rules πρέπει να είναι αντικείμενο")
    elif isinstance(red, dict):
        if "always_redact_fields" in red:
            _str_list(red["always_redact_fields"], "redaction_rules.always_redact_fields", out)
        for kind, root_set in (("restricted_fields", when_roots | {"row"}), ("row_filters", when_roots | {"item"})):
            entries = red.get(kind, [])
            if not isinstance(entries, list):
                _issue(out, "error", f"redaction_rules.{kind}", "πρέπει να είναι λίστα")
                continue
            for i, e in enumerate(entries):
                p = f"redaction_rules.{kind}[{i}]"
                if not isinstance(e, dict):
                    _issue(out, "error", p, "η καταχώρηση πρέπει να είναι αντικείμενο")
                    continue
                for lk in ("tools", "roles"):
                    if lk in e and _str_list(e[lk], f"{p}.{lk}", out):
                        if lk == "tools":
                            redaction_tools.update(t for t in e[lk] if t != "*")
                        else:
                            for ro in e[lk]:
                                if ro != "*" and role_set and ro not in role_set:
                                    _issue(out, "error", f"{p}.roles", f"ο ρόλος {ro!r} δεν υπάρχει στα roles")
                if kind == "restricted_fields":
                    if "fields" not in e:
                        _issue(out, "error", f"{p}.fields", "λείπει το fields")
                    else:
                        _str_list(e["fields"], f"{p}.fields", out)
                    if "visible_if" in e:
                        _check_groups(e["visible_if"], f"{p}.visible_if", root_set, out)
                else:
                    rp = e.get("result_path")
                    if rp is not None and not (isinstance(rp, str) and rp):
                        _issue(out, "error", f"{p}.result_path", "το result_path πρέπει να είναι null ή κείμενο")
                    if "drop_if" not in e:
                        _issue(out, "error", f"{p}.drop_if", "λείπει το drop_if")
                    else:
                        _check_groups(e["drop_if"], f"{p}.drop_if", root_set, out)

    for t in sorted((set(untrusted) | set(high_risk) | redaction_tools) - rule_tools):
        _issue(out, "warning", "rules", f"το εργαλείο {t!r} αναφέρεται αλλού αλλά σε κανέναν κανόνα (θα απορρίπτεται)")

    # --- lookups και $ctx
    lookups = policy.get("lookups")
    if "lookups" in policy:
        _check_lookups(lookups, out)
    lookup_names = set(lookups) if isinstance(lookups, dict) else set()
    meta = policy.get("meta")
    declared = set()
    if isinstance(meta, dict) and isinstance(meta.get("context_attributes"), dict):
        declared = set(meta["context_attributes"])
    used: set = set()
    _collect_ctx_refs(policy.get("rules", []), used)
    _collect_ctx_refs(policy.get("redaction_rules", {}), used)
    for name in sorted(used - lookup_names - declared):
        _issue(out, "warning", "meta.context_attributes",
               f"το $ctx.{name} δεν έχει ούτε lookups.{name} ούτε meta.context_attributes.{name}")
    for name in sorted(lookup_names - used):
        _issue(out, "warning", f"lookups.{name}", "το lookup δεν χρησιμοποιείται από κανέναν κανόνα")
    return out


# ---------------------------------------------------------------------------
# Γραμμή εντολών (χωρίς HTTP)
# ---------------------------------------------------------------------------

def _emit(obj) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _read_stdin_json() -> dict:
    data = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("το JSON εισόδου πρέπει να είναι αντικείμενο")
    return data


def _format_matrix(engine: PolicyEngine) -> str:
    m = engine.matrix()
    w = max([len("tool")] + [len(t) for t in m]) + 2
    cw = max([len(r) for r in engine.roles] + [len("conditional")]) + 2
    lines = ["tool".ljust(w) + "".join(r.ljust(cw) for r in engine.roles)]
    lines.append("-" * (w + cw * len(engine.roles)))
    for t in m:
        lines.append(t.ljust(w) + "".join(m[t][r].ljust(cw) for r in engine.roles))
    return "\n".join(lines)


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(prog="policy_engine", description="AgentGuard policy engine")
    parser.add_argument("command", choices=["validate", "matrix", "evaluate", "redact"])
    parser.add_argument("--policy", required=True, help="αρχείο πολιτικής (JSON)")
    ns = parser.parse_args(argv)

    try:
        if ns.command == "validate":
            with open(ns.policy, "r", encoding="utf-8") as f:
                issues = validate_policy(json.load(f))
            for it in issues:
                tag = "[FAIL]" if it["level"] == "error" else "[WARN]"
                print(f'{tag} {it["path"] or "<root>"}: {it["message"]}')
            errors = sum(1 for i in issues if i["level"] == "error")
            if errors:
                print(f"[FAIL] {errors} errors, {len(issues) - errors} warnings")
                return 1
            print(f"[OK] policy valid ({len(issues)} warnings)")
            return 0
        engine = PolicyEngine.from_file(ns.policy)
        if ns.command == "matrix":
            print(_format_matrix(engine))
            return 0
        data = _read_stdin_json()
        for key in ("user", "tool"):
            if key not in data:
                raise ValueError(f"λείπει το κλειδί {key!r}")
        if ns.command == "evaluate":
            _emit(engine.evaluate(data.get("user"), data.get("tool"), data.get("args") or {}, data.get("context") or {}))
            return 0
        if "result" not in data:
            raise ValueError("λείπει το κλειδί 'result'")
        _emit(engine.redact(data.get("user"), data.get("tool"), data.get("args") or {}, data["result"],
                            data.get("context") or {}))
        return 0
    except Exception as e:  # κάθε σφάλμα => JSON error και exit code != 0, ποτέ allow
        _emit({"error": f"{type(e).__name__}: {e}"})
        return 2


if __name__ == "__main__":
    sys.exit(main())
