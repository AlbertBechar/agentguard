"""
copilot/tooldefs.py -- ανάγνωση ορισμών εργαλείων από 5 μορφές (καθαρό parsing, δεν εκτελεί τίποτα).

Μορφές: (list) απλή λίστα, (gemini) function_declarations, (openai) {"type":"function",...},
(mcp) {"name","inputSchema"}, (openapi) OpenAPI 3 με "paths".

Έξοδος: λίστα από
    {"name", "description", "params": {pname: {"type", "description", "required"}},
     "source_format", "http_method" | None}
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")


class ToolDefError(ValueError):
    """Σφάλμα στην είσοδο ορισμών εργαλείων (το μήνυμα είναι στα ελληνικά)."""


# ---------------------------------------------------------------------------
# Βοηθητικά
# ---------------------------------------------------------------------------

def _read_source(source):
    """Διαδρομή αρχείου JSON, κείμενο JSON ή έτοιμο αντικείμενο -> αντικείμενο Python."""
    if isinstance(source, (list, dict)):
        return source
    if isinstance(source, Path) or (isinstance(source, str) and not source.lstrip().startswith(("[", "{"))):
        path = Path(source)
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise ToolDefError(f"Δεν βρέθηκε το αρχείο εργαλείων: {path}") from None
        except OSError as e:
            raise ToolDefError(f"Δεν διαβάζεται το αρχείο εργαλείων {path}: {e}") from None
    elif isinstance(source, str):
        text = source
    else:
        raise ToolDefError("Η είσοδος εργαλείων πρέπει να είναι διαδρομή αρχείου JSON ή αντικείμενο (λίστα/λεξικό).")
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ToolDefError(f"Το JSON των εργαλείων είναι χαλασμένο (γραμμή {e.lineno}, στήλη {e.colno}): {e.msg}") from None


def _lower_type(t) -> str:
    if isinstance(t, list):  # JSON Schema: ["string", "null"]
        t = next((x for x in t if x != "null"), "string")
    return str(t).lower() if t else "string"


def _resolve_ref(schema, root, depth=0):
    """Λύνει απλά τοπικά $ref ("#/components/schemas/X"). Άλλα $ref μένουν ως έχουν."""
    if not isinstance(schema, dict) or depth > 8:
        return schema
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/") and isinstance(root, dict):
        node = root
        for part in ref[2:].split("/"):
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, dict):
            return _resolve_ref(node, root, depth + 1)
    return schema


def _params_from_schema(schema, root=None) -> dict:
    """JSON Schema (ή Gemini schema με κεφαλαία τύπους) -> {pname: {type, description, required}}."""
    schema = _resolve_ref(schema, root)
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    if not isinstance(props, dict):
        # επίπεδο λεξικό {pname: {...}} (απλή μορφή)
        props = {k: v for k, v in schema.items() if isinstance(v, dict) and k not in ("type", "required", "description")}
    required = schema.get("required") if isinstance(schema.get("required"), list) else []
    out = {}
    for pname, spec in props.items():
        spec = _resolve_ref(spec, root)
        spec = spec if isinstance(spec, dict) else {}
        out[str(pname)] = {
            "type": _lower_type(spec.get("type")),
            "description": str(spec.get("description") or ""),
            "required": pname in required or spec.get("required") is True,
        }
    return out


def _name_of(item, where) -> str:
    name = item.get("name") if isinstance(item, dict) else None
    if not isinstance(name, str) or not name.strip():
        raise ToolDefError(f"Εργαλείο χωρίς όνομα ({where}).")
    return name.strip()


# ---------------------------------------------------------------------------
# Μετατροπείς ανά μορφή
# ---------------------------------------------------------------------------

def _from_plain(item, where, fmt="list"):
    name = _name_of(item, where)
    schema = item.get("parameters", item.get("params", item.get("inputSchema", {})))
    return {"name": name, "description": str(item.get("description") or ""),
            "params": _params_from_schema(schema), "source_format": fmt, "http_method": None}


def _from_openai(item, where):
    fn = item.get("function")
    if not isinstance(fn, dict):
        raise ToolDefError(f"Εργαλείο OpenAI χωρίς «function» ({where}).")
    t = _from_plain(fn, where, "openai")
    return t


def _from_mcp(item, where):
    return _from_plain(item, where, "mcp")


def _from_gemini(item, where):
    return _from_plain(item, where, "gemini")


def _openapi_tools(doc) -> list[dict]:
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ToolDefError("Το OpenAPI δεν έχει «paths».")
    tools = []
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        shared = ops.get("parameters") if isinstance(ops.get("parameters"), list) else []
        for method in _HTTP_METHODS:
            op = ops.get(method)
            if not isinstance(op, dict):
                continue
            name = op.get("operationId") or f"{method}_{re.sub(r'[^A-Za-z0-9]+', '_', path).strip('_')}"
            summary, desc = str(op.get("summary") or ""), str(op.get("description") or "")
            params = {}
            for p in list(shared) + list(op.get("parameters") or []):
                p = _resolve_ref(p, doc)
                if isinstance(p, dict) and p.get("name"):
                    sch = _resolve_ref(p.get("schema") or {}, doc)
                    params[str(p["name"])] = {"type": _lower_type((sch or {}).get("type")),
                                              "description": str(p.get("description") or ""),
                                              "required": bool(p.get("required"))}
            body = _resolve_ref(op.get("requestBody") or {}, doc)
            content = (body.get("content") or {}) if isinstance(body, dict) else {}
            for ctype in ("application/json", *content.keys()):
                if isinstance(content.get(ctype), dict):
                    params.update(_params_from_schema(content[ctype].get("schema") or {}, doc))
                    break
            tools.append({"name": str(name), "description": " — ".join(x for x in (summary, desc) if x),
                          "params": params, "source_format": "openapi", "http_method": method.upper()})
    if not tools:
        raise ToolDefError("Το OpenAPI δεν περιέχει καμία λειτουργία (get/post/...).")
    return tools


def _detect(item) -> str:
    if not isinstance(item, dict):
        raise ToolDefError("Κάθε εργαλείο πρέπει να είναι αντικείμενο JSON.")
    if "function_declarations" in item or "functionDeclarations" in item:
        return "gemini_group"
    if item.get("type") == "function" and "function" in item:
        return "openai"
    if "inputSchema" in item:
        return "mcp"
    if "name" in item:
        return "list"
    raise ToolDefError("Άγνωστη μορφή εργαλείου: δεν υπάρχει «name», «function» ή «function_declarations».")


def load_tools(source) -> list[dict]:
    """Φορτώνει και κανονικοποιεί ορισμούς εργαλείων. Σφάλμα -> ToolDefError (ελληνικό μήνυμα)."""
    data = _read_source(source)
    if isinstance(data, dict):
        if "openapi" in data or "swagger" in data:
            return _check_dupes(_openapi_tools(data))
        if "paths" in data and "info" in data:
            return _check_dupes(_openapi_tools(data))
        for key in ("function_declarations", "functionDeclarations", "tools"):
            if key in data and isinstance(data[key], list):
                data = [{"function_declarations": data[key]}] if key != "tools" else data[key]
                break
        else:
            raise ToolDefError("Άγνωστη μορφή: περίμενα λίστα εργαλείων, «function_declarations», «tools» ή OpenAPI.")
    if not isinstance(data, list):
        raise ToolDefError("Η είσοδος εργαλείων πρέπει να είναι λίστα ή αντικείμενο.")
    if not data:
        raise ToolDefError("Η λίστα εργαλείων είναι κενή.")
    tools = []
    for i, item in enumerate(data):
        kind = _detect(item)
        where = f"θέση {i}"
        if kind == "gemini_group":
            decls = item.get("function_declarations", item.get("functionDeclarations"))
            if not isinstance(decls, list):
                raise ToolDefError(f"Το «function_declarations» ({where}) πρέπει να είναι λίστα.")
            tools.extend(_from_gemini(d if isinstance(d, dict) else {}, f"{where}/function_declarations") for d in decls)
        elif kind == "openai":
            tools.append(_from_openai(item, where))
        elif kind == "mcp":
            tools.append(_from_mcp(item, where))
        else:
            # {"name","description","parameters"}: αν οι τύποι είναι κεφαλαία (OBJECT/STRING) είναι Gemini
            fmt = "gemini" if str((item.get("parameters") or {}).get("type", "")).isupper() else "list"
            tools.append(_from_plain(item, where, fmt))
    if not tools:
        raise ToolDefError("Δεν βρέθηκε κανένα εργαλείο.")
    return _check_dupes(tools)


def _check_dupes(tools):
    seen = set()
    for t in tools:
        if t["name"] in seen:
            raise ToolDefError(f"Διπλό όνομα εργαλείου: {t['name']!r}.")
        seen.add(t["name"])
    return tools
