# Policy file format: schema "agentguard-policy/1" (condensed)

A policy is ONE JSON object. Output only valid JSON.

```
{
  "schema": "agentguard-policy/1",
  "app": "<short app name>",
  "default_action": "deny",
  "meta": {"context_attributes": {"<name>": "<what it means>"}},
  "roles": ["role1", "role2"],
  "untrusted_tools": ["tools that return text written by third parties"],
  "high_risk_tools": ["tools that change data or send data out"],
  "lookups": { "<ctx name>": {"description": "...", "sql": "SELECT ... WHERE id = :p",
                              "params": {"p": "$args.field"}, "returns": "scalar|list|row|exists"} },
  "rules": [ {"id": "unique.id", "tools": ["tool"], "roles": ["role"], "effect": "allow|deny",
              "when": [ <conditions, ALL must hold> ], "reason": "short human reason"} ],
  "redaction_rules": {
    "always_redact_fields": ["field hidden from everyone"],
    "restricted_fields": [ {"id": "x", "fields": ["f"], "tools": ["optional"], "roles": ["optional"],
                            "visible_if": [ [<conditions AND>], [<conditions AND>] ]} ],
    "row_filters": [ {"id": "y", "tools": ["tool"], "roles": ["role"], "result_path": null,
                      "drop_if": [ [<conditions AND>] ]} ]
  }
}
```

## Rules
- `tools` / `roles` are lists or `["*"]`. Any matching `deny` rule whose `when` holds wins (deny overrides).
  Otherwise any matching `allow` whose `when` holds allows. Otherwise the call is denied (`default_action`).
- A rule without `when` always applies. Give every `allow` rule for a write/external tool a `when` whenever an
  ownership or limit condition exists.

## Conditions
`{"left": <operand>, "op": <operator>, "right": <operand>}` (no `right` for the unary operators).
- Operators: `equals`, `not_equals`, `in`, `not_in`, `subset_of`, `contains`, `lt`, `lte`, `gt`, `gte`,
  `is_true`, `is_false`, `exists`, `not_exists`.
- Operand: a constant (text, number, true/false, list) or a reference starting with `$`:
  `$user.<field>` (the caller, always has `id` and `role`), `$args.<field>` (tool arguments),
  `$args_keys` (list of the argument names that are not null), `$ctx.<name>` (a fact about the call).
  In redaction also `$row.<field>` (the record containing the field) and `$item.<field>` (the list element).
  A constant text starting with `$` is written `$$...`.
- Any comparison with a missing (null) value is FALSE, including `not_equals`, `not_in`, `is_false`
  (only `not_exists` is true for null). So a missing fact makes an `allow` rule fail: the call is denied.
- `when` is a list (all items must hold). An item may be a condition, `{"any_of": [[...], [...]]}`
  (OR between groups, AND inside a group) or `{"not": <item>}`.
- `7` equals `"7"`; `true` equals `1`. `lt/lte/gt/gte` need numbers (or numeric text).

## Facts ($ctx.*) and lookups
- Use ONLY the `$ctx.<name>` listed in the provided context attributes.
- If a database schema is provided, define each needed fact as a `lookups` entry: ONE `SELECT`, only tables and
  columns of the provided schema, named parameters `:name`, each parameter mapped to `$user.<field>` or
  `$args.<field>` (nothing else), no `;`, no comments, no INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/ATTACH/PRAGMA...
  `returns`: `scalar` (first column of first row or null), `list`, `row`, `exists`.
- If you need a fact that was not provided, add it to `meta.context_attributes` as
  `{"description": "...", "requested": true}` and mention it in `assumptions`.

## Redaction (applied in this order)
1. `row_filters`: drop list elements for which a `drop_if` group holds. `result_path` is the key (or `a.b`) where
   the list lives; `null` means the result itself is a list.
2. `always_redact_fields`: those keys become `"[redacted]"` everywhere, for everybody.
3. `restricted_fields`: those keys become `"[redacted]"` unless a `visible_if` group holds (`$row` = the record).
