"""Τεστ για copilot/review.py και copilot/contract.py (review, context contract, resolver stub, snippets)."""
from __future__ import annotations

import ast
import copy
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.policy_engine import PolicyEngine  # noqa: E402
from copilot.contract import (context_contract_md, context_names_used, resolver_needed, resolver_stub_py,  # noqa: E402
                              snippet)
from copilot.review import review_md  # noqa: E402
from copilot.scenarios import run_scenarios  # noqa: E402
from copilot.tooldefs import load_tools  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "copilot"
GOOD = json.loads((FIX / "demobank.llm_response.json").read_text(encoding="utf-8"))["policy"]
TOOLS = load_tools(FIX / "demobank.tools.list.json")


def policy_with_facts(*names, lookups=None):
    """Πολιτική με κανόνες που χρησιμοποιούν γεγονότα $ctx.<name> και προαιρετικά lookups."""
    p = {"schema": "agentguard-policy/1", "roles": ["r"], "untrusted_tools": ["t"],
         "meta": {"context_attributes": {n: f"description of {n}" for n in names}},
         "rules": [{"id": f"rule.{n}", "tools": ["t"], "roles": ["r"], "effect": "allow",
                    "when": [{"left": f"$ctx.{n}", "op": "equals", "right": "$user.id"}]} for n in names] or
                  [{"id": "r", "tools": ["t"], "roles": ["r"], "effect": "allow"}]}
    if lookups:
        p["lookups"] = lookups
    return p


def load_module(source: str):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "resolver_stub.py"
        path.write_text(source, encoding="utf-8")
        spec = importlib.util.spec_from_file_location("resolver_stub_under_test", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


class ResolverStubTests(unittest.TestCase):
    def test_stub_compiles_imports_and_is_fail_closed(self):
        src = resolver_stub_py(policy_with_facts("is_vip", "branch_manager_id"))
        compile(src, "resolver_stub.py", "exec")
        ast.parse(src)
        mod = load_module(src)
        self.assertEqual(sorted(mod.DESCRIPTIONS), ["branch_manager_id", "is_vip"])
        self.assertEqual(mod.resolve({"id": 1, "role": "r"}, "t", {}), {})        # τίποτα υλοποιημένο => κανένα γεγονός
        with self.assertRaises(NotImplementedError):
            mod._attr_is_vip({}, "t", {})
        mod._ATTRIBUTES["is_vip"] = lambda user, tool, args: True                  # ο developer υλοποιεί ένα
        self.assertEqual(mod.resolve({}, "t", {}), {"is_vip": True})

    def test_one_todo_function_per_fact_with_signature_and_docstring(self):
        tree = ast.parse(resolver_stub_py(policy_with_facts("a", "b", "c")))
        fns = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        self.assertEqual(sorted(fns), ["_attr_a", "_attr_b", "_attr_c", "resolve"])
        for name in ("_attr_a", "_attr_b", "_attr_c"):
            self.assertEqual([a.arg for a in fns[name].args.args], ["user", "tool", "args"])
            self.assertIsNotNone(ast.get_docstring(fns[name]))
            self.assertTrue(any(isinstance(s, ast.Raise) for s in fns[name].body))

    def test_no_stub_when_there_is_nothing_to_implement(self):
        self.assertIsNone(resolver_stub_py(policy_with_facts()))                                  # κανένα $ctx
        self.assertIsNone(resolver_stub_py(GOOD))                                                  # όλα καλύπτονται από lookups
        self.assertEqual(resolver_needed(GOOD), [])
        only_lookup = policy_with_facts("owner", lookups={"owner": {"description": "d", "sql": "SELECT 1 FROM t WHERE a = :a",
                                                                    "params": {"a": "$args.a"}, "returns": "scalar"}})
        self.assertIsNone(resolver_stub_py(only_lookup))

    def test_stub_only_for_facts_without_lookup(self):
        p = policy_with_facts("owner", "vip", lookups={"owner": {"description": "d", "sql": "SELECT 1 FROM t WHERE a = :a",
                                                                 "params": {"a": "$args.a"}, "returns": "scalar"}})
        self.assertEqual(resolver_needed(p), ["vip"])
        src = resolver_stub_py(p)
        self.assertIn("_attr_vip", src)
        self.assertNotIn("_attr_owner", src)

    def test_malicious_descriptions_and_names_cannot_inject_code(self):
        evil = '"""\nimport os\nos.system("echo pwned")\n"""\n# '
        p = policy_with_facts("ctx-name.1", "fact")
        p["meta"]["context_attributes"]["fact"] = evil
        p["meta"]["context_attributes"]["ctx-name.1"] = {"description": evil, "requested": True}
        src = resolver_stub_py(p)
        tree = ast.parse(src)                                                                      # παραμένει έγκυρο Python
        imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertEqual([getattr(n, "module", None) for n in imports], ["__future__"])
        called = {n.func.attr if isinstance(n.func, ast.Attribute) else n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call)}
        self.assertNotIn("system", called)
        mod = load_module(src)
        self.assertEqual(mod.DESCRIPTIONS["fact"], evil)                                          # το κείμενο μένει απλό δεδομένο
        self.assertEqual(mod.resolve({}, "t", {}), {})

    def test_context_contract(self):
        p = policy_with_facts("a", "b")
        p["meta"]["context_attributes"]["b"] = {"description": "ζητήθηκε από το AI", "requested": True}
        md = context_contract_md(p)
        self.assertIn("`$ctx.a`", md)
        self.assertIn("ο developer πρέπει να το υλοποιήσει", md)
        self.assertIn("το ζήτησε το AI", md)
        self.assertIn("lookup (SQL", context_contract_md(GOOD))
        self.assertIn("δεν χρειάζεται lookup ούτε resolver", context_contract_md(policy_with_facts()))
        self.assertEqual(context_names_used(GOOD), ["account_owner_id", "from_account_owner_id", "owned_account_ids", "ticket_customer_id"])


class SnippetTests(unittest.TestCase):
    @staticmethod
    def code_lines(src):
        return [l for l in src.splitlines() if l.strip() and not l.strip().startswith("#")]

    def test_python_snippet_is_three_lines_with_the_real_api(self):
        src = snippet("python", GOOD, TOOLS)
        ast.parse(src)
        lines = self.code_lines(src)
        self.assertEqual(lines, ["from agentguard import Guard, sqlite_readonly",
                                 'guard = Guard.from_policy("policy.json", db=sqlite_readonly("company.db"))',
                                 "safe_call = guard.wrap(my_call_tool)"])
        self.assertIn("get_account", src)                                                          # τα δικά τους εργαλεία
        self.assertIn("guard.new_turn", src)

    def test_python_snippet_with_resolver_and_without_lookups(self):
        p = policy_with_facts("vip")
        src = snippet("python", p, TOOLS)
        ast.parse(src)
        lines = self.code_lines(src)
        self.assertEqual(len(lines), 4)
        self.assertIn("from resolver_stub import resolve", lines)
        self.assertIn('guard = Guard.from_policy("policy.json", context_resolver=resolve)', lines)
        self.assertNotIn("sqlite_readonly", src)
        both = copy.deepcopy(GOOD)
        both["rules"].append({"id": "x", "tools": ["get_account"], "roles": ["admin"], "effect": "deny",
                              "when": [{"left": "$ctx.vip", "op": "is_true"}]})
        self.assertIn('db=sqlite_readonly("company.db"), context_resolver=resolve', snippet("python", both, TOOLS))

    def test_node_snippet_calls_the_sidecar(self):
        src = snippet("node", GOOD, TOOLS)
        for part in ('fetch(BASE + path', '"/turn"', '"/authorize"', '"/filter_result"', "--sqlite company.db",
                     "python -m agentguard serve --policy policy.json --port 8787", "get_account", "d.decision"):
            self.assertIn(part, src)
        self.assertEqual(src.count("{"), src.count("}"))
        self.assertNotIn("--sqlite", snippet("node", policy_with_facts(), TOOLS))
        self.assertIn("send them in `context`", snippet("node", policy_with_facts("vip"), TOOLS))

    def test_http_snippet_has_valid_json_bodies(self):
        src = snippet("http", GOOD, TOOLS)
        for path in ("/turn", "/authorize", "/filter_result"):
            self.assertIn(f"http://127.0.0.1:8787{path}", src)
        bodies = re.findall(r"-d '(\{.*?\})'(?:\n|$)", src, re.S)
        self.assertEqual(len(bodies), 3)
        for b in bodies:
            json.loads(b)
        self.assertEqual(json.loads(bodies[1])["tool"], "get_account")

    def test_unknown_language_and_odd_tool_names(self):
        with self.assertRaises(ValueError):
            snippet("ruby", GOOD, TOOLS)
        weird = [{"name": 'we"ird\'name', "description": "", "params": {}, "source_format": "list", "http_method": None}]
        for lang in ("python", "node", "http"):
            src = snippet(lang, policy_with_facts(), weird)
            if lang == "python":
                ast.parse(src)


class ReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.intake = {"company": "DemoBank", "agent": "bot", "language": "el", "roles": ["customer", "teller", "admin"],
                      "tools": TOOLS, "requirements": "x"}
        cls.policy = copy.deepcopy(GOOD)
        cls.engine = PolicyEngine(cls.policy)
        cls.matrix = cls.engine.matrix()
        cls.decisions = {"qa": [{"id": "q1", "text": "Επιτρέπεται το run_sql;", "answer": "Όχι, σε κανέναν", "answered": True},
                                {"id": "q2", "text": "Ποιος είναι ο ιδιοκτήτης;", "answer": "accounts.owner_id", "answered": False}]}
        cls.issues = [{"level": "error", "code": "probe.open", "message": "Το «close_account» επιτρέπεται χωρίς συνθήκη."},
                      {"level": "warning", "code": "floor.uncovered", "message": "Λείπει κανόνας για X.", "tool": "x"},
                      {"level": "info", "code": "floor.denied", "message": "Το «run_sql» κλείνει για όλους.", "tool": "run_sql"},
                      {"level": "warning", "code": "probe.confirmed", "tool": "send_email", "message": "επιβεβαιώθηκε"}]
        cls.report = run_scenarios(cls.engine, [
            {"id": "S1", "kind": "authorize", "text": "Ο πελάτης διαβάζει δικό του λογαριασμό", "user": {"id": "c1", "role": "customer"},
             "tool": "get_account", "args": {}, "context": {"account_owner_id": "c1"}, "expect": "allow", "source": "llm"},
            {"id": "S2", "kind": "authorize", "text": "Αντίθετο σενάριο", "user": {"id": "c1", "role": "customer"},
             "tool": "get_account", "args": {}, "context": {"account_owner_id": "c2"}, "expect": "allow", "source": "llm"}])
        cls.md = review_md(cls.intake, cls.policy, cls.matrix, cls.issues, cls.decisions, cls.report,
                           ["Ο teller βλέπει κάθε λογαριασμό"], ["Όριο ημερήσιων μεταφορών;"], source="llm", model="fake")

    def test_has_every_section_and_the_banner(self):
        for heading in ("## 1. Τι επιτρέπεται", "## 2. Τι θεωρήσαμε", "## 3. Τι άλλαξε το safety floor",
                        "## 4. Προβλήματα", "## 5. Σενάρια που διαφωνούν — αποφασίζει ο άνθρωπος", "## 6. Lookups",
                        "## 7. Ερωτήσεις πριν υπογράψετε"):
            self.assertIn(heading, self.md)
        self.assertIn("Πρόχειρο από AI — ελέγξτε πριν εγκρίνετε", self.md)

    def test_contains_every_tool_of_the_policy(self):
        for tool in self.engine.tools():
            self.assertIn(f"`{tool}`", self.md, tool)

    def test_matrix_cells_use_plain_symbols_and_reasons(self):
        self.assertIn("🔒 απαγορεύεται", self.md)
        self.assertIn("✅ επιτρέπεται", self.md)
        self.assertIn("⚠️ υπό συνθήκη:", self.md)
        row = next(l for l in self.md.splitlines() if l.startswith("| `transfer_funds`"))
        self.assertIn("customers transfer up to 1000", row)
        header = next(l for l in self.md.splitlines() if l.startswith("| Εργαλείο"))
        for l in self.md.splitlines():
            if l.startswith("| `"):
                self.assertEqual(l.count("|"), header.count("|"), l)    # κανένα «|» δεν σπάει τον πίνακα

    def test_every_lookup_is_shown_with_its_sql_and_a_read_only_note(self):
        for name, lk in self.policy["lookups"].items():
            self.assertIn(f"### `{name}`", self.md)
            self.assertIn(lk["sql"], self.md)
        self.assertGreaterEqual(self.md.count("```sql"), 4)
        self.assertGreaterEqual(self.md.count("Τρέχει μόνο ανάγνωση στη βάση σου"), 4)

    def test_issues_floor_changes_and_disagreeing_scenarios(self):
        self.assertIn("ΣΦΑΛΜΑ (μπλοκάρει την έγκριση)", self.md)
        self.assertIn("Το «run_sql» κλείνει για όλους", self.md)
        self.assertIn("Πέρασαν 1 από 2", self.md)
        self.assertIn("Διαφωνία: μπορεί να είναι λάθος το σενάριο ή η πολιτική", self.md)
        self.assertIn("Αντίθετο σενάριο", self.md)
        self.assertIn("(προεπιλογή, δεν απαντήθηκε)", self.md)
        self.assertIn("Παραδοχή του AI: Ο teller", self.md)

    def test_three_to_five_questions(self):
        section = self.md.split("## 7. Ερωτήσεις πριν υπογράψετε")[1]
        numbered = re.findall(r"^\d+\. ", section, re.M)
        self.assertTrue(3 <= len(numbered) <= 5, numbered)
        self.assertIn("σενάρια που διαφωνούν", section)
        self.assertIn("`send_email`", section)                              # από το probe.confirmed

    def test_review_of_a_minimal_policy_still_has_three_questions(self):
        p = policy_with_facts()
        eng = PolicyEngine(p)
        md = review_md({"company": "X"}, p, eng.matrix(), [], {"qa": []}, None)
        self.assertEqual(len(re.findall(r"^\d+\. ", md.split("## 7.")[1], re.M)), 3)
        self.assertIn("Η πολιτική δεν έχει lookups", md)
        self.assertIn("Δεν έτρεξαν σενάρια", md)

    def test_offline_source_is_labelled(self):
        md = review_md(self.intake, self.policy, self.matrix, [], self.decisions, None, source="offline")
        self.assertIn("offline πολιτική από heuristics", md)

    def test_is_plain_text_not_json(self):
        self.assertFalse(self.md.lstrip().startswith("{"))
        self.assertTrue(self.md.startswith("# Review"))


if __name__ == "__main__":
    unittest.main()
