"""Τεστ για copilot/tooldefs.py (ανάγνωση εργαλείων από 5 μορφές)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from copilot.tooldefs import ToolDefError, load_tools  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "copilot"
BANK_NAMES = ["get_account", "list_transactions", "get_statement", "transfer_funds", "update_contact",
              "read_support_ticket", "send_email", "close_account", "run_sql", "fetch_url"]


class FormatTests(unittest.TestCase):
    def test_demobank_in_all_five_formats(self):
        for name, fmt in [("list", "list"), ("gemini", "gemini"), ("openai", "openai"), ("mcp", "mcp"),
                          ("openapi", "openapi")]:
            with self.subTest(fmt=fmt):
                tools = load_tools(FIX / f"demobank.tools.{name}.json")
                self.assertEqual([t["name"] for t in tools], BANK_NAMES)
                self.assertEqual({t["source_format"] for t in tools}, {fmt})

    def test_params_are_normalized_identically_in_every_format(self):
        ref = {t["name"]: t["params"] for t in load_tools(FIX / "demobank.tools.list.json")}
        for name in ("gemini", "openai", "mcp", "openapi"):
            with self.subTest(fmt=name):
                got = {t["name"]: t["params"] for t in load_tools(FIX / f"demobank.tools.{name}.json")}
                self.assertEqual(got, ref)

    def test_param_details(self):
        t = {x["name"]: x for x in load_tools(FIX / "demobank.tools.gemini.json")}
        p = t["list_transactions"]["params"]
        self.assertEqual(p["account_id"], {"type": "string", "description": "id of the account", "required": True})
        self.assertEqual(p["limit"]["type"], "integer")  # τύποι με κεφαλαία (Gemini) -> πεζά
        self.assertFalse(p["limit"]["required"])
        self.assertEqual(t["transfer_funds"]["params"]["amount"]["type"], "number")

    def test_openapi_http_methods_and_read_indication(self):
        t = {x["name"]: x for x in load_tools(FIX / "demobank.tools.openapi.json")}
        self.assertEqual(t["get_account"]["http_method"], "GET")
        self.assertEqual(t["transfer_funds"]["http_method"], "POST")
        self.assertEqual(t["update_contact"]["http_method"], "PUT")
        self.assertIsNone(load_tools(FIX / "demobank.tools.mcp.json")[0]["http_method"])

    def test_openapi_without_operation_id_gets_method_path_name(self):
        doc = {"openapi": "3.0.0", "paths": {"/pets/{id}": {"get": {"summary": "Get a pet"},
                                                              "delete": {"description": "Remove"}}}}
        tools = load_tools(doc)
        self.assertEqual([t["name"] for t in tools], ["get_pets_id", "delete_pets_id"])
        self.assertEqual(tools[0]["description"], "Get a pet")

    def test_openapi_request_body_and_ref(self):
        doc = {"openapi": "3.0.0",
               "components": {"schemas": {"Pet": {"type": "object", "required": ["name"],
                                                   "properties": {"name": {"type": "string"}, "tag": {"type": "string"}}}}},
               "paths": {"/pets": {"post": {"operationId": "add_pet", "requestBody": {"content": {
                   "application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}}}}}}
        t = load_tools(doc)[0]
        self.assertEqual(sorted(t["params"]), ["name", "tag"])
        self.assertTrue(t["params"]["name"]["required"])

    def test_eclass_thirty_tools(self):
        tools = load_tools(FIX / "eclass.tools.gemini.json")
        self.assertEqual(len(tools), 30)
        self.assertIn("set_final_grade", [t["name"] for t in tools])

    def test_mixed_formats_in_one_list(self):
        mixed = [{"name": "a", "description": "A", "parameters": {"type": "object", "properties": {}}},
                 {"type": "function", "function": {"name": "b", "description": "B", "parameters": {"properties": {}}}},
                 {"name": "c", "inputSchema": {"properties": {"x": {"type": "string"}}}},
                 {"function_declarations": [{"name": "d", "description": "D"}]}]
        tools = load_tools(mixed)
        self.assertEqual([(t["name"], t["source_format"]) for t in tools],
                         [("a", "list"), ("b", "openai"), ("c", "mcp"), ("d", "gemini")])

    def test_wrappers(self):
        self.assertEqual(len(load_tools({"tools": [{"name": "x", "inputSchema": {}}]})), 1)
        self.assertEqual(len(load_tools({"function_declarations": [{"name": "x"}, {"name": "y"}]})), 2)
        self.assertEqual(len(load_tools([{"functionDeclarations": [{"name": "x"}]}])), 1)

    def test_flat_parameter_dict(self):
        t = load_tools([{"name": "x", "parameters": {"city": {"type": "string", "description": "c"}}}])[0]
        self.assertEqual(t["params"]["city"]["type"], "string")

    def test_json_schema_union_type(self):
        t = load_tools([{"name": "x", "inputSchema": {"properties": {"a": {"type": ["string", "null"]}}}}])[0]
        self.assertEqual(t["params"]["a"]["type"], "string")

    def test_source_can_be_json_text_path_string_or_object(self):
        text = (FIX / "demobank.tools.list.json").read_text(encoding="utf-8")
        self.assertEqual(len(load_tools(text)), 10)
        self.assertEqual(len(load_tools(str(FIX / "demobank.tools.list.json"))), 10)
        self.assertEqual(len(load_tools(json.loads(text))), 10)

    def test_does_not_mutate_input(self):
        data = json.loads((FIX / "demobank.tools.gemini.json").read_text(encoding="utf-8"))
        snap = json.dumps(data, sort_keys=True)
        load_tools(data)
        self.assertEqual(json.dumps(data, sort_keys=True), snap)


class ErrorTests(unittest.TestCase):
    def assertToolDefError(self, source, fragment=None):
        with self.assertRaises(ToolDefError) as cm:
            load_tools(source)
        if fragment:
            self.assertIn(fragment, str(cm.exception))

    def test_empty_inputs(self):
        self.assertToolDefError([], "κενή")
        self.assertToolDefError({}, "Άγνωστη μορφή")
        self.assertToolDefError([{"function_declarations": []}], "κανένα εργαλείο")

    def test_broken_json_and_missing_file(self):
        self.assertToolDefError("[{broken", "χαλασμένο")
        self.assertToolDefError(ROOT / "no" / "such" / "file.json", "Δεν βρέθηκε")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.json"
            p.write_text("{not json", encoding="utf-8")
            self.assertToolDefError(p, "χαλασμένο")

    def test_wrong_types(self):
        self.assertToolDefError(42, "διαδρομή")
        self.assertToolDefError("just a string", "Δεν βρέθηκε")  # κείμενο που δεν είναι JSON: το δοκιμάζει ως διαδρομή
        self.assertToolDefError([1, 2], "αντικείμενο")
        self.assertToolDefError([["x"]], "αντικείμενο")

    def test_unrecognized_and_nameless(self):
        self.assertToolDefError([{"foo": "bar"}], "Άγνωστη μορφή")
        self.assertToolDefError([{"name": ""}], "χωρίς όνομα")
        self.assertToolDefError([{"name": 5}], "χωρίς όνομα")
        self.assertToolDefError([{"type": "function"}], "Άγνωστη μορφή")
        self.assertToolDefError([{"type": "function", "function": "x"}], "function")

    def test_duplicates(self):
        self.assertToolDefError([{"name": "a"}, {"name": "a"}], "Διπλό")
        self.assertToolDefError([{"function_declarations": [{"name": "a"}]}, {"name": "a", "description": ""}], "Διπλό")

    def test_openapi_problems(self):
        self.assertToolDefError({"openapi": "3.0.0"}, "paths")
        self.assertToolDefError({"openapi": "3.0.0", "paths": {"/x": {"summary": "no ops"}}}, "καμία λειτουργία")

    def test_gemini_group_must_hold_a_list(self):
        self.assertToolDefError([{"function_declarations": "nope"}], "λίστα")


if __name__ == "__main__":
    unittest.main()
