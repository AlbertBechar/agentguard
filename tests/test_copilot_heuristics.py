"""Τεστ για copilot/heuristics.py."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from copilot.heuristics import analyze_tool, analyze_tools, measure, measurement_report  # noqa: E402
from copilot.tooldefs import load_tools  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "copilot"


def T(name, description="", params=(), http=None):
    return {"name": name, "description": description,
            "params": {p: {"type": "string", "description": "", "required": True} for p in params},
            "source_format": "list", "http_method": http}


class RiskTests(unittest.TestCase):
    def test_risk_table(self):
        cases = [
            (T("get_account", "Read one account"), "read"),
            (T("list_orders"), "read"),
            (T("search_books", "Search the catalog"), "read"),
            (T("showInvoice"), "read"),
            (T("update_profile", "Change the profile"), "write"),
            (T("deleteUser"), "write"),
            (T("transfer_funds"), "write"),
            (T("prescribe", "Prescribe a drug"), "write"),
            (T("send_email", "Send an email"), "external"),
            (T("notify_customer"), "external"),
            (T("post_to_slack", "Post a message to Slack"), "write"),  # πρώτο ρήμα: post -> write
            (T("run_sql", "Run SQL", ["query"]), "dangerous"),
            (T("execute_command", "Run a shell command", ["cmd"]), "dangerous"),
            (T("fetch_url", "Fetch a page", ["url"]), "dangerous"),
            (T("download_file", "Download", ["url"]), "dangerous"),
            (T("query_db", "Execute an arbitrary query on the database"), "dangerous"),
            (T("lookup", "Look something up", ["sql"]), "dangerous"),
            (T("διαγραφή_χρήστη"), "write"),
            (T("στείλε_μήνυμα"), "external"),
            (T("διάβασε_εγγραφή"), "read"),
            (T("εκτέλεσε_εντολή"), "dangerous"),
            (T("frobnicate"), "write"),                      # άγνωστο ρήμα => συντηρητικά write
            (T("frobnicate", http="GET"), "read"),           # αλλά το GET βοηθά
            (T("frobnicate", http="POST"), "write"),
            (T("thing", "Get the thing"), "read"),           # ρήμα από την περιγραφή
            (T("thing", "Delete the thing"), "write"),
        ]
        for tool, expected in cases:
            with self.subTest(tool=tool["name"], desc=tool["description"], http=tool["http_method"]):
                self.assertEqual(analyze_tool(tool)["risk"], expected)

    def test_every_answer_has_a_reason(self):
        for t in load_tools(FIX / "demobank.tools.list.json") + load_tools(FIX / "eclass.tools.gemini.json"):
            a = analyze_tool(t)
            self.assertIn(a["risk"], ("read", "write", "external", "dangerous"))
            for key in ("risk", "untrusted", "sensitive"):
                self.assertTrue(a["reasons"][key], (t["name"], key))

    def test_deterministic(self):
        tools = load_tools(FIX / "eclass.tools.gemini.json")
        self.assertEqual(analyze_tools(tools), analyze_tools(tools))


class UntrustedAndSensitiveTests(unittest.TestCase):
    def test_untrusted_table(self):
        cases = [
            (T("read_forum", "Read the forum posts"), True),
            (T("list_transactions", "The memo field is written by third parties"), True),
            (T("read_support_ticket", "Read a ticket"), True),
            (T("get_inbox", "Read emails"), True),
            (T("fetch_url", "Fetch a page", ["url"]), True),
            (T("read_comments"), True),
            (T("διάβασε_φόρουμ"), True),
            (T("get_balance", "Return the balance"), False),
            (T("list_courses", "List all courses"), False),
            (T("get_grades", "Get final course grades"), False),
            (T("send_email", "Send an email to a customer"), False),   # στέλνει, δεν επιστρέφει ξένο κείμενο
            (T("update_note", "Update a note"), False),                # εγγραφή
            (T("get_status", "Show the status", http="GET"), False),
        ]
        for tool, expected in cases:
            with self.subTest(tool=tool["name"]):
                self.assertIs(analyze_tool(tool)["returns_untrusted"], expected)

    def test_sensitive_params_and_fields(self):
        a = analyze_tool(T("reset", "Reset the user password", ["user_id", "new_password", "apiKey", "cardNumber"]))
        self.assertEqual(a["sensitive_params"], ["apiKey", "cardNumber", "new_password"])
        b = analyze_tool(T("get_account", "Returns owner_id, iban, balance and card_number.", ["account_id"]))
        self.assertEqual(b["sensitive_params"], [])
        self.assertEqual(b["sensitive_fields"], ["card", "iban"])
        self.assertEqual(analyze_tool(T("list_courses"))["sensitive_fields"], [])
        self.assertEqual(analyze_tool(T("pin_post", "Pin a post", ["post_id"]))["sensitive_params"], [])  # "pin" εντός λέξης όχι
        self.assertEqual(analyze_tool(T("x", "", ["pin"]))["sensitive_params"], ["pin"])


class MeasurementTests(unittest.TestCase):
    def test_measure_counts(self):
        analysis = analyze_tools([T("get_a"), T("delete_b"), T("send_c")])
        m = measure(analysis, ["delete_b", "update_z"], [])
        self.assertEqual(m["high_risk"]["true_positives"], 1)
        self.assertEqual(m["high_risk"]["missed"], ["update_z"])
        self.assertEqual(m["high_risk"]["false_positives"], ["send_c"])
        self.assertEqual(m["high_risk"]["recall"], 0.5)
        self.assertIsNone(m["untrusted"]["recall"])

    def test_eclass_and_demobank_recall_against_v1_and_spec_tables(self):
        policy = json.loads((ROOT / "app" / "eclass_policy.json").read_text(encoding="utf-8"))
        rep = measurement_report(load_tools(FIX / "eclass.tools.gemini.json"), policy,
                                 load_tools(FIX / "demobank.tools.list.json"))
        self.assertEqual(rep["eclass"]["tools"], 30)
        self.assertEqual(rep["demobank"]["tools"], 10)
        # Το δάπεδο δεν πρέπει να χάνει κανένα εργαλείο που το v1 θεωρεί high-risk ή untrusted
        self.assertEqual(rep["eclass"]["high_risk"]["missed"], [])
        self.assertEqual(rep["eclass"]["untrusted"]["missed"], [])
        self.assertEqual(rep["demobank"]["high_risk"]["missed"], [])
        self.assertEqual(rep["demobank"]["untrusted"]["missed"], [])

    def test_stored_measurement_is_current(self):
        """Το νούμερο που θα μπει στα docs πρέπει να ισούται με αυτό που βγάζει ο κώδικας τώρα."""
        policy = json.loads((ROOT / "app" / "eclass_policy.json").read_text(encoding="utf-8"))
        rep = measurement_report(load_tools(FIX / "eclass.tools.gemini.json"), policy,
                                 load_tools(FIX / "demobank.tools.list.json"))
        stored = json.loads((FIX / "heuristics_measurement.json").read_text(encoding="utf-8"))
        self.assertEqual(stored, json.loads(json.dumps(rep)))


if __name__ == "__main__":
    unittest.main()
