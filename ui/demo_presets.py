"""
ui/demo_presets.py -- τα δύο έτοιμα παραδείγματα του Studio.

* DemoBank  : διαβάζεται από τα αρχεία του repo (examples/demobank/*) -- δεν αντιγράφεται τίποτα. Μόνο η επωνυμία, ο
              βοηθός, οι ρόλοι και τα context attributes είναι σταθερές εδώ, ΑΚΡΙΒΩΣ όπως στο copilot/evaluate.py
              (_new_session), γιατί η καταγραφή replay ταιριάζει με το περιεχόμενο των prompts.
* DemoClinic: ui/presets/democlinic.json (δική μας δοκιμαστική εφαρμογή, χωρίς replay).
Και τα δύο είναι «δοκιμαστικές εφαρμογές (όχι πραγματικές εταιρίες)».
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMOBANK_DIR = ROOT / "examples" / "demobank"
CLINIC_FILE = Path(__file__).resolve().parent / "presets" / "democlinic.json"
REPLAY_FILE = ROOT / "tests" / "fixtures" / "copilot" / "replay" / "demobank.replay.ndjson"

BADGE = "δοκιμαστική εφαρμογή (όχι πραγματική εταιρία)"

# Ίδια με copilot/evaluate.py::_new_session και CONTEXT_ATTRIBUTES (το test_ui_service το επαληθεύει με το replay).
DEMOBANK_COMPANY = "DemoBank — λιανική τράπεζα"
DEMOBANK_AGENT = "Chatbot εξυπηρέτησης πελατών και ταμιών"
DEMOBANK_ROLES = ["customer", "teller", "admin"]
DEMOBANK_CONTEXT = {"account_owner_id": "owner of the account args.account_id",
                    "from_account_owner_id": "owner of the account args.from_account",
                    "ticket_customer_id": "customer who owns the ticket args.ticket_id"}

DEMOBANK_USERS = {"customer": "c1", "teller": "t1", "admin": "a1"}
DEMOBANK_ARGS = {
    "get_account": {"account_id": "A1"},
    "list_transactions": {"account_id": "A1", "limit": 5},
    "get_statement": {"account_id": "A1", "month": "2026-10"},
    "transfer_funds": {"from_account": "A1", "to_account": "A3", "amount": 50},
    "update_contact": {"customer_id": "c1", "email": "new@mail.example"},
    "read_support_ticket": {"ticket_id": "T1"},
    "send_email": {"to": "c1@mail.example", "subject": "Hello", "body": "Hi"},
    "close_account": {"account_id": "A4"},
    "run_sql": {"query": "SELECT * FROM accounts"},
    "fetch_url": {"url": "https://example.test/"},
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def demobank_available() -> bool:
    return all((DEMOBANK_DIR / n).is_file() for n in ("tools.json", "requirements.txt", "db_schema.sql", "policy.reference.json"))


def replay_available() -> bool:
    return REPLAY_FILE.is_file()


def demobank_inputs() -> dict:
    """Τα δεδομένα εισόδου της DemoBank όπως τα διαβάζει το Copilot (tools ως κείμενο JSON, όπως στο repo)."""
    return {"company": DEMOBANK_COMPANY, "agent": DEMOBANK_AGENT, "tools_text": _read(DEMOBANK_DIR / "tools.json"),
            "requirements": _read(DEMOBANK_DIR / "requirements.txt"), "roles": list(DEMOBANK_ROLES),
            "db_schema": _read(DEMOBANK_DIR / "db_schema.sql"), "context_attributes": dict(DEMOBANK_CONTEXT)}


def demobank_preset() -> dict:
    data = demobank_inputs()
    modes = ["offline", "live"] + (["replay"] if replay_available() else [])
    return {"id": "demobank", "title": "DemoBank", "badge": BADGE,
            "description": "Δοκιμαστική λιανική τράπεζα με SQLite. Έχει καταγραφή replay και ζωντανή επίθεση (20 επιθέσεις, 15 κανονικές χρήσεις).",
            **data, "modes": modes, "attack_available": True, "replay_available": replay_available(),
            "example_users": dict(DEMOBANK_USERS), "example_args": {k: dict(v) for k, v in DEMOBANK_ARGS.items()}}


def democlinic_preset() -> dict:
    raw = json.loads(_read(CLINIC_FILE))
    tools_text = json.dumps(raw.pop("tools"), indent=2, ensure_ascii=False)
    return {**raw, "tools_text": tools_text, "modes": ["offline", "live"], "attack_available": False, "replay_available": False}


def presets() -> list[dict]:
    out = []
    if demobank_available():
        out.append(demobank_preset())
    out.append(democlinic_preset())
    return out
