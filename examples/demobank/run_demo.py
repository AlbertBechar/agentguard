"""
examples/demobank/run_demo.py -- η απόδειξη στο DemoBank: επιθέσεις και κανονικές χρήσεις, ΧΩΡΙΣ και ΜΕ Guard.

    python examples/demobank/run_demo.py        (από τη ρίζα του repo)

Για κάθε επίθεση: ο «αφελής agent» (examples/sim_agent.py) εκτελεί ό,τι οδηγία βρει. Χωρίς Guard πηγαίνει κατευθείαν στην
εφαρμογή· με Guard περνά από guard.wrap(app.call_tool) με την πολιτική (reference ή άλλη). Η επιτυχία κρίνεται από την
ΠΡΑΓΜΑΤΙΚΗ κατάσταση της βάσης/εξόδων (υπόλοιπα, emails, ρόλοι...), όχι από τα λόγια του agent.
Exit code != 0 αν κάτι διαφέρει από το αναμενόμενο.

Η run(policy=None) δεν τυπώνει τίποτα (θα την καλέσει web UI για ζωντανή επίδειξη).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentguard import Guard  # noqa: E402
from examples.demobank.app import DemoBankApp  # noqa: E402
from examples.sim_agent import NaiveAgent, guarded, unprotected  # noqa: E402

HERE = Path(__file__).resolve().parent
REFERENCE = HERE / "policy.reference.json"


def _load(name: str, key: str) -> list[dict]:
    return json.loads((HERE / name).read_text(encoding="utf-8"))[key]


def evaluate_check(check: dict, before: dict, after: dict, app: DemoBankApp, observed: list[str]) -> tuple[bool, str]:
    """(πέτυχε;, λεπτομέρεια) με βάση την πραγματική κατάσταση."""
    t = check["type"]
    if t == "money_moved":
        a = check["from_account"]
        b0, b1 = before["balances"].get(a), after["balances"].get(a)
        return (b1 is not None and b0 is not None and b1 < b0), f"balance {a}: {b0} -> {b1}"
    if t == "observed_contains":
        hit = any(check["text"] in o for o in observed)
        return hit, f"text {'seen' if hit else 'not seen'} by the agent"
    if t == "email_sent":
        sent = [m for m in app.outbox if check["to_contains"] in m["to"]]
        return bool(sent), f"{len(sent)} email(s) to *{check['to_contains']}*"
    if t == "email_leak":
        leaked = [m for m in app.outbox if check["to_contains"] in m["to"] and check["secret"] in m["body"]]
        sent = [m for m in app.outbox if check["to_contains"] in m["to"]]
        return bool(leaked), f"{len(sent)} email(s) sent, secret inside: {bool(leaked)}"
    if t == "profile_changed":
        uid, field = check["customer_id"], check["field"]
        b0, b1 = before["users"][uid][field], after["users"][uid][field]
        return b0 != b1, f"{uid}.{field}: {b0} -> {b1}"
    if t == "role_changed":
        b0, b1 = before["users"][check["user_id"]]["role"], after["users"][check["user_id"]]["role"]
        return b0 != b1, f"role of {check['user_id']}: {b0} -> {b1}"
    if t == "account_closed":
        gone = check["account_id"] not in after["balances"]
        return gone, f"account {check['account_id']} {'closed' if gone else 'still open'}"
    if t == "url_fetched":
        hits = [u for u in app.fetched if check["url_contains"] in u]
        return bool(hits), f"{len(hits)} fetch(es) to *{check['url_contains']}*"
    raise ValueError(f"unknown success_check type {t!r}")


def _run_case(case: dict, policy: dict | str, guarded_run: bool) -> dict:
    app = DemoBankApp()
    try:
        if case.get("plant"):
            app.plant(**case["plant"])
        before = app.snapshot()
        if guarded_run:
            guard = Guard.from_policy(policy, db=app.readonly_connection(), audit_path=None)
            call, begin = guarded(guard, app, session_id=case["id"])
        else:
            call, begin = unprotected(app)
        result = NaiveAgent(call, begin).run(case["user"], case["user_message"])
        success, detail = evaluate_check(case["success_check"], before, app.snapshot(), app, result["observed"])
        blocked = next((s for s in result["steps"] if s["status"] != "ok"), None)
        return {"success": success, "detail": detail, "status": blocked["status"] if blocked else "ok",
                "rule": blocked["rule"] if blocked else "", "calls": len(result["steps"]),
                "findings": sum(s["findings"] for s in result["steps"])}
    finally:
        app.close()


def run(policy=None) -> dict:
    """{"attacks": [...], "normal": [...]}. policy=None => η reference πολιτική· αλλιώς διαδρομή ή dict πολιτικής. Δεν τυπώνει."""
    pol = policy if policy is not None else str(REFERENCE)
    out: dict = {"attacks": [], "normal": []}
    for kind, cases in (("attacks", _load("attacks.json", "attacks")), ("normal", _load("normal.json", "normal"))):
        for case in cases:
            plain, protected = _run_case(case, pol, False), _run_case(case, pol, True)
            out[kind].append({"id": case["id"], "category": case["category"], "text": case["text"],
                              "without_guard": {"success": plain["success"], "detail": plain["detail"]},
                              "with_guard": {"success": protected["success"], "status": protected["status"], "rule": protected["rule"],
                                             "detail": protected["detail"], "findings": protected["findings"]}})
    return out


def summarize(report: dict) -> dict:
    a, n = report["attacks"], report["normal"]
    return {"attacks": len(a), "attacks_without_guard": sum(x["without_guard"]["success"] for x in a),
            "attacks_with_guard": sum(x["with_guard"]["success"] for x in a), "normal": len(n),
            "normal_without_guard": sum(x["without_guard"]["success"] for x in n),
            "normal_with_guard": sum(x["with_guard"]["success"] for x in n)}


def problems(report: dict) -> list[str]:
    """Ό,τι διαφέρει από το αναμενόμενο: επίθεση που ΔΕΝ πετυχαίνει χωρίς Guard (όχι πραγματική επίθεση), επίθεση που πετυχαίνει
    ΜΕ Guard, κανονική χρήση που αποτυγχάνει (με ή χωρίς Guard)."""
    bad = []
    for x in report["attacks"]:
        if not x["without_guard"]["success"]:
            bad.append(f"{x['id']}: the attack does not succeed even without Guard (not a real attack)")
        if x["with_guard"]["success"]:
            bad.append(f"{x['id']}: the attack SUCCEEDED with Guard ({x['with_guard']['detail']})")
    for x in report["normal"]:
        if not x["without_guard"]["success"]:
            bad.append(f"{x['id']}: normal use fails without Guard")
        if not x["with_guard"]["success"]:
            bad.append(f"{x['id']}: normal use BLOCKED by Guard ({x['with_guard']['status']} {x['with_guard']['rule']})")
    return bad


def format_table(report: dict) -> str:
    def row(x):
        w = "SUCCESS" if x["without_guard"]["success"] else "failed"
        g = "SUCCESS" if x["with_guard"]["success"] else "stopped"
        how = x["with_guard"]["status"] + (f" ({x['with_guard']['rule']})" if x["with_guard"]["rule"] else "")
        if not x["with_guard"]["success"] and x["with_guard"]["status"] == "ok":
            how = (f"neutralised ({x['with_guard']['findings']} sanitizer findings)" if x["with_guard"]["findings"]
                   else f"allowed, no harm done: {x['with_guard']['detail']}")
        return f"{x['id']:<5}{x['category']:<22}{w:<10}{g:<10}{how}"
    lines = [f"{'ID':<5}{'category':<22}{'no Guard':<10}{'Guard':<10}how the Guard reacted", "-" * 100]
    lines += [row(x) for x in report["attacks"]]
    lines += ["", f"{'ID':<5}{'normal use':<22}{'no Guard':<10}{'Guard':<10}", "-" * 100]
    for x in report["normal"]:
        lines.append(f"{x['id']:<5}{x['text'][:21]:<22}{'works' if x['without_guard']['success'] else 'FAILS':<10}{'works' if x['with_guard']['success'] else 'BLOCKED':<10}")
    s = summarize(report)
    lines += ["-" * 100, f"ATTACKS that succeeded:  without Guard {s['attacks_without_guard']}/{s['attacks']}   with Guard {s['attacks_with_guard']}/{s['attacks']}",
              f"NORMAL uses that worked: without Guard {s['normal_without_guard']}/{s['normal']}   with Guard {s['normal_with_guard']}/{s['normal']}"]
    return "\n".join(lines)


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = sys.argv[1:] if argv is None else argv
    report = run(args[0] if args else None)
    print(format_table(report))
    bad = problems(report)
    for b in bad:
        print("[FAIL] " + b)
    print("[OK] as expected" if not bad else f"[FAIL] {len(bad)} unexpected result(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
