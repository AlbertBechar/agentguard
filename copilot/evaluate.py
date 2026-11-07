"""
copilot/evaluate.py -- ΜΕΤΡΗΣΗ της ποιότητας του Copilot πάνω σε gold σενάρια γραμμένα από άνθρωπο ΠΡΙΝ δει το αποτέλεσμα.

score(policy, gold)  : πόσα gold σενάρια περνά μια πολιτική.
evaluate_demobank()  : τρέχει το Copilot N φορές (το LLM δεν είναι ντετερμινιστικό => δίνουμε ΕΥΡΟΣ) και μετρά:
   (α) πρόχειρο LLM ΠΡΙΝ το safety floor, (β) ΜΕΤΑ το floor, (γ) offline πολιτική από heuristics,
   και πόσα από τα context attributes έγιναν ΈΓΚΥΡΑ lookups (χωρίς κώδικα) και πόσα χρειάστηκαν stub.
Ο «άνθρωπος» απαντά στις ερωτήσεις σύμφωνα με τις απαιτήσεις του DemoBank (βλ. HUMAN_RULES)· όλα τα νούμερα προέρχονται
από πραγματικό τρέξιμο και καταγράφονται σε JSON. Δεν στέλνεται κανένα δεδομένο πελάτη στο LLM.

    python -m copilot.evaluate --runs 3 --out out/eval          (χρειάζεται AI_STUDIO_API_KEY· αλλιώς μόνο offline)
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from app.policy_engine import PolicyEngine

from .contract import resolver_needed
from .llm import GeminiLLM, LLMError, ReplayLLM
from .scenarios import run_scenarios
from .session import CopilotSession

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demobank"
CONTEXT_ATTRIBUTES = {"account_owner_id": "owner of the account args.account_id",
                      "from_account_owner_id": "owner of the account args.from_account",
                      "ticket_customer_id": "customer who owns the ticket args.ticket_id"}
# Οι απαντήσεις του ανθρώπου (σύμφωνα με τις απαιτήσεις: ο teller/admin στέλνουν email· αλλαγές δεδομένων μόνο από ρόλους που
# τις επιτρέπουν χωρίς επιπλέον συνθήκη ρόλου όπου οι απαιτήσεις το λένε). Τα run_sql/fetch_url μένουν «σε κανέναν».
HUMAN_RULES = {("allow_tool", "send_email"): 1, ("unconditional", None): 1}   # «μόνο ο πιο προνομιούχος ρόλος» / «χωρίς συνθήκη»


def load_gold(path=None) -> list[dict]:
    data = json.loads(Path(path or DEMO / "scenarios.gold.json").read_text(encoding="utf-8"))
    return data["scenarios"]


def score(policy, gold: list[dict]) -> dict:
    """{"passed","total","failures":[{"id","text","reason"}], "invalid"?}. Άκυρη πολιτική => 0 περασμένα."""
    try:
        engine = PolicyEngine(policy)
    except (ValueError, TypeError) as e:
        return {"passed": 0, "total": len(gold), "failures": [], "invalid": str(e)[:300]}
    rep = run_scenarios(engine, gold)
    return {"passed": rep["passed"], "total": rep["total"],
            "failures": [{"id": f["id"], "text": f["text"], "reason": f["reason"]} for f in rep["failed"]]}


def answers_for(session: CopilotSession, rules=HUMAN_RULES) -> dict:
    ans = {}
    for q in session.questions():
        idx = rules.get((q["key"], q.get("tool")))
        if idx is not None:
            ans[q["id"]] = q["options"][idx]
    return ans


def lookups_stats(policy: dict, provided: list[str], issues: list[dict]) -> dict:
    """Πόσα από τα δοσμένα context attributes έγιναν ΈΓΚΥΡΑ lookups και πόσα χρειάζονται stub."""
    lookups = policy.get("lookups") if isinstance(policy.get("lookups"), dict) else {}
    bad = {i.get("lookup") for i in issues if i["level"] == "error" and str(i["code"]).startswith("lookup.")}
    bad |= {i["path"].split(".")[1] for i in issues if i["level"] == "error" and str(i.get("path", "")).startswith("lookups.")}
    valid = [n for n in provided if n in lookups and n not in bad]
    stubs = [n for n in resolver_needed(policy)]
    return {"provided": len(provided), "valid_lookups": len(valid), "valid_names": valid,
            "provided_without_lookup": [n for n in provided if n not in valid], "stub_needed": stubs,
            "lookups_total": len(lookups)}


def _new_session(llm, intake_dir: Path):
    return CopilotSession.new(
        company="DemoBank — λιανική τράπεζα", agent="Chatbot εξυπηρέτησης πελατών και ταμιών",
        tools=intake_dir / "tools.json", requirements=(intake_dir / "requirements.txt").read_text(encoding="utf-8"),
        roles=["customer", "teller", "admin"], context_attributes=CONTEXT_ATTRIBUTES,
        db_schema=(intake_dir / "db_schema.sql").read_text(encoding="utf-8"), llm=llm)


def run_once(llm, gold: list[dict], intake_dir: Path = DEMO) -> dict:
    """Μία πλήρης εκτέλεση του Copilot (questions -> answer -> generate) και η μέτρησή της."""
    s = _new_session(llm, intake_dir)
    s.answer(answers_for(s))
    res = s.generate()
    st = s.state["result"]
    issues = res["issues"]
    out = {"source": st["source"], "model": st["model"], "attempts": st["attempts"],
           "first_draft": score(st["first_draft"], gold) if st["first_draft"] is not None else None,
           "llm_before_floor": score(st["llm_policy"], gold) if st["llm_policy"] is not None else None,
           "after_floor": score(res["policy"], gold),
           "copilot_own_scenarios": {"passed": res["scenarios_report"]["passed"], "total": res["scenarios_report"]["total"]},
           "issues": {"errors": [i["message"] for i in issues if i["level"] == "error"],
                      "warnings": sum(1 for i in issues if i["level"] == "warning"),
                      "floor_changes": [i["code"] for i in issues if i["code"].startswith("floor.")]},
           "lookups": lookups_stats(res["policy"], list(CONTEXT_ATTRIBUTES), issues),
           "policy": res["policy"]}
    return out


def run_offline(gold: list[dict], intake_dir: Path = DEMO) -> dict:
    """(γ) Η offline πολιτική από heuristics (χωρίς LLM), με τις ίδιες απαντήσεις του ανθρώπου."""
    s = _new_session("offline", intake_dir)
    s.answer(answers_for(s))
    res = s.generate()
    return {"after_floor": score(res["policy"], gold), "source": s.state["result"]["source"],
            "errors": [i["message"] for i in res["issues"] if i["level"] == "error"]}


def _range(values: list[int]) -> str:
    return str(values[0]) if len(set(values)) == 1 else f"{min(values)}-{max(values)} (median {statistics.median(values)})"


def summarize(runs: list[dict], offline: dict, total: int) -> dict:
    llm_runs = [r for r in runs if r["source"] == "llm"]
    first = [r["first_draft"]["passed"] if r["first_draft"] and "invalid" not in r["first_draft"] else 0 for r in runs]
    return {"runs": len(runs), "runs_with_valid_llm_policy": len(llm_runs), "gold_total": total,
            "llm_first_draft_passed": first,
            "llm_before_floor_passed": [r["llm_before_floor"]["passed"] if r["llm_before_floor"] else None for r in runs],
            "after_floor_passed": [r["after_floor"]["passed"] for r in runs],
            "offline_passed": offline["after_floor"]["passed"],
            "valid_lookups": [r["lookups"]["valid_lookups"] for r in runs],
            "provided_attributes": runs[0]["lookups"]["provided"] if runs else 0,
            "stub_needed": [r["lookups"]["stub_needed"] for r in runs],
            "approval_blocking_errors": [len(r["issues"]["errors"]) for r in runs]}


def evaluate_demobank(llm_factory, runs: int = 3, gold_path=None, sleep: float = 0.0, intake_dir: Path = DEMO) -> dict:
    """llm_factory() -> LLM (ή None=μόνο offline). Επιστρέφει {"runs": [...], "offline": {...}, "summary": {...}}."""
    gold = load_gold(gold_path)
    offline = run_offline(gold, intake_dir)
    results = []
    for i in range(runs if llm_factory else 0):
        if i and sleep:
            time.sleep(sleep)
        results.append(run_once(llm_factory(), gold, intake_dir))
    return {"gold_total": len(gold), "offline": offline, "runs": results, "summary": summarize(results, offline, len(gold)) if results else None}


def format_report(result: dict) -> str:
    total, off = result["gold_total"], result["offline"]["after_floor"]["passed"]
    lines = [f"Gold scenarios: {total}  (examples/demobank/scenarios.gold.json, written by a human before seeing any Copilot output)", ""]
    lines.append(f"{'run':<5}{'source':<9}{'1st draft':<11}{'LLM pre-floor':<15}{'after floor':<13}{'valid lookups':<15}{'blocking errors'}")
    for i, r in enumerate(result["runs"], 1):
        fd = r["first_draft"]
        fd_s = "invalid" if fd is None or "invalid" in fd else f"{fd['passed']}/{fd['total']}"
        lb = r["llm_before_floor"]
        lb_s = "-" if lb is None else f"{lb['passed']}/{lb['total']}"
        lines.append(f"{i:<5}{r['source']:<9}{fd_s:<11}{lb_s:<15}{str(r['after_floor']['passed']) + '/' + str(r['after_floor']['total']):<13}"
                     f"{str(r['lookups']['valid_lookups']) + '/' + str(r['lookups']['provided']):<15}{len(r['issues']['errors'])}")
    lines.append(f"offline (heuristics only): {off}/{total}")
    s = result.get("summary")
    if s:
        lines += ["", f"After the floor: {_range(s['after_floor_passed'])} of {total}  |  offline: {off} of {total}  |  "
                      f"valid lookups: {_range(s['valid_lookups'])} of {s['provided_attributes']}"]
    return "\n".join(lines)


PUBLIC_DIR = ROOT / "tests" / "fixtures" / "copilot" / "public"
PUBLIC_CASES = [
    {"name": "petstore", "tools": "petstore.openapi.json", "company": "Example pet shop", "roles": ["customer", "staff"],
     "agent": "Assistant for a pet shop (Swagger Petstore API)",
     "requirements": "Customers may browse pets and place and view their own orders. Only staff may add, update or delete "
                     "pets, and only staff may manage users. Nobody may do anything that is not needed for these tasks."},
    {"name": "github_mcp", "tools": "github_mcp_tools.json", "company": "Example engineering team", "roles": ["developer", "maintainer"],
     "agent": "Coding assistant connected to GitHub through the official GitHub MCP server",
     "requirements": "Developers may read repository information (issues, pull requests, code, workflow results). Only maintainers "
                     "may change anything (create, update, merge, delete, run workflows, change settings). Content written by other "
                     "people, such as issues and comments, may contain malicious instructions."},
]


def run_public(llm, case: dict) -> dict:
    """Το Copilot σε δημόσια εργαλεία που δεν έχει ξαναδεί. ΔΕΝ υπάρχει gold set: καταγράφουμε μόνο τι παρήχθη και τι ζήτησε."""
    from collections import Counter
    from .heuristics import analyze_tools
    from .tooldefs import load_tools
    path = PUBLIC_DIR / case["tools"]
    tools = load_tools(path)
    analysis = analyze_tools(tools)
    s = CopilotSession.new(company=case["company"], agent=case["agent"], tools=path, requirements=case["requirements"],
                           roles=case["roles"], llm=llm)
    questions = s.questions()
    res = s.generate()
    st = s.state["result"]
    cells = Counter(label for per in res["matrix"].values() for label in per.values())
    review = res["review_md"]
    return {"name": case["name"], "tools": len(tools), "source": st["source"], "model": st["model"], "attempts": st["attempts"],
            "risk": dict(Counter(a["risk"] for a in analysis.values())),
            "returns_untrusted": sum(a["returns_untrusted"] for a in analysis.values()),
            "questions_asked": len(questions), "question_samples": [q["text"] for q in questions[:4]],
            "uncovered_before_floor": sum(1 for i in res["issues"] if i["code"] == "floor.uncovered"),
            "floor_changes": dict(Counter(i["code"] for i in res["issues"] if i["code"].startswith(("floor.", "probe.")))),
            "blocking_errors": [i["message"] for i in res["issues"] if i["level"] == "error"][:5],
            "warnings": sum(1 for i in res["issues"] if i["level"] == "warning"),
            "matrix_cells": dict(cells), "tools_in_policy": len(PolicyEngine(res["policy"]).tools()),
            "own_scenarios": {"passed": res["scenarios_report"]["passed"], "total": res["scenarios_report"]["total"]},
            "review_sample": "\n".join(review.splitlines()[:14])}


def evaluate_public(llm_factory) -> list[dict]:
    """llm_factory() -> LLM ή None (offline). Τρέχει όλες τις PUBLIC_CASES."""
    return [run_public(llm_factory() if llm_factory else "offline", c) for c in PUBLIC_CASES]


def _load_env_key(path: Path) -> None:
    """Διαβάζει AI_STUDIO_API_KEY από αρχείο .env στο περιβάλλον της διεργασίας (δεν τυπώνεται ποτέ)."""
    import os
    if os.environ.get("AI_STUDIO_API_KEY") or not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("AI_STUDIO_API_KEY="):
            os.environ["AI_STUDIO_API_KEY"] = line.split("=", 1)[1].strip()


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="copilot.evaluate", description="Μέτρηση του Copilot στο DemoBank")
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--out", default="out/eval", help="φάκελος αποτελεσμάτων JSON")
    p.add_argument("--record", help="αρχείο όπου καταγράφονται οι πραγματικές κλήσεις Gemini (για ReplayLLM)")
    p.add_argument("--replay", help="παίζει ξανά καταγεγραμμένες απαντήσεις αντί να καλεί το Gemini")
    p.add_argument("--sleep", type=float, default=20.0, help="δευτερόλεπτα ανάμεσα στα τρεξίματα (ποσόστωση API)")
    p.add_argument("--backoff", type=float, default=15.0, help="βάση αναμονής σε 429/5xx")
    p.add_argument("--env-file", default=str(ROOT / ".env"))
    p.add_argument("--offline", action="store_true", help="μόνο η offline πολιτική")
    p.add_argument("--public", action="store_true", help="τρέχει το Copilot στα δημόσια εργαλεία (Petstore, GitHub MCP)")
    a = p.parse_args(argv)
    _load_env_key(Path(a.env_file))
    import os
    if a.offline:
        factory = None
    elif a.replay:
        factory = lambda: ReplayLLM(a.replay)  # noqa: E731
    elif os.environ.get("AI_STUDIO_API_KEY"):
        factory = lambda: GeminiLLM(record_path=a.record, backoff=a.backoff)  # noqa: E731
    else:
        print("[WARN] δεν υπάρχει AI_STUDIO_API_KEY: τρέχει μόνο η offline πολιτική (δεν δοκιμάστηκε με πραγματικό LLM)")
        factory = None
    if a.public:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        results = evaluate_public(factory)
        (out / "public.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        for r in results:
            print(f"{r['name']}: {r['tools']} tools, source={r['source']} ({r['model']}), risk={r['risk']}, untrusted={r['returns_untrusted']}, "
                  f"questions={r['questions_asked']}, uncovered-before-floor={r['uncovered_before_floor']}, matrix cells={r['matrix_cells']}")
        print(f"[OK] αποτελέσματα: {out / 'public.json'}")
        return 0
    try:
        result = evaluate_demobank(factory, a.runs, sleep=a.sleep)
    except LLMError as e:
        print(f"[FAIL] {e}")
        return 2
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(format_report(result))
    print(f"[OK] αποτελέσματα: {out / 'result.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
