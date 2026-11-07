"""
copilot/cli.py -- λεπτό περίβλημα γραμμής εντολών πάνω στο CopilotSession (η βιβλιοθήκη δεν κάνει input()/print()).

    python -m copilot init     --company ... --agent ... --tools FILE (--requirements TEXT | --requirements-file FILE)
    python -m copilot answer   [--answers FILE | --defaults]
    python -m copilot generate
    python -m copilot approve  --by "Όνομα" [--confirm yes]
    python -m copilot dry-run

Όλα τα αρχεία γράφονται στο --out (προεπιλογή out/<company>/). Η κονσόλα δεν τυπώνει emoji ([OK]/[WARN]/[FAIL]).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .dbschema import SchemaError
from .llm import GeminiLLM, LLMError, ReplayLLM
from .session import ApprovalRefused, CopilotSession, slugify
from .tooldefs import ToolDefError

SESSION_FILE = "session.json"


def _out(msg: str = "") -> None:
    sys.stdout.write(msg + "\n")


def _make_llm(args):
    if getattr(args, "replay", None):
        return ReplayLLM(args.replay)
    if getattr(args, "llm", "auto") == "offline":
        return False
    llm = None
    if getattr(args, "record", None):
        llm = GeminiLLM(record_path=args.record)
        if not llm._key:
            return None
    return llm


def _find_out(args) -> Path:
    if args.out:
        return Path(args.out)
    found = sorted(Path("out").glob(f"*/{SESSION_FILE}")) if Path("out").is_dir() else []
    if len(found) == 1:
        return found[0].parent
    raise SystemExit("[FAIL] δώστε --out (δεν βρέθηκε μοναδική συνεδρία στον φάκελο out/).")


def _load(args) -> tuple[CopilotSession, Path]:
    out = _find_out(args)
    path = out / SESSION_FILE
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        return CopilotSession.from_dict(state, llm=_make_llm(args)), out
    except FileNotFoundError:
        raise SystemExit(f"[FAIL] δεν υπάρχει συνεδρία στο {path}· τρέξτε πρώτα `init`.") from None
    except (ValueError, LLMError) as e:
        raise SystemExit(f"[FAIL] {e}") from None


def _save(session: CopilotSession, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with open(out / SESSION_FILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(session.to_dict(), f, indent=2, ensure_ascii=False)
        f.write("\n")


def _read_text_arg(text, file):
    if file:
        return Path(file).read_text(encoding="utf-8")
    return text


def cmd_init(args) -> int:
    requirements = _read_text_arg(args.requirements, args.requirements_file)
    schema = Path(args.db_schema).read_text(encoding="utf-8") if args.db_schema else None
    ctx = {}
    for item in args.context_attr or []:
        name, _, desc = item.partition("=")
        ctx[name.strip()] = desc.strip()
    out = Path(args.out) if args.out else Path("out") / slugify(args.company)
    session = CopilotSession.new(company=args.company, agent=args.agent, tools=args.tools, requirements=requirements or "",
                                 roles=[r.strip() for r in args.roles.split(",")] if args.roles else None,
                                 context_attributes=ctx or None, db_schema=schema, llm=_make_llm(args),
                                 language=args.language, out_dir=str(out))
    _save(session, out)
    _out(f"[OK] συνεδρία δημιουργήθηκε: {out / SESSION_FILE} ({len(session.intake['tools'])} εργαλεία)")
    return 0


def cmd_answer(args) -> int:
    session, out = _load(args)
    questions = session.questions()
    if args.answers:
        answers = json.loads(Path(args.answers).read_text(encoding="utf-8"))
    elif args.defaults:
        answers = {}
    else:
        answers = {}
        for q in questions:
            _out(f"\n[{q['id']}] {q['text']}")
            if q.get("why"):
                _out(f"    Γιατί ρωτάμε: {q['why']}")
            for i, opt in enumerate(q["options"], 1):
                _out(f"    {i}) {opt}")
            _out(f"    (Enter = προεπιλογή: {q['default']})")
            raw = input("    > ").strip()
            if not raw:
                continue
            answers[q["id"]] = q["options"][int(raw) - 1] if raw.isdigit() and 0 < int(raw) <= len(q["options"]) else raw
    result = session.answer(answers)
    _save(session, out)
    _out(f"[OK] {len(result['accepted'])} απαντήσεις αποθηκεύτηκαν, {len(questions) - len(result['accepted'])} με προεπιλογή")
    if result["unknown"]:
        _out(f"[WARN] άγνωστα id απαντήσεων: {', '.join(result['unknown'])}")
    return 0


def cmd_generate(args) -> int:
    session, out = _load(args)
    result = session.generate()
    paths = session.save_draft(out)
    _save(session, out)
    errors = [i for i in result["issues"] if i["level"] == "error"]
    warnings = [i for i in result["issues"] if i["level"] == "warning"]
    rep = result["scenarios_report"]
    _out(f"[OK] πρόχειρο: {out / 'policy.draft.json'}")
    _out(f"     πηγή: {session.state['result']['source']} ({session.state['result']['model']}) · σενάρια: {rep['passed']}/{rep['total']} πέρασαν")
    for i in errors:
        _out(f"[FAIL] {i['message']}")
    for i in warnings[:10]:
        _out(f"[WARN] {i['message']}")
    if errors:
        _out(f"[FAIL] {len(errors)} σφάλματα: η έγκριση μπλοκάρεται μέχρι να διορθωθούν (δείτε {out / 'review.md'}).")
    else:
        _out(f"[OK] χωρίς σφάλματα. Διαβάστε το {out / 'review.md'} και μετά τρέξτε `approve`.")
    _out(f"     αρχεία: {', '.join(Path(p).name for p in paths)}")
    return 0


def cmd_approve(args) -> int:
    session, out = _load(args)
    if session.state["result"] is None:
        session.generate()
    confirm = args.confirm
    if confirm is None:
        confirm = input('Πληκτρολογήστε "yes" για να εγκρίνετε την πολιτική: ').strip()
    try:
        res = session.approve(by=args.by, confirm=confirm, out_dir=out)
    except ApprovalRefused as e:
        _out("[FAIL] η έγκριση αρνήθηκε:")
        for reason in e.reasons:
            _out(f"       - {reason}")
        return 1
    _save(session, out)
    _out(f"[OK] εγκρίθηκε από {args.by}: {res['policy_path']}")
    _out(f"     υπογραφή/αρχείο έγκρισης: {res['approval_path']}")
    return 0


def cmd_dry_run(args) -> int:
    session, _ = _load(args)
    for stage in session.dry_run():
        _out("=" * 78)
        _out(f"ΣΤΑΔΙΟ: {stage['stage']}")
        _out("=" * 78)
        _out("--- SYSTEM ---")
        _out(stage["system"])
        _out("--- USER ---")
        _out(stage["user"])
    _out("=" * 78)
    _out("[OK] dry-run: τίποτα δεν στάλθηκε. Αυτό είναι ΑΚΡΙΒΩΣ ό,τι θα φύγει προς το LLM (μόνο περιγραφές, απαιτήσεις, απαντήσεις).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out", help="φάκελος αρχείων (προεπιλογή out/<company>/)")
    common.add_argument("--llm", choices=["auto", "offline"], default="auto", help="auto = Gemini αν υπάρχει AI_STUDIO_API_KEY")
    common.add_argument("--replay", help="αρχείο καταγραφής για ReplayLLM (demo χωρίς δίκτυο)")
    common.add_argument("--record", help="αρχείο όπου καταγράφονται οι πραγματικές κλήσεις Gemini")
    parser = argparse.ArgumentParser(prog="copilot", description="AgentGuard Policy Copilot")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", parents=[common], help="νέα συνεδρία")
    p.add_argument("--company", required=True)
    p.add_argument("--agent", required=True)
    p.add_argument("--tools", required=True, help="αρχείο JSON με τα εργαλεία (5 μορφές)")
    p.add_argument("--requirements", default="", help="απαιτήσεις ασφαλείας ως κείμενο")
    p.add_argument("--requirements-file", help="αρχείο κειμένου με τις απαιτήσεις")
    p.add_argument("--roles", help="ρόλοι χωρισμένοι με κόμμα")
    p.add_argument("--context-attr", action="append", help="όνομα=περιγραφή (επαναλαμβανόμενο)")
    p.add_argument("--db-schema", help="αρχείο με CREATE TABLE (μόνο σχήμα)")
    p.add_argument("--language", default="el", choices=["el", "en"])
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("answer", parents=[common], help="απαντήσεις στις ερωτήσεις")
    p.add_argument("--answers", help="αρχείο JSON {id: απάντηση}")
    p.add_argument("--defaults", action="store_true", help="δέξου όλα τα ασφαλή defaults")
    p.set_defaults(func=cmd_answer)

    p = sub.add_parser("generate", parents=[common], help="πρόχειρο policy + review")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("approve", parents=[common], help="υπογραφή: γράφει policy.json και approval.json")
    p.add_argument("--by", required=True, help="όνομα του ανθρώπου που εγκρίνει")
    p.add_argument("--confirm", help='πρέπει να είναι ακριβώς "yes" (αλλιώς ρωτά διαδραστικά)')
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("dry-run", parents=[common], help="τυπώνει ΑΚΡΙΒΩΣ ό,τι θα σταλεί στο LLM")
    p.set_defaults(func=cmd_dry_run)
    return parser


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ToolDefError, SchemaError, ValueError, LLMError, OSError) as e:
        _out(f"[FAIL] {e}")
        return 2
