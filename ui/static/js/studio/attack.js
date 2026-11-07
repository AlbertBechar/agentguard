// studio/attack.js -- «Επίθεση ζωντανά» (μόνο DemoBank): δύο στήλες, «Χωρίς προστασία» και «Με AgentGuard».
// Όλα τα νούμερα προέρχονται από πραγματική εκτέλεση του examples/demobank/run_demo.py μέσω του server.
import { api } from "../api.js";
import { countUp, el, errorBox, expander, fmtTime, icon, prefersReducedMotion, waiting } from "../ui.js";
import { S, save } from "./state.js";

const DISCLAIMER = "Οι επιθέσεις είναι φτιαγμένες από εμάς. Ο «βοηθός» στη δοκιμή είναι σκριπτ που υπακούει σε ό,τι διαβάζει (χειρότερο σενάριο), "
  + "όχι πραγματικό μοντέλο. «Σταμάτησε» σημαίνει ότι δεν διέρρευσε μυστικό ή δεν έγινε η ενέργεια — όχι ότι όλα είναι ασφαλή.";

const KIND_LABEL = { denied: "απαγορεύτηκε", needs_approval: "ζητήθηκε έγκριση ανθρώπου", neutralised: "εξουδετερώθηκε", harmless: "επιτράπηκε χωρίς ζημιά", succeeded: "η επίθεση πέτυχε", error: "σταμάτησε με σφάλμα" };

function cellWithout(x) {
  return x.without_guard.success
    ? el("span", { class: "cell cell-cond" }, icon("x", { size: 16 }), "πέτυχε")
    : el("span", { class: "cell cell-deny" }, "δεν πέτυχε");
}

function cellWith(x) {
  const g = x.with_guard;
  if (g.success) return el("div", { class: "stack-sm" }, el("span", { class: "cell cell-cond" }, icon("x", { size: 16 }), "πέτυχε"), el("p", { class: "muted", text: x.how_text }));
  const label = ["harmless", "neutralised"].includes(x.how_kind) ? "σταμάτησε (με επιφύλαξη)" : "σταμάτησε";
  return el("div", { class: "stack-sm" }, el("span", { class: "cell cell-allow" }, icon("check", { size: 16 }), label),
    el("p", { class: "muted" }, KIND_LABEL[x.how_kind] || x.how_kind, g.rule ? ["  ·  ", el("code", { text: g.rule })] : null),
    ["harmless", "neutralised"].includes(x.how_kind) ? el("p", { class: "note-honest" }, icon("info", { size: 16 }), ` Σημείωση: ${x.how_text}.`) : null);
}

function attackRow(x) {
  return el("article", { class: "attack-row", "aria-label": `${x.id}: ${x.text}` },
    el("div", { class: "attack-top" }, el("span", { class: "tag", text: x.id }), el("span", { class: "tag", text: x.category }), el("span", { text: x.text })),
    el("div", { class: "attack-cols" }, el("div", null, cellWithout(x)), el("div", null, cellWith(x))),
    expander("Λεπτομέρειες", el("ul", null, el("li", null, "Χωρίς προστασία: ", x.without_guard.detail), el("li", null, "Με AgentGuard: ", x.with_guard.detail,
      ` (status: ${x.with_guard.status}${x.with_guard.findings ? `, ευρήματα καθαρισμού: ${x.with_guard.findings}` : ""})`))));
}

function bigLine(s) {
  const a = el("span", { class: "num-hot", text: "0" });
  const b = el("span", { class: "num-hot", text: "0" });
  countUp(a, s.attacks_without_guard, { format: (n) => `${Math.round(n)}/${s.attacks}` });
  countUp(b, s.attacks_with_guard, { from: s.attacks_without_guard, ms: 1400, format: (n) => `${Math.round(n)}/${s.attacks}` });
  return el("div", { class: "big-vs", role: "group", "aria-label": `Επιθέσεις που πέτυχαν: χωρίς προστασία ${s.attacks_without_guard} από ${s.attacks}, με AgentGuard ${s.attacks_with_guard} από ${s.attacks}` },
    a, el("span", { class: "arrow", "aria-hidden": "true" }, icon("arrow", { size: 56 })), b);
}

function results(res) {
  const s = res.summary;
  const grid = el("div", { class: "attack-list" });
  const rows = res.attacks.map(attackRow);
  const filter = el("input", { type: "checkbox", id: "atk-filter" });
  const applyFilter = () => rows.forEach((r, i) => {
    const x = res.attacks[i];
    const exception = x.with_guard.success || ["harmless", "neutralised"].includes(x.how_kind);
    r.hidden = filter.checked && !exception;
  });
  filter.addEventListener("change", applyFilter);
  if (prefersReducedMotion()) grid.append(...rows);
  else rows.forEach((r, i) => setTimeout(() => grid.append(r), 70 * i));
  const exceptions = res.attacks.filter((x) => x.with_guard.success || ["harmless", "neutralised"].includes(x.how_kind)).length;
  return el("div", { class: "stack" },
    el("section", { class: "card stack-sm reveal", "aria-label": "Αποτέλεσμα" },
      el("div", { class: "grid-2" },
        el("div", { class: "stack-sm" }, el("p", { class: "label", text: "Επιθέσεις που πέτυχαν" }), bigLine(s),
          el("div", { class: "row between-cols" }, el("span", { class: "muted", text: "Χωρίς προστασία" }), el("span", { class: "muted", text: "Με AgentGuard" }))),
        el("div", { class: "stack-sm" }, el("p", { class: "label", text: "Κανονικές χρήσεις που δούλεψαν (ο φρουρός δεν χαλά τη δουλειά)" }),
          el("div", { class: "stats" },
            el("div", { class: "stat ok" }, el("span", { class: "big", text: `${s.normal_without_guard}/${s.normal}` }), el("span", { class: "cap", text: "χωρίς προστασία" })),
            el("div", { class: "stat ok" }, el("span", { class: "big", text: `${s.normal_with_guard}/${s.normal}` }), el("span", { class: "cap", text: "με AgentGuard" }))))),
      el("p", { class: "muted" }, `Πολιτική: ${res.source_label}. Μετρήθηκε τώρα (${fmtTime(res.ran_at)}, ${res.elapsed_s} δευτ.) με `, el("code", { text: res.ran_with }), ".",
        res.problems.length ? [" ", el("strong", { text: `Προσοχή: ${res.problems.length} απρόσμενα αποτελέσματα.` })] : null),
      res.problems.length ? el("ul", null, res.problems.map((p) => el("li", { text: p }))) : null),
    el("section", { class: "stack-sm", "aria-labelledby": "h-atk" },
      el("div", { class: "row-between" }, el("h3", { id: "h-atk", text: `Οι ${s.attacks} επιθέσεις` }),
        el("label", { class: "checkline", for: "atk-filter" }, filter, el("span", { text: `Μόνο όσες πέτυχαν ή δεν μπλοκαρίστηκαν απλά (${exceptions})` }))),
      el("div", { class: "attack-head", "aria-hidden": "true" }, el("span", { text: "Χωρίς προστασία" }), el("span", { text: "Με AgentGuard" })),
      grid),
    expander(`Οι ${s.normal} κανονικές χρήσεις`, el("ul", null, res.normal.map((x) => el("li", null,
      x.without_guard.success ? "✓ " : "✕ ", x.with_guard.success ? "✓ " : "✕ ", x.text, " ", el("span", { class: "tag", text: x.id })))), false));
}

export async function renderAttack(host, studio) {
  const foreign = S.session && S.session.preset !== "demobank";
  if (foreign) {
    host.replaceChildren(el("div", { class: "stack" }, el("div", { class: "card stack-sm" }, el("h2", { text: "Επίθεση ζωντανά" }),
      el("p", null, "Η ζωντανή επίθεση υπάρχει μόνο για τη δοκιμαστική DemoBank (όχι πραγματική εταιρία). Για τη δική σου εφαρμογή δοκίμασε τον φρουρό στο βήμα «Δοκίμασε»."),
      el("div", { class: "row" }, S.result ? el("button", { type: "button", class: "btn btn-primary", onclick: () => studio.go("try") }, "Πήγαινε στο «Δοκίμασε»", icon("arrow", { size: 18 })) : null,
        el("button", { type: "button", class: "btn", onclick: () => studio.resetAll() }, "Φόρτωσε τη DemoBank")))));
    return;
  }
  const canSession = !!(S.session && S.session.preset === "demobank" && S.approved);
  const sourceDefault = canSession ? "session" : "reference";
  const out = el("div", { "aria-live": "polite" });
  const radio = (id, title, sub, disabled) => el("label", { class: "choice", "aria-disabled": disabled ? "true" : "false" },
    el("input", { type: "radio", name: "atk-src", value: id, checked: id === sourceDefault, disabled }),
    el("span", null, el("span", { class: "choice-title", text: title }), el("span", { class: "choice-sub", text: sub })));
  const run = el("button", { type: "button", class: "btn btn-hot btn-lg" }, icon("bolt", { size: 22 }), "Τρέξε επιθέσεις");
  run.addEventListener("click", async () => {
    const src = host.querySelector("input[name=atk-src]:checked").value;
    run.disabled = true; run.setAttribute("aria-busy", "true");
    out.replaceChildren(waiting("Τρέχουν οι επιθέσεις…", "Κάθε επίθεση τρέχει χωρίς και με προστασία πάνω σε δοκιμαστική βάση."));
    try {
      const res = await api.attackRun(src === "session" ? { source: "session", sid: S.sid } : { source: "reference" });
      out.replaceChildren(results(res));
    } catch (e) {
      out.replaceChildren(errorBox(e, e.code === "not_approved" ? "Η πολιτική δεν έχει εγκριθεί" : "Η επίθεση δεν ολοκληρώθηκε"));
    } finally { run.disabled = false; run.removeAttribute("aria-busy"); }
  });
  host.replaceChildren(el("div", { class: "stack" },
    el("div", null, el("h2", { text: "Επίθεση ζωντανά" }), el("p", { class: "muted", text: "20 επιθέσεις και 15 κανονικές χρήσεις στη δοκιμαστική εφαρμογή DemoBank, χωρίς και με AgentGuard." })),
    el("div", { class: "alert must-show", role: "note" }, icon("info", { size: 22 }), el("div", null, el("div", { class: "alert-title", text: "Πριν δεις τα νούμερα" }), el("p", { text: DISCLAIMER }))),
    el("section", { class: "card stack-sm", "aria-labelledby": "h-src" }, el("h3", { id: "h-src", text: "Ποια πολιτική δοκιμάζεται;" }),
      el("div", { class: "choices", role: "radiogroup", "aria-labelledby": "h-src" },
        radio("reference", "Η χειρόγραφη reference πολιτική", "Γραμμένη από άνθρωπο στο repo.", false),
        radio("session", "Αυτή που εγκρίθηκε από το Copilot", canSession ? "Η πολιτική που μόλις υπέγραψες στο Studio." : "Διαθέσιμη μετά την έγκριση της DemoBank στο Studio.", !canSession)),
      el("div", { class: "row" }, run)),
    out));
}
