// studio/check.js -- βήμα «Έλεγχος»: το Copilot γράφει τους κανόνες και δείχνουμε μετρητές, πίνακα, issues, διαφωνίες, SQL.
import { api } from "../api.js";
import { codeBlock, countUp, el, errorBox, expander, icon, store, waiting } from "../ui.js";
import { mdToDom } from "../md.js";
import { S, save } from "./state.js";

const CELL = { allow: ["cell-allow", "check", "επιτρέπεται"], deny: ["cell-deny", "x", "απαγορεύεται"], conditional: ["cell-cond", "half", "υπό συνθήκη"] };
const LEVEL = { error: ["Σφάλματα", "alert", "tag-amber"], warning: ["Προειδοποιήσεις", "alert", "tag-amber"], info: ["Πληροφορίες", "info", ""] };

function cellTitle(detail) {
  if (!detail || !detail.rules.length) return "Κανένας κανόνας δεν επιτρέπει την κλήση: απαγορεύεται από προεπιλογή.";
  return detail.rules.map((r) => `${r.effect === "allow" ? "επιτρέπει" : "απαγορεύει"}${r.conditional ? " υπό συνθήκη" : ""} · ${r.id}${r.reason ? `: ${r.reason}` : ""}`).join("\n");
}

export function matrixTable(res) {
  const roles = res.roles;
  const rows = Object.keys(res.matrix).map((tool) => el("tr", null,
    el("td", { class: "tool" }, tool,
      res.high_risk_tools.includes(tool) ? el("span", { class: "tag tag-amber", style: { "margin-left": ".5rem" }, title: "Εργαλείο υψηλού κινδύνου" }, icon("alert", { size: 14 }), "υψηλού κινδύνου") : null,
      res.untrusted_tools.includes(tool) ? el("span", { class: "tag", style: { "margin-left": ".4rem" }, title: "Επιστρέφει κείμενο γραμμένο από τρίτους" }, "μη έμπιστο κείμενο") : null),
    roles.map((role) => {
      const label = res.matrix[tool][role];
      const [cls, ic, text] = CELL[label] || CELL.deny;
      const title = cellTitle(res.matrix_detail[tool] && res.matrix_detail[tool][role]);
      return el("td", null, el("span", { class: `cell ${cls}`, tabindex: "0", title, "aria-label": `${tool}, ${role}: ${text}. ${title}` }, icon(ic, { size: 16 }), text));
    })));
  return el("div", { class: "table-wrap" }, el("table", null,
    el("thead", null, el("tr", null, el("th", { text: "Εργαλείο" }), roles.map((r) => el("th", { text: r })))), el("tbody", null, rows)));
}

function sourceBanner(res) {
  const out = [];
  if (S.mode === "replay") {
    const r = res.replay || { fallback_used: 0, calls: 0 };
    if (r.fallback_used > 0) {
      out.push(el("div", { class: "alert must-show" }, icon("alert", { size: 22 }), el("div", null,
        el("div", { class: "alert-title", text: "Το replay δεν ταίριαξε ακριβώς" }),
        el("p", { text: `${r.fallback_used} από τις ${r.calls} απαντήσεις της καταγραφής αντικαταστάθηκαν από την επόμενη καταγεγραμμένη, γιατί οι απαντήσεις σου διαφέρουν από της καταγεγραμμένης εκτέλεσης. Το αποτέλεσμα δεν είναι πιστή αναπαραγωγή.` }))));
    } else out.push(el("div", { class: "alert alert-ok" }, icon("check", { size: 22 }), el("div", null,
      el("div", { class: "alert-title", text: "Replay: πλήρης αντιστοιχία με την καταγραφή" }),
      el("p", { text: `Και οι ${r.calls} κλήσεις ταίριαξαν ακριβώς με πραγματική καταγεγραμμένη εκτέλεση Gemini (καμία αντικατάσταση).` }))));
  } else if (S.mode === "live" && res.source === "offline") {
    out.push(el("div", { class: "alert must-show" }, icon("alert", { size: 22 }), el("div", null,
      el("div", { class: "alert-title", text: "Το Gemini δεν έδωσε έγκυρο πρόχειρο" }), el("p", { text: "Χρησιμοποιήθηκε το ευρετικό πρόχειρο χωρίς AI. Δες τις προειδοποιήσεις παρακάτω." }))));
  } else if (S.mode === "offline") {
    out.push(el("div", { class: "alert" }, icon("info", { size: 22 }), el("div", null, el("div", { class: "alert-title", text: "Χωρίς AI" }),
      el("p", { text: "Ευρετικό πρόχειρο: ανοίγουν μόνο εργαλεία ανάγνωσης και όλα τα άλλα κλείνουν. Χρειάζεται δική σου συμπλήρωση πριν εγκριθεί για πραγματική χρήση." }))));
  }
  return out;
}

function stat(label, value, kind, fmt) {
  const big = el("span", { class: "big", "aria-hidden": "true", text: "0" });
  countUp(big, value, fmt ? { format: fmt } : undefined);
  return el("div", { class: `stat ${kind}`, role: "group", "aria-label": `${label}: ${fmt ? fmt(value) : value}` }, big, el("span", { class: "cap", text: label }));
}

function issuesView(res) {
  const groups = ["error", "warning", "info"].map((lv) => [lv, res.issues.filter((i) => i.level === lv)]).filter(([, l]) => l.length);
  if (!groups.length) return el("p", { class: "muted", text: "Δεν υπάρχουν προβλήματα ή προειδοποιήσεις." });
  return el("div", { class: "stack-sm" }, groups.map(([lv, list]) => {
    const [title, ic] = LEVEL[lv];
    const items = el("ul", null, list.map((i) => el("li", null, i.message, " ", i.code ? el("span", { class: "tag", text: i.code }) : null)));
    if (lv === "error") return el("div", { class: "alert", role: "alert" }, icon(ic, { size: 22 }), el("div", null, el("div", { class: "alert-title", text: `${title} (${list.length}) — μπλοκάρουν την έγκριση` }), items));
    return expander(`${title} (${list.length})`, items, lv === "warning" && list.length <= 6);
  }));
}

function disagreements(res) {
  const list = res.disagreements;
  const all = res.scenarios.results;
  const head = el("div", { class: "row-between" }, el("h3", { text: "Αποφασίζει ο άνθρωπος" }), el("span", { class: "tag tag-human" }, icon("user", { size: 16 }), "διαφωνίες σεναρίων"));
  if (!list.length) {
    return el("section", { class: "card stack-sm" }, head,
      el("p", { text: `Όλα τα σενάρια (${res.scenarios.passed}/${res.scenarios.total}) συμφωνούν με τους κανόνες: κανένα δεν χρειάζεται δική σου κρίση.` }),
      expander("Δες όλα τα σενάρια", el("ul", null, all.map((r) => el("li", null, r.ok ? "✓ " : "✕ ", r.text, " ", el("span", { class: "tag", text: r.source || r.kind })))), false));
  }
  return el("section", { class: "card stack-sm" }, head,
    el("p", { class: "muted", text: "Σε αυτά τα σενάρια οι κανόνες δεν έδωσαν το αποτέλεσμα που αναμενόταν. Εσύ κρίνεις: διόρθωσε τους κανόνες (πίσω στις ερωτήσεις) ή δέξου τη διαφορά." }),
    list.map((d) => el("div", { class: "card-2 stack-sm" }, el("strong", { text: d.text || d.id }),
      el("p", null, "Ζητήθηκε: ", el("code", { text: typeof d.expected === "string" ? d.expected : JSON.stringify(d.expected) })),
      el("p", null, "Αποφάσισαν οι κανόνες: ", el("code", { text: String(d.actual) }), d.rule ? ["  ·  κανόνας ", el("code", { text: d.rule })] : null),
      d.reason ? el("p", { class: "muted", text: d.reason }) : null)));
}

function lookupsView(res) {
  if (!res.lookups.length) return null;
  return el("section", { class: "card stack-sm" }, el("h3", { text: "Ερωτήματα στη βάση σου (lookups)" }),
    el("p", { class: "muted", text: "Για να ξέρει ο φρουρός «ποιανού είναι αυτή η εγγραφή», τρέχει αυτά τα SQL." }),
    el("div", { class: "alert alert-ok must-show" }, icon("lock", { size: 22 }), el("div", null, el("div", { class: "alert-title", text: "Τρέχει μόνο ανάγνωση στη βάση σου" }),
      el("p", { text: "Κάθε SQL ελέγχεται στατικά πριν τρέξει, εκτελείται σε σύνδεση μόνο για ανάγνωση και οι τιμές μπαίνουν μόνο ως παράμετροι." }))),
    res.lookups.map((l) => el("div", { class: "stack-sm" }, el("strong", { class: "mono", text: l.name }), l.description ? el("p", { class: "muted", text: l.description }) : null,
      codeBlock(l.sql, { title: `SQL · επιστρέφει: ${l.returns}` }),
      el("p", { class: "muted", text: `Παράμετροι: ${Object.entries(l.params).map(([k, v]) => `${k} ← ${v}`).join(", ") || "—"}` }))));
}

function dashboard(res, studio) {
  const errors = res.summary.errors;
  const back = el("button", { type: "button", class: "btn", onclick: () => studio.go("questions") }, icon("back", { size: 18 }), "Πίσω στις ερωτήσεις");
  const next = el("button", { type: "button", class: "btn btn-primary btn-lg", disabled: !res.summary.can_approve, onclick: () => { S.maxStep = Math.max(S.maxStep, 3); save(); studio.go("approve"); } },
    "Συνέχεια στην έγκριση", icon("arrow", { size: 20 }));
  return el("div", { class: "stack" },
    el("div", null, el("h2", { text: "Έλεγχος του πρόχειρου" }), el("p", { class: "muted", text: "Αυτό είναι πρόχειρο. Τίποτα δεν ισχύει μέχρι να το εγκρίνεις εσύ." })),
    ...sourceBanner(res),
    el("div", { class: "stats" },
      stat("σφάλματα (μπλοκάρουν την έγκριση)", errors, errors ? "warn" : "ok"),
      stat("προειδοποιήσεις", res.summary.warnings, res.summary.warnings ? "warn" : "ok"),
      stat("σενάρια που περνούν", res.summary.scenarios_passed, res.summary.scenarios_passed === res.summary.scenarios_total ? "ok" : "warn", (n) => `${Math.round(n)}/${res.summary.scenarios_total}`)),
    el("section", { class: "card stack-sm", "aria-labelledby": "h-matrix" }, el("h3", { id: "h-matrix", text: "Τι επιτρέπεται (εργαλείο × ρόλος)" }),
      el("p", { class: "muted", text: "Πέρνα το ποντίκι ή εστίασε ένα κελί για να δεις ποιος κανόνας το αποφασίζει. ◐ σημαίνει υπό συνθήκη, π.χ. μόνο ο ιδιοκτήτης ή έως ένα όριο." }),
      matrixTable(res)),
    el("section", { class: "card stack-sm" }, el("h3", { text: "Προβλήματα και προειδοποιήσεις" }), issuesView(res)),
    disagreements(res),
    lookupsView(res),
    expander("Πλήρης περίληψη (review)", mdToDom(res.review_md)),
    expander("Το αρχείο κανόνων (policy, JSON)", codeBlock(JSON.stringify(res.policy, null, 2), { title: "policy.draft.json" })),
    el("div", { class: "stack-sm" },
      errors ? el("div", { class: "alert must-show", role: "alert" }, icon("alert", { size: 22 }), el("div", null, el("div", { class: "alert-title", text: "Η έγκριση είναι κλειδωμένη" }),
        el("p", { text: `Υπάρχουν ${errors} σφάλματα στους κανόνες. Γύρνα στις ερωτήσεις και άλλαξε τις απαντήσεις που τα προκαλούν (π.χ. ζήτησε συνθήκη ιδιοκτησίας).` }))) : null,
      el("div", { class: "row-between" }, back, next)));
}

export async function renderCheck(host, studio) {
  if (!S.sid) { host.replaceChildren(errorBox({ message: "Δεν υπάρχει ενεργή συνεδρία. Γύρνα στο βήμα «Εφαρμογή»." })); return; }
  if (S.result) { host.replaceChildren(dashboard(S.result, studio)); return; }
  host.replaceChildren(waiting("Το Copilot γράφει τους κανόνες…", S.mode === "live" ? "Μιλά με το Gemini· μπορεί να πάρει λίγα δευτερόλεπτα." : "Μπορεί να πάρει λίγα δευτερόλεπτα."));
  try {
    const res = await api.generate(S.sid);
    S.result = res; S.approved = null; S.maxStep = Math.max(S.maxStep, 2); save();
    store.set("engine", S.mode);
    if (host.isConnected) host.replaceChildren(dashboard(res, studio));
  } catch (e) {
    host.replaceChildren(el("div", { class: "stack" }, errorBox(e, e.code === "session_not_found" ? "Η συνεδρία έληξε" : "Οι κανόνες δεν γράφτηκαν"),
      el("div", { class: "row" }, el("button", { type: "button", class: "btn", onclick: () => studio.go("questions") }, icon("back", { size: 18 }), "Πίσω στις ερωτήσεις"),
        el("button", { type: "button", class: "btn btn-primary", onclick: () => studio.paint() }, icon("refresh", { size: 18 }), "Δοκίμασε ξανά"))));
  }
}
