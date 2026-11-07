// studio/approve.js -- βήμα «Έγκριση»: ο άνθρωπος υπογράφει. Το ένα ροζ κουμπί της οθόνης είναι το «Έγκριση».
import { api } from "../api.js";
import { el, errorBox, fmtTime, icon, store } from "../ui.js";
import { S, save } from "./state.js";

const ENGINE = { replay: "Replay (καταγεγραμμένη εκτέλεση)", live: "Ζωντανό Gemini", offline: "Χωρίς AI (ευρετικοί κανόνες)" };

function summaryLines(res) {
  const roles = res.roles.join(", ");
  const tools = Object.keys(res.matrix).length;
  const lines = [
    `${tools} εργαλεία, ρόλοι: ${roles}. Υψηλού κινδύνου: ${res.high_risk_tools.length}.`,
    `${res.summary.errors} σφάλματα, ${res.summary.warnings} προειδοποιήσεις · σενάρια ${res.summary.scenarios_passed}/${res.summary.scenarios_total}.`,
    `Πηγή του πρόχειρου: ${ENGINE[S.mode] || S.mode}${res.replay && res.replay.fallback_used ? ` — με ${res.replay.fallback_used} αντικαταστάσεις (δεν είναι πιστή αναπαραγωγή)` : ""}.`,
  ];
  return el("ol", { class: "summary-lines" }, lines.map((l) => el("li", { text: l })));
}

function refusalCards(err, studio) {
  const items = err.items && err.items.length ? err.items : (err.reasons || []).map((t) => ({ text: t, fix: "questions" }));
  const target = { questions: ["questions", "Πήγαινε στις ερωτήσεις"], check: ["check", "Πήγαινε στον έλεγχο"], approve: [null, null] };
  return el("div", { class: "stack-sm", role: "alert" },
    el("div", { class: "alert-title", style: { color: "var(--amber)" }, text: "Η έγκριση δεν έγινε. Αυτοί είναι οι λόγοι:" }),
    items.map((it) => {
      const [step, label] = target[it.fix] || target.questions;
      return el("div", { class: "alert" }, icon("alert", { size: 22 }), el("div", { class: "stack-sm" }, el("p", { text: it.text }),
        step ? el("button", { type: "button", class: "btn btn-sm", onclick: () => studio.go(step) }, label, icon("arrow", { size: 16 })) : null));
    }));
}

function approvedView(studio) {
  const a = S.approved;
  const demobank = S.session && S.session.preset === "demobank";
  return el("div", { class: "stack" },
    el("section", { class: "card stack-sm approved reveal", role: "status" },
      el("div", { class: "approved-badge", "aria-hidden": "true" }, icon("shield", { size: 56 })),
      el("h2", { text: "Εγκρίθηκε" }),
      el("p", null, "Ο/Η ", el("strong", { text: a.approved_by }), " υπέγραψε τους κανόνες στις ", fmtTime(a.approved_at), "."),
      el("p", { class: "muted", text: `Σενάρια: ${a.scenarios.passed}/${a.scenarios.total} · αποτύπωμα policy: ${a.policy_sha256.slice(0, 12)}…` }),
      el("div", { class: "row" }, a.files.map((f) => el("a", { class: "btn", href: api.downloadUrl(S.sid, f.name), download: f.name }, icon("download", { size: 18 }), `Λήψη ${f.name}`)))),
    el("div", { class: "row-between" },
      el("button", { type: "button", class: "btn", onclick: () => studio.go("check") }, icon("back", { size: 18 }), "Πίσω στον έλεγχο"),
      el("div", { class: "row" },
        demobank ? el("button", { type: "button", class: "btn btn-hot btn-lg", onclick: () => studio.openAttack() }, icon("bolt", { size: 20 }), "Τρέξε επιθέσεις") : null,
        el("button", { type: "button", class: demobank ? "btn btn-ghost btn-lg" : "btn btn-primary btn-lg", onclick: () => { S.maxStep = Math.max(S.maxStep, 4); save(); studio.go("embed"); } }, "Ενσωμάτωση", icon("arrow", { size: 20 })))),
    demobank ? el("p", { class: "muted", text: "Στην επίθεση μπορείς να διαλέξεις την πολιτική που μόλις ενέκρινες." }) : null);
}

export async function renderApprove(host, studio) {
  const res = S.result;
  if (!S.sid || !res) {
    host.replaceChildren(el("div", { class: "stack" }, errorBox({ message: "Δεν υπάρχει πρόχειρο προς έγκριση. Γράψε πρώτα τους κανόνες." }),
      el("button", { type: "button", class: "btn", onclick: () => studio.go("check") }, "Πήγαινε στον έλεγχο")));
    return;
  }
  if (S.approved) { host.replaceChildren(approvedView(studio)); return; }

  const alertHost = el("div", { "aria-live": "polite" });
  const name = el("input", { type: "text", id: "ap-name", maxlength: "100", autocomplete: "name", "aria-describedby": "ap-name-h" });
  const check = el("input", { type: "checkbox", id: "ap-ok" });
  const btn = el("button", { type: "button", class: "btn btn-hot btn-lg", disabled: true }, icon("shield", { size: 22 }), "Έγκριση");
  const sync = () => { btn.disabled = !(name.value.trim() && check.checked); };
  name.addEventListener("input", sync);
  check.addEventListener("change", sync);
  btn.addEventListener("click", async () => {
    btn.disabled = true; btn.setAttribute("aria-busy", "true");
    try {
      const out = await api.approve(S.sid, name.value.trim(), check.checked ? "yes" : "no");
      S.approved = out; S.maxStep = Math.max(S.maxStep, 3); save();
      store.set("engine", S.mode);
      host.replaceChildren(approvedView(studio));
    } catch (e) {
      alertHost.replaceChildren(e.status === 409 && e.code === "approval_refused" ? refusalCards(e, studio) : errorBox(e, e.code === "session_not_found" ? "Η συνεδρία έληξε" : "Η έγκριση δεν ολοκληρώθηκε"));
      btn.removeAttribute("aria-busy"); sync();
    }
  });

  host.replaceChildren(el("div", { class: "stack" },
    el("div", null, el("h2", { text: "Έγκριση" }), el("p", { class: "muted" }, "Μόνο ", el("strong", { text: "άνθρωπος" }), " μπορεί να εγκρίνει. Το Copilot προτείνει, ο κώδικας επιβάλλει, ο άνθρωπος υπογράφει.")),
    S.quickNote ? el("div", { class: "alert alert-ok must-show" }, icon("info", { size: 22 }), el("div", null, el("div", { class: "alert-title", text: "Γρήγορη επίδειξη: έφτασες στην έγκριση" }),
      el("p", { text: "Όλα τα προηγούμενα βήματα έτρεξαν αυτόματα με τις απαντήσεις της καταγραφής. Η υπογραφή γίνεται πάντα με δικό σου κλικ." }))) : null,
    el("section", { class: "card stack-sm" }, el("h3", { text: "Τι εγκρίνεις" }), summaryLines(res),
      el("div", { class: "row" }, el("button", { type: "button", class: "btn btn-sm", onclick: () => studio.go("check") }, icon("back", { size: 16 }), "Ξαναδές τον έλεγχο"))),
    el("section", { class: "card stack", "aria-labelledby": "h-sign" },
      el("div", { class: "row-between" }, el("h3", { id: "h-sign", text: "Υπογραφή" }), el("span", { class: "tag tag-human" }, icon("user", { size: 16 }), "εδώ αποφασίζει ο άνθρωπος")),
      el("div", { class: "field" }, el("label", { for: "ap-name", text: "Όνομα εγκρίνοντος" }),
        el("p", { id: "ap-name-h", class: "hint", text: "Γράφεται στο approval.json μαζί με την ώρα και το αποτύπωμα των κανόνων." }), name),
      el("label", { class: "checkline", for: "ap-ok" }, check, el("span", { text: "Διάβασα τους κανόνες και τους εγκρίνω." })),
      alertHost,
      el("div", { class: "row-between" }, el("button", { type: "button", class: "btn", onclick: () => studio.go("check") }, icon("back", { size: 18 }), "Πίσω"), btn))));
}
