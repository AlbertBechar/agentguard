// studio/quick.js -- «Γρήγορη επίδειξη»: DemoBank σε replay, αυτόματα Εφαρμογή → Ερωτήσεις → Έλεγχος και ΣΤΑΜΑΤΑ στην Έγκριση.
// Η έγκριση γίνεται πάντα με χειροκίνητο κλικ (ο άνθρωπος υπογράφει). Οι απαντήσεις είναι της καταγεγραμμένης εκτέλεσης:
// μόνο έτσι ταιριάζουν τα prompts με το replay (με τις «ασφαλείς προεπιλογές» το πρόχειρο έχει σφάλμα και η έγκριση αρνείται).
import { api } from "../api.js";
import { el, errorBox, icon, store } from "../ui.js";
import { S, reset, save } from "./state.js";

function progress(items, done, failed) {
  return el("div", { class: "wrap section stack" }, el("div", { class: "card stack", role: "status", "aria-live": "polite" },
    el("h2", { text: "Γρήγορη επίδειξη" }),
    el("ol", { class: "summary-lines" }, items.map((label, i) => el("li", null,
      i < done ? icon("check", { size: 18 }) : i === done && !failed ? el("span", { class: "spinner" }) : null, ` ${label}`)))));
}

export async function quickDemo(wrap, studio) {
  const steps = ["Φόρτωση της δοκιμαστικής DemoBank (όχι πραγματική εταιρία)", "Ερωτήσεις: απαντήσεις της καταγεγραμμένης εκτέλεσης", "Το Copilot γράφει και ελέγχει τους κανόνες (replay)"];
  reset();
  wrap.replaceChildren(progress(steps, 0));
  try {
    const status = await api.status();
    if (!status.replay_available) throw { message: "Δεν βρέθηκε το αρχείο replay της DemoBank, άρα η γρήγορη επίδειξη δεν μπορεί να τρέξει. Άνοιξε το Studio και διάλεξε «Χωρίς AI»." };
    const bank = (await api.presets()).presets.find((p) => p.id === "demobank");
    S.preset = "demobank"; S.mode = "replay"; store.set("engine", "replay");
    S.form = { company: bank.company, agent: bank.agent, tools: bank.tools_text, requirements: bank.requirements, roles: [...bank.roles], db_schema: bank.db_schema, context_attributes: bank.context_attributes };
    const sess = await api.createSession({ ...S.form, roles: S.form.roles, mode: "replay" });
    S.sid = sess.sid; S.session = sess; S.maxStep = 1; save();
    wrap.replaceChildren(progress(steps, 1));
    S.answers = { ...sess.recorded_answers };
    await api.answers(S.sid, S.answers);
    wrap.replaceChildren(progress(steps, 2));
    S.result = await api.generate(S.sid);
    S.quickNote = true;
    S.maxStep = S.result.summary.can_approve ? 3 : 2;
    save();
    await studio.go(S.result.summary.can_approve ? "approve" : "check");
  } catch (e) {
    wrap.replaceChildren(el("div", { class: "wrap section stack" }, errorBox(e, "Η γρήγορη επίδειξη δεν ολοκληρώθηκε"),
      el("div", { class: "row" }, el("button", { type: "button", class: "btn btn-primary", onclick: () => studio.go("app") }, "Άνοιξε το Studio", icon("arrow", { size: 18 })))));
  }
}
