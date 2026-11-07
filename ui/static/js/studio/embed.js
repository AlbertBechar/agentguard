// studio/embed.js -- βήμα «Ενσωμάτωση»: snippets Python / Node / HTTP με κουμπί αντιγραφής.
import { api } from "../api.js";
import { codeBlock, el, errorBox, icon, tabs, waiting } from "../ui.js";
import { S, save } from "./state.js";

const LANGS = [["python", "Python"], ["node", "Node"], ["http", "HTTP"]];

export async function renderEmbed(host, studio) {
  if (!S.sid || !S.result) {
    host.replaceChildren(el("div", { class: "stack" }, errorBox({ message: "Δεν υπάρχει πολιτική ακόμα. Γράψε πρώτα τους κανόνες." }),
      el("button", { type: "button", class: "btn", onclick: () => studio.go("check") }, "Πήγαινε στον έλεγχο")));
    return;
  }
  const cache = {};
  const render = (lang) => () => {
    const box = el("div", { class: "stack-sm" }, waiting("Φόρτωση κώδικα…"));
    (cache[lang] = cache[lang] || api.snippet(S.sid, lang)).then((s) => {
      box.replaceChildren(
        s.note ? el("div", { class: lang === "python" ? "alert alert-ok" : "alert must-show" }, icon(lang === "python" ? "info" : "alert", { size: 22 }),
          el("div", null, lang === "python" ? null : el("div", { class: "alert-title", text: "Δεν έχει εκτελεστεί ή δοκιμαστεί" }), el("p", { text: s.note }))) : null,
        codeBlock(s.code, { title: lang === "python" ? "guard.py (Python)" : lang === "node" ? "guard.mjs (Node)" : "curl (HTTP)" }));
    }).catch((e) => box.replaceChildren(errorBox(e)));
    return box;
  };
  host.replaceChildren(el("div", { class: "stack" },
    el("div", null, el("h2", { text: "Ενσωμάτωση" }),
      el("p", { class: "muted", text: "Αυτός είναι όλος ο κώδικας που προσθέτει η εταιρία." })),
    S.approved ? null : el("div", { class: "alert" }, icon("alert", { size: 22 }), el("p", { text: "Η πολιτική δεν έχει εγκριθεί ακόμα: το policy.json θα υπάρχει μόνο μετά την υπογραφή." })),
    el("section", { class: "card" }, tabs(LANGS.map(([id, label]) => ({ label, render: render(id) })), 0)),
    el("div", { class: "row-between" },
      el("button", { type: "button", class: "btn", onclick: () => studio.go("approve") }, icon("back", { size: 18 }), "Πίσω"),
      el("button", { type: "button", class: "btn btn-primary btn-lg", onclick: () => { S.maxStep = Math.max(S.maxStep, 5); save(); studio.go("try"); } }, "Δοκίμασε τον φρουρό", icon("arrow", { size: 20 })))));
}
