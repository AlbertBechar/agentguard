// pages/studio.js -- το Studio (#/studio): stepper Εφαρμογή → Ερωτήσεις → Έλεγχος → Έγκριση → Ενσωμάτωση → Δοκίμασε (+ Επίθεση ζωντανά).
import { el, errorBox, icon, modal, store } from "../ui.js";
import { S, STEPS, STEP_IDS, reached, reset, save } from "../studio/state.js";
import { renderApp } from "../studio/app.js";
import { renderQuestions } from "../studio/questions.js";
import { renderCheck } from "../studio/check.js";
import { renderApprove } from "../studio/approve.js";
import { renderEmbed } from "../studio/embed.js";
import { renderTry } from "../studio/try.js";
import { renderAttack } from "../studio/attack.js";
import { quickDemo } from "../studio/quick.js";

const RENDER = { app: renderApp, questions: renderQuestions, check: renderCheck, approve: renderApprove, embed: renderEmbed, try: renderTry };
const PRESET_BADGE = "δοκιμαστική εφαρμογή (όχι πραγματική εταιρία)";

export async function renderStudio(root, { query, navigate }) {
  const wrap = el("div", { class: "wrap section stack" });
  root.append(wrap);
  let seq = 0;

  const studio = {
    navigate,
    go(step) { S.view = "flow"; S.step = step; save(); return studio.paint(); },
    openAttack() { S.view = "attack"; save(); return studio.paint(); },
    resetAll() { reset(); store.set("engine", null); return studio.paint(); },
    async paint() {
      const mine = ++seq;
      const host = el("div", { id: "studio-body", "aria-live": "polite" });
      wrap.replaceChildren(header(), stepper(), host);
      try {
        if (S.view === "attack") await renderAttack(host, studio);
        else await RENDER[S.step](host, studio);
      } catch (err) {
        if (mine === seq) host.replaceChildren(errorBox(err, "Αυτό το βήμα δεν μπόρεσε να φορτώσει"));
      }
    },
  };

  function header() {
    const session = S.session;
    return el("div", { class: "row-between" },
      el("div", null, el("h1", { class: "h1", text: "Studio" }),
        el("p", { class: "muted" }, "Περιέγραψε τον βοηθό σου, δες τους κανόνες που προτείνει το AI και υπόγραψε.",
          session && (S.preset === "demobank" || S.preset === "democlinic") ? el("span", { class: "tag", style: { "margin-left": ".6rem" }, text: PRESET_BADGE }) : null)),
      S.sid ? el("button", { type: "button", class: "btn btn-sm", onclick: () => modal({
        title: "Ξεκίνα από την αρχή;", body: el("p", { text: "Θα χαθούν οι απαντήσεις, το πρόχειρο και η έγκριση αυτής της συνεδρίας." }),
        actions: [{ label: "Άκυρο" }, { label: "Ναι, ξεκίνα από την αρχή", class: "btn-primary", onClick: () => studio.resetAll() }] }) }, icon("refresh", { size: 16 }), "Ξεκίνα από την αρχή") : null);
  }

  function stepper() {
    const current = S.view === "attack" ? "attack" : S.step;
    const items = [...STEPS, ["attack", "Επίθεση"]];
    return el("nav", { "aria-label": "Βήματα του Studio" }, el("ol", { class: "stepper" }, items.map(([id, label], i) => {
      const isCurrent = id === current;
      const enabled = id === "attack" || reached(id);
      const done = id !== "attack" && STEP_IDS.indexOf(id) < STEP_IDS.indexOf(S.step) && reached(id) && S.view === "flow";
      const content = [el("span", { class: "n", "aria-hidden": "true" }, done ? icon("check", { size: 14 }) : String(i + 1)), el("span", { class: "lbl", text: label })];
      return el("li", null, el(enabled ? "button" : "span", { type: enabled ? "button" : null, class: `step${done ? " done" : ""}`, "aria-current": isCurrent ? "step" : null,
        disabled: !enabled && null, onclick: enabled ? () => (id === "attack" ? studio.openAttack() : studio.go(id)) : null }, content));
    })));
  }

  if (query.get("quick")) {                                       // «Γρήγορη επίδειξη»: αυτόματα ως την Έγκριση
    history.replaceState(null, "", "#/studio");                   // το refresh να μην την ξανατρέξει
    await quickDemo(wrap, studio);
    return;
  }
  if (S.mode) store.set("engine", S.mode);
  await studio.paint();
}
