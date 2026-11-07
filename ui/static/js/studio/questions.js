// studio/questions.js -- βήμα «Ερωτήσεις»: μία κάρτα ανά ερώτηση, με ασφαλή προεπιλογή και «γιατί ρωτάμε».
import { api } from "../api.js";
import { el, errorBox, icon, waiting } from "../ui.js";
import { S, save } from "./state.js";
import { dryRunView } from "./dryrun.js";

/** Οι επιλογές που είναι «αποκλειστικές» (δεν συνδυάζονται με άλλες): «σε κανέναν» / «κανένα». */
function exclusiveOption(q) {
  if (q.key === "allow_tool" || q.key === "allow_tools_more") return q.options[0];
  if (q.key === "sensitive") return q.options[q.options.length - 1];
  return null;
}

/** Η ασφαλής προεπιλογή ως λίστα επιλογών (το default των πολλαπλών μπορεί να είναι «a, b»). */
function defaultSelection(q) {
  const d = String(q.default ?? "");
  if (q.options.includes(d)) return [d];
  const parts = d.split(",").map((x) => x.trim()).filter(Boolean);
  return parts.length && parts.every((p) => q.options.includes(p)) ? parts : [d];
}

function currentSelection(q, recorded) {
  const a = S.answers[q.id];
  if (a !== undefined) return Array.isArray(a) ? a : [a];
  if (recorded && recorded[q.id] !== undefined) return Array.isArray(recorded[q.id]) ? recorded[q.id] : [recorded[q.id]];
  return defaultSelection(q);
}

export async function renderQuestions(host, studio) {
  const sess = S.session;
  if (!sess) { host.replaceChildren(errorBox({ message: "Δεν υπάρχει ενεργή συνεδρία. Γύρνα στο βήμα «Εφαρμογή»." })); return; }
  if (!sess.questions) {                                           // refresh σε live πριν ζητηθούν οι ερωτήσεις
    host.replaceChildren(waiting("Φόρτωση ερωτήσεων…"));
    try { Object.assign(sess, await api.questions(S.sid)); save(); } catch (e) { host.replaceChildren(errorBox(e)); return; }
  }
  const replay = S.mode === "replay";
  const recorded = replay ? sess.recorded_answers || {} : null;
  const alertHost = el("div", { "aria-live": "polite" });
  const dryHost = el("div");

  // η τρέχουσα επιλογή κάθε ερώτησης κρατιέται στο S.answers μόλις ο χρήστης την αγγίξει
  const set = (q, value) => { S.answers[q.id] = value; save(); };

  function questionCard(q, idx) {
    const sel = new Set(currentSelection(q, recorded));
    const defaults = new Set(defaultSelection(q));
    const excl = exclusiveOption(q);
    const body = el("div", { class: "chips", role: q.multi ? "group" : "radiogroup", "aria-labelledby": `q-${q.id}` });
    if (!q.options.length) {                                       // ελεύθερο κείμενο (π.χ. ρόλοι)
      const input = el("input", { type: "text", id: `in-${q.id}`, value: [...sel].join(", "), "aria-labelledby": `q-${q.id}` });
      input.addEventListener("input", () => set(q, input.value));
      return card(q, idx, el("div", { class: "stack-sm" }, el("p", { class: "hint", text: `Προεπιλογή: ${q.default}` }), input));
    }
    const boxes = [];
    q.options.forEach((opt, i) => {
      const input = el("input", { type: q.multi ? "checkbox" : "radio", name: `q-${q.id}`, value: opt, checked: sel.has(opt) });
      boxes.push([opt, input]);
      input.addEventListener("change", () => {
        if (q.multi) {
          if (input.checked) boxes.forEach(([o, b]) => { if (excl && ((opt === excl && o !== excl) || (opt !== excl && o === excl))) b.checked = false; });
          const picked = boxes.filter(([, b]) => b.checked).map(([o]) => o);
          set(q, picked.length ? picked : [excl || q.default]);
        } else set(q, opt);
      });
      const tags = [];
      if (defaults.has(opt)) tags.push(el("span", { class: "tag tag-mint", text: "ασφαλής προεπιλογή" }));
      if (recorded && recorded[q.id] !== undefined && [].concat(recorded[q.id]).includes(opt)) tags.push(el("span", { class: "tag", text: "απάντηση καταγραφής" }));
      body.append(el("label", { class: "chip" }, input, el("span", { text: opt }), tags));
    });
    return card(q, idx, body);
  }

  function card(q, idx, control) {
    return el("article", { class: "card stack-sm reveal", style: { "--d": `${idx * 0.04}s` }, "aria-labelledby": `q-${q.id}` },
      el("div", { class: "row-between" }, el("h3", { id: `q-${q.id}`, text: `${idx + 1}. ${q.text}` }),
        q.human_decision ? el("span", { class: "tag tag-human" }, icon("user", { size: 16 }), "αποφασίζει ο άνθρωπος") : null),
      control,
      q.why ? el("details", { class: "sec" }, el("summary", { class: "muted", text: "Γιατί ρωτάμε;" }), el("p", { class: "muted", text: q.why })) : null);
  }

  async function submit(btn) {
    btn.disabled = true; btn.setAttribute("aria-busy", "true");
    const answers = {};
    for (const q of sess.questions) answers[q.id] = S.answers[q.id] !== undefined ? S.answers[q.id] : currentSelection(q, recorded).length > 1 ? currentSelection(q, recorded) : currentSelection(q, recorded)[0];
    try {
      await api.answers(S.sid, answers);
      S.answers = answers; S.result = null; S.approved = null; S.maxStep = Math.max(S.maxStep, 2); save();
      studio.go("check");
    } catch (e) {
      alertHost.replaceChildren(errorBox(e, e.code === "session_not_found" ? "Η συνεδρία έληξε" : "Οι απαντήσεις δεν αποθηκεύτηκαν"));
      btn.disabled = false; btn.removeAttribute("aria-busy");
    }
  }

  async function showDry(btn) {
    btn.disabled = true;
    try {
      const answers = {};
      for (const q of sess.questions) { const s = currentSelection(q, recorded); answers[q.id] = s.length > 1 ? s : s[0]; }
      await api.answers(S.sid, answers);
      const res = await api.dryRun(S.sid);
      dryHost.replaceChildren(dryRunView(res.dry_run, { open: true }));
    } catch (e) { dryHost.replaceChildren(errorBox(e)); } finally { btn.disabled = false; }
  }

  const submitBtn = el("button", { type: "button", class: "btn btn-primary btn-lg", onclick: () => submit(submitBtn) }, "Γράψε τους κανόνες", icon("arrow", { size: 20 }));
  const dryBtn = el("button", { type: "button", class: "btn btn-sm", onclick: () => showDry(dryBtn) }, icon("refresh", { size: 16 }), "Δες τι θα σταλεί με αυτές τις απαντήσεις");

  host.replaceChildren(el("div", { class: "stack" },
    el("div", null, el("h2", { text: "Λίγες ερωτήσεις πριν γραφτούν οι κανόνες" }),
      el("p", { class: "muted", text: "Κάθε ερώτηση έχει ασφαλή προεπιλογή: αν δεν απαντήσεις, επιλέγεται το πιο αυστηρό." })),
    replay ? el("div", { class: "alert alert-ok must-show" }, icon("info", { size: 22 }), el("div", null,
      el("div", { class: "alert-title", text: "Replay: προεπιλεγμένες είναι οι απαντήσεις της καταγραφής" }),
      el("p", { text: "Η καταγραφή ταιριάζει με τα prompts μόνο όταν οι απαντήσεις είναι ίδιες με της καταγεγραμμένης εκτέλεσης. Αν τις αλλάξεις, στον Έλεγχο θα δεις ότι το replay δεν ταιριάζει ακριβώς." }),
      el("div", { class: "row", style: { "margin-top": ".6rem" } },
        el("button", { type: "button", class: "btn btn-sm", onclick: () => {
          S.answers = {}; for (const q of sess.questions) { const d = defaultSelection(q); S.answers[q.id] = d.length > 1 ? d : d[0]; }
          save(); studio.paint();
        } }, "Δοκίμασε με τις ασφαλείς προεπιλογές"),
        el("button", { type: "button", class: "btn btn-sm", onclick: () => { S.answers = {}; save(); studio.paint(); } }, "Επαναφορά στις απαντήσεις της καταγραφής")))) : null,
    sess.questions.map(questionCard),
    S.mode === "live" ? el("div", { class: "stack-sm" }, dryBtn, dryHost) : null,
    alertHost,
    el("div", { class: "row-between" }, el("button", { type: "button", class: "btn", onclick: () => studio.go("app") }, icon("back", { size: 18 }), "Πίσω"), submitBtn)));
}
