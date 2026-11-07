// studio/app.js -- βήμα «Εφαρμογή»: παράδειγμα, φόρμα, εργαλεία, επιλογή μηχανής, «Τι θα σταλεί στο AI».
import { api } from "../api.js";
import { el, errorBox, expander, icon, store, toast, codeBlock, waiting } from "../ui.js";
import { S, dropSession, newForm, save } from "./state.js";
import { dryRunView } from "./dryrun.js";

let presetsCache = null;
const MAX_FILE = 1_500_000;

async function loadPresets() {
  if (!presetsCache) presetsCache = (await api.presets()).presets;
  return presetsCache;
}

const defaultMode = (presetId, status) =>
  presetId === "demobank" && status.replay_available ? "replay" : status.live_available ? "live" : "offline";

function formFromPreset(p) {
  return { company: p.company, agent: p.agent, tools: p.tools_text, requirements: p.requirements, roles: [...p.roles],
    db_schema: p.db_schema || "", context_attributes: p.context_attributes || null };
}

export async function renderApp(host, studio) {
  const status = store.get("status") || (await api.status().catch(() => ({})));
  const presets = await loadPresets();
  let parsed = null;                 // αποτέλεσμα του «Έλεγξε τα εργαλεία»
  const alertHost = el("div", { "aria-live": "polite" });

  const refresh = () => host.replaceChildren(build());

  function loadPreset(id) {
    dropSession();
    S.preset = id;
    S.form = id === "blank" ? newForm() : formFromPreset(presets.find((p) => p.id === id));
    S.mode = defaultMode(id, status);
    store.set("engine", S.mode);
    parsed = null;
    save();
    refresh();
  }

  function setMode(mode) {
    if (mode === S.mode) return;
    if (mode === "replay") {                                  // το replay ταιριάζει μόνο με τα δεδομένα της DemoBank
      dropSession();
      S.preset = "demobank";
      S.form = formFromPreset(presets.find((p) => p.id === "demobank"));
    } else if (S.session) dropSession();
    S.mode = mode;
    store.set("engine", mode);
    save();
    refresh();
  }

  function unlockCopy() {
    const target = status.live_available ? "live" : "offline";
    dropSession();
    S.mode = target;
    S.preset = S.preset === "demobank" ? "demobank" : S.preset;
    store.set("engine", target);
    save();
    toast(target === "live" ? "Τα πεδία ξεκλείδωσαν: δοκίμασε με τα δικά σου δεδομένα στο ζωντανό Gemini."
      : "Τα πεδία ξεκλείδωσαν. Δεν υπάρχει κλειδί Gemini, οπότε επιλέχθηκε «Χωρίς AI».", "ok", 6000);
    refresh();
  }

  function bind(field, node, transform = (v) => v) {
    node.addEventListener("input", () => { S.form[field] = transform(node.value); if (S.session) { dropSession(); save(); } save(); });
    return node;
  }

  async function checkTools(btn, out) {
    btn.disabled = true;
    out.replaceChildren(waiting("Έλεγχος εργαλείων…"));
    try {
      parsed = await api.parseTools(S.form.tools);
      out.replaceChildren(toolsTable(parsed));
    } catch (e) {
      parsed = null;
      out.replaceChildren(errorBox(e, "Τα εργαλεία δεν διαβάστηκαν"));
    } finally { btn.disabled = false; }
  }

  function toolsTable(res) {
    const formats = Object.entries(res.formats).map(([k, n]) => `${k}: ${n}`).join(", ");
    return el("div", { class: "stack-sm" },
      el("div", { class: "alert alert-ok" }, icon("check", { size: 22 }),
        el("div", null, el("div", { class: "alert-title", text: `Βρέθηκαν ${res.count} εργαλεία` }), el("p", { class: "muted", text: `Μορφή: ${formats}` }))),
      el("div", { class: "table-wrap" }, el("table", null,
        el("thead", null, el("tr", null, ["Εργαλείο", "Περιγραφή", "Ορίσματα"].map((h) => el("th", { text: h })))),
        el("tbody", null, res.tools.map((t) => el("tr", null,
          el("td", { class: "tool", text: t.name }), el("td", { text: t.description || "—" }),
          el("td", { text: t.params.map((p) => p.name + (p.required ? "*" : "")).join(", ") || "—" })))))));
  }

  function rolesField(locked) {
    const list = el("div", { class: "chips", "aria-live": "polite" });
    const input = el("input", { type: "text", id: "role-in", "aria-label": "Νέος ρόλος", disabled: locked, maxlength: "60" });
    const paint = () => {
      list.replaceChildren(...S.form.roles.map((r, i) => el("span", { class: "chip", "aria-pressed": "true" }, r,
        locked ? null : el("button", { type: "button", class: "x", "aria-label": `Αφαίρεση ρόλου ${r}`, onclick: () => { S.form.roles.splice(i, 1); if (S.session) dropSession(); save(); paint(); } }, icon("x", { size: 14 })))));
      if (!S.form.roles.length) list.append(el("span", { class: "muted", text: "Κανένας ρόλος: το Copilot θα ρωτήσει." }));
    };
    const add = () => {
      const v = input.value.trim();
      if (v && !S.form.roles.includes(v)) { S.form.roles.push(v); if (S.session) dropSession(); save(); }
      input.value = ""; paint();
    };
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); add(); } });
    paint();
    return el("div", { class: "field span-all" }, el("label", { for: "role-in", text: "Ρόλοι χρηστών (προαιρετικό)" }),
      el("p", { class: "hint", text: "Π.χ. customer, teller, admin. Πάτα Enter για να προσθέσεις." }),
      el("div", { class: "row" }, input, el("button", { type: "button", class: "btn btn-sm", disabled: locked, onclick: add }, "Προσθήκη")), list);
  }

  function field(id, label, node, hint) {
    return el("div", { class: "field" }, el("label", { for: id, text: label }), hint ? el("p", { class: "hint", text: hint }) : null, node);
  }

  function presetCard() {
    const items = [...presets.map((p) => [p.id, p.title, p.badge]), ["blank", "Κενή φόρμα", "Η δική σου εφαρμογή"]];
    return el("section", { class: "card stack-sm", "aria-labelledby": "h-preset" },
      el("h2", { id: "h-preset", text: "1. Διάλεξε παράδειγμα ή γράψε τη δική σου εφαρμογή" }),
      el("div", { class: "choices", role: "radiogroup", "aria-labelledby": "h-preset" }, items.map(([id, title, sub]) =>
        el("label", { class: "choice" }, el("input", { type: "radio", name: "preset", value: id, checked: S.preset === id, onchange: () => loadPreset(id) }),
          el("span", null, el("span", { class: "choice-title", text: title }), el("span", { class: "choice-sub", text: sub }))))));
  }

  function formCard() {
    const locked = S.mode === "replay";
    const f = S.form;
    const toolsOut = el("div", { "aria-live": "polite" });
    if (parsed) toolsOut.append(toolsTable(parsed));
    const fileIn = el("input", { type: "file", accept: ".json,application/json,text/plain", hidden: true, tabindex: "-1" });
    const ta = (id, field, rows, mono) => bind(field, el("textarea", { id, rows, class: mono ? "mono" : "", disabled: locked, spellcheck: "false" }, f[field]));
    const toolsTa = ta("f-tools", "tools", 10, true);
    toolsTa.value = f.tools;
    fileIn.addEventListener("change", async () => {
      const file = fileIn.files && fileIn.files[0];
      if (!file) return;
      if (file.size > MAX_FILE) { toolsOut.replaceChildren(errorBox({ message: "Το αρχείο είναι πολύ μεγάλο (όριο 1,5 MB)." })); return; }
      toolsTa.value = await file.text(); S.form.tools = toolsTa.value; parsed = null; toolsOut.replaceChildren(); if (S.session) dropSession(); save();
      fileIn.value = "";
    });
    const checkBtn = el("button", { type: "button", class: "btn btn-sm", onclick: () => checkTools(checkBtn, toolsOut) }, icon("check", { size: 16 }), "Έλεγξε τα εργαλεία");
    const company = bind("company", el("input", { type: "text", id: "f-company", disabled: locked, value: f.company, maxlength: "200" }));
    const agent = bind("agent", el("textarea", { id: "f-agent", rows: 2, disabled: locked }, f.agent));
    const req = ta("f-req", "requirements", 6, false);
    const schema = ta("f-schema", "db_schema", 5, true);
    return el("section", { class: "card stack", "aria-labelledby": "h-form" },
      el("h2", { id: "h-form", text: "2. Περιέγραψε τον βοηθό σου" }),
      locked ? el("div", { class: "alert alert-ok must-show" }, icon("lock", { size: 22 }),
        el("div", null, el("div", { class: "alert-title", text: "Σε replay τα πεδία είναι κλειδωμένα" }),
          el("p", { text: "Το replay είναι καταγραφή πραγματικής εκτέλεσης στη δοκιμαστική DemoBank και ταιριάζει με το περιεχόμενο των prompts, γι' αυτό δεν αλλάζει τίποτα εδώ." }),
          el("div", { class: "row", style: { "margin-top": ".75rem" } },
            el("button", { type: "button", class: "btn btn-sm btn-ghost", onclick: unlockCopy }, icon("refresh", { size: 16 }), "Αντίγραψε στη ζωντανή δοκιμή με τα δικά μου δεδομένα")))) : null,
      el("div", { class: "form-grid" },
        field("f-company", "Εταιρία", company), field("f-agent", "Τι κάνει ο βοηθός", agent),
        el("div", { class: "field span-all" }, el("label", { for: "f-tools", text: "Εργαλεία του βοηθού (JSON)" }),
          el("p", { class: "hint", text: "Δέχεται απλή λίστα, Gemini, OpenAI, MCP ή OpenAPI. Δεν εκτελείται τίποτα, μόνο διαβάζονται τα ονόματα και οι περιγραφές." }),
          toolsTa,
          el("div", { class: "row" }, el("button", { type: "button", class: "btn btn-sm", disabled: locked, onclick: () => fileIn.click() }, icon("upload", { size: 16 }), "Φόρτωσε αρχείο"), fileIn, checkBtn), toolsOut),
        el("div", { class: "span-all" }, field("f-req", "Απαιτήσεις ασφαλείας", req, "Με δικά σου λόγια: ποιος επιτρέπεται να κάνει τι.")),
        el("div", { class: "span-all" }, field("f-schema", "Δομή βάσης (προαιρετικό)", schema, "Μόνο σχήμα (CREATE TABLE), ποτέ δεδομένα.")),
        rolesField(locked)),
      S.form.context_attributes ? el("p", { class: "muted sec", text: `Γεγονότα πλαισίου από το παράδειγμα: ${Object.keys(S.form.context_attributes).join(", ")}.` }) : null);
  }

  function engineCard() {
    const clinic = S.preset !== "demobank";
    const opt = (id, title, sub, disabled, extra) => el("label", { class: "choice", "aria-disabled": disabled ? "true" : "false" },
      el("input", { type: "radio", name: "mode", value: id, checked: S.mode === id, disabled, onchange: () => setMode(id) }),
      el("span", null, el("span", { class: "choice-title", text: title }), el("span", { class: "choice-sub", text: sub }), extra || null));
    const liveHelp = !status.live_available ? el("details", { class: "sec" }, el("summary", { text: "Πώς το ενεργοποιώ;" }),
      el("div", { class: "stack-sm", style: { "margin-top": ".5rem" } },
        el("p", { text: "Όρισε τη μεταβλητή περιβάλλοντος AI_STUDIO_API_KEY πριν ξεκινήσεις τον server. Το κλειδί δεν πληκτρολογείται ποτέ εδώ." }),
        codeBlock('export AI_STUDIO_API_KEY="το-κλειδί-σου"\npython ui/server.py', { title: "macOS / Linux" }),
        codeBlock('$env:AI_STUDIO_API_KEY="το-κλειδί-σου"\npython ui/server.py', { title: "Windows PowerShell" }))) : null;
    return el("section", { class: "card stack-sm", "aria-labelledby": "h-engine" },
      el("h2", { id: "h-engine", text: "3. Διάλεξε μηχανή" }),
      el("div", { class: "choices", role: "radiogroup", "aria-labelledby": "h-engine" },
        opt("replay", "Replay", "Καταγεγραμμένη πραγματική εκτέλεση Gemini· χωρίς δίκτυο· μόνο DemoBank.", !status.replay_available,
          !status.replay_available ? el("span", { class: "choice-sub", text: "Δεν βρέθηκε το αρχείο καταγραφής." }) : (clinic ? el("span", { class: "choice-sub", text: "Επιλέγοντάς το φορτώνεται η DemoBank." }) : null)),
        opt("live", "Ζωντανό Gemini", status.live_available ? "Ζωντανές κλήσεις με το κλειδί του περιβάλλοντος. Θα δεις πρώτα τι στέλνεται." : "Ανενεργό: δεν βρέθηκε το AI_STUDIO_API_KEY στο περιβάλλον του server.", !status.live_available, liveHelp),
        opt("offline", "Χωρίς AI", "Μόνο ευρετικοί κανόνες. Το πρόχειρο θέλει περισσότερη ανθρώπινη συμπλήρωση.", false)));
  }

  function reviewCard() {
    const go = el("button", { type: "button", class: "btn btn-primary", onclick: async () => {
      go.disabled = true;
      try {
        const q = await api.questions(S.sid);
        Object.assign(S.session, q); S.reviewing = false; S.maxStep = Math.max(S.maxStep, 1); save(); studio.go("questions");
      } catch (e) { alertHost.replaceChildren(errorBox(e)); go.disabled = false; }
    } }, "Εντάξει, στείλε στο Gemini και συνέχισε", icon("arrow", { size: 18 }));
    return el("section", { class: "card stack", "aria-labelledby": "h-review" },
      el("h2", { id: "h-review", text: "Τι θα σταλεί στο Gemini" }),
      el("p", { class: "muted", text: "Ως εδώ δεν έχει σταλεί τίποτα. Διάβασε τα prompts και πάτα «στείλε» μόνο αν συμφωνείς." }),
      dryRunView(S.session.dry_run, { open: true }),
      el("div", { class: "row" }, el("button", { type: "button", class: "btn", onclick: () => { S.reviewing = false; save(); refresh(); } }, icon("back", { size: 18 }), "Πίσω στη φόρμα"), go),
      alertHost);
  }

  function actionRow() {
    const btn = el("button", { type: "button", class: "btn btn-primary btn-lg" }, S.mode === "live" ? "Συνέχεια: δες τι θα σταλεί" : "Συνέχεια", icon("arrow", { size: 20 }));
    btn.addEventListener("click", async () => {
      const f = S.form;
      const missing = [["company", "εταιρία"], ["agent", "τι κάνει ο βοηθός"], ["tools", "εργαλεία"], ["requirements", "απαιτήσεις"]].filter(([k]) => !String(f[k] || "").trim());
      if (!S.mode) { alertHost.replaceChildren(errorBox({ message: "Διάλεξε πρώτα μηχανή." })); return; }
      if (missing.length) { alertHost.replaceChildren(errorBox({ message: `Συμπλήρωσε: ${missing.map((m) => m[1]).join(", ")}.` }, "Λείπουν στοιχεία")); return; }
      btn.disabled = true; btn.setAttribute("aria-busy", "true");
      alertHost.replaceChildren(waiting("Δημιουργία συνεδρίας…"));
      try {
        const res = await api.createSession({ company: f.company, agent: f.agent, tools: f.tools, requirements: f.requirements,
          roles: f.roles.length ? f.roles : null, db_schema: f.db_schema.trim() ? f.db_schema : null, context_attributes: f.context_attributes, mode: S.mode });
        const keep = S.preset;
        dropSession();
        Object.assign(S, { sid: res.sid, session: res, preset: keep || res.preset || "blank" });
        store.set("engine", S.mode);
        if (S.mode === "live") { S.reviewing = true; save(); refresh(); return; }
        S.maxStep = 1; save(); studio.go("questions");
      } catch (e) {
        alertHost.replaceChildren(errorBox(e, e.code === "no_api_key" ? "Δεν υπάρχει κλειδί Gemini" : "Δεν ήταν δυνατή η συνέχεια"));
        btn.disabled = false; btn.removeAttribute("aria-busy");
      }
    });
    return el("div", { class: "stack-sm" }, alertHost, el("div", { class: "row-between" },
      el("p", { class: "muted", text: "Τίποτα δεν στέλνεται εκτός υπολογιστή σου σε Replay ή Χωρίς AI." }), btn));
  }

  function build() {
    if (S.reviewing && S.session) return reviewCard();
    return el("div", { class: "stack" }, presetCard(), S.preset ? formCard() : el("p", { class: "muted", text: "Διάλεξε ένα παράδειγμα για να ξεκινήσεις." }),
      S.preset ? engineCard() : null, S.preset ? actionRow() : null);
  }

  refresh();
}
