// studio/try.js -- βήμα «Δοκίμασε»: τι θα αποφάσιζε ο φρουρός για μια κλήση. Δεν εκτελείται τίποτα, μόνο η απόφαση της μηχανής κανόνων.
import { api } from "../api.js";
import { el, errorBox, fmtClock, icon, waiting } from "../ui.js";
import { S, save } from "./state.js";

const VERDICT = {
  allow: ["allow", "check", "επιτρέπεται"],
  deny: ["deny", "x", "απαγορεύεται"],
  needs_approval: ["ask", "alert", "θέλει έγκριση ανθρώπου"],
};
const pretty = (o) => JSON.stringify(o, null, 2);

function parseObject(text, label) {
  const t = (text || "").trim();
  if (!t) return {};
  let v;
  try { v = JSON.parse(t); } catch { throw { message: `Τα «${label}» δεν είναι έγκυρο JSON.` }; }
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw { message: `Τα «${label}» πρέπει να είναι αντικείμενο JSON, π.χ. {"όνομα": "τιμή"}.` };
  return v;
}

function decisionCard(r) {
  const [cls, ic, label] = VERDICT[r.decision] || VERDICT.deny;
  return el("div", { class: `decision ${cls} reveal`, role: "status" },
    el("div", { class: "verdict" }, icon(ic, { size: 34 }), el("span", { text: label })),
    el("div", { class: "row" },
      el("span", { class: `tag ${r.stage === "approved" ? "tag-mint" : "tag-amber"}`, text: r.stage_el }),
      el("span", { class: "tag", text: `${r.user.role} → ${r.tool}` }),
      r.high_risk ? el("span", { class: "tag tag-amber" }, icon("alert", { size: 14 }), "υψηλού κινδύνου") : null),
    el("p", null, "Κανόνας: ", el("code", { text: r.rule }), r.matched_rules && r.matched_rules.length > 1 ? ` (και ${r.matched_rules.length - 1} ακόμα)` : ""),
    r.reason_el ? el("p", { text: r.reason_el }) : null,
    r.reason ? el("p", { class: "muted" }, "Λόγος από τον κανόνα: ", r.reason) : null,
    r.note ? el("p", { class: "muted", text: r.note }) : null,
    r.facts.demo_db.length ? el("p", { class: "muted", text: `Γεγονότα από τη δοκιμαστική βάση DemoBank: ${r.facts.demo_db.join(", ")}.` }) : null,
    r.facts.manual.length ? el("p", { class: "muted", text: `Γεγονότα που έδωσες εσύ: ${r.facts.manual.join(", ")}.` }) : null,
    r.lookup_errors.length ? el("p", { class: "alert-title", style: { color: "var(--amber)" }, text: `Δεν υπολογίστηκαν τα γεγονότα: ${r.lookup_errors.join(", ")} (η κλήση απορρίπτεται).` }) : null);
}

function historyTable(history) {
  if (!history || !history.length) return el("p", { class: "muted", text: "Εδώ θα εμφανίζονται οι τελευταίες 10 δοκιμές." });
  return el("div", { class: "table-wrap nowrap" }, el("table", null,
    el("thead", null, el("tr", null, ["Ώρα", "Ρόλος", "Εργαλείο", "Απόφαση", "Πολιτική"].map((h) => el("th", { text: h })))),
    el("tbody", null, history.map((h) => {
      const [, ic, label] = VERDICT[h.decision] || VERDICT.deny;
      return el("tr", null, el("td", { text: fmtClock(h.at) }), el("td", { text: h.role }), el("td", { class: "tool", text: h.tool + (h.after_untrusted ? " ⚠ μετά από μη έμπιστο" : "") }),
        el("td", null, el("span", { class: `cell ${h.decision === "allow" ? "cell-allow" : h.decision === "deny" ? "cell-deny" : "cell-cond"}` }, icon(ic, { size: 14 }), label)),
        el("td", { text: h.stage === "approved" ? "εγκεκριμένη" : "πρόχειρη" }));
    }))));
}

export async function renderTry(host, studio) {
  const res = S.result;
  if (!S.sid || !res) {
    host.replaceChildren(el("div", { class: "stack" }, errorBox({ message: "Δεν υπάρχει πολιτική ακόμα. Γράψε πρώτα τους κανόνες." }),
      el("button", { type: "button", class: "btn", onclick: () => studio.go("check") }, "Πήγαινε στον έλεγχο")));
    return;
  }
  const hints = res.try_hints;
  const tool0 = hints.tools[0];
  const f = S.tryForm = S.tryForm || { role: hints.roles[0], user_id: hints.user_ids[hints.roles[0]], tool: tool0 && tool0.name, args: tool0 ? pretty(tool0.example_args) : "{}", ctx: "", after: false, history: [], last: null };
  const out = el("div", { "aria-live": "polite" });
  const err = el("div", { "aria-live": "polite" });

  const role = el("select", { id: "t-role" }, hints.roles.map((r) => el("option", { value: r, selected: r === f.role }, r)));
  const uid = el("input", { type: "text", id: "t-uid", value: f.user_id || "", maxlength: "100" });
  const tool = el("select", { id: "t-tool" }, hints.tools.map((t) => el("option", { value: t.name, selected: t.name === f.tool }, t.name + (t.high_risk ? "  ⚠" : ""))));
  const args = el("textarea", { id: "t-args", class: "mono", rows: 5, spellcheck: "false" }, f.args);
  const ctx = el("textarea", { id: "t-ctx", class: "mono", rows: 3, spellcheck: "false" }, f.ctx);
  const after = el("input", { type: "checkbox", id: "t-after", checked: !!f.after });
  args.value = f.args; ctx.value = f.ctx;
  const persist = () => { Object.assign(f, { role: role.value, user_id: uid.value, tool: tool.value, args: args.value, ctx: ctx.value, after: after.checked }); save(); };
  role.addEventListener("change", () => { uid.value = hints.user_ids[role.value] || `user-${role.value}`; persist(); });
  tool.addEventListener("change", () => { const t = hints.tools.find((x) => x.name === tool.value); if (t) args.value = pretty(t.example_args); persist(); });
  for (const n of [uid, args, ctx, after]) n.addEventListener("input", persist);

  async function run(btn) {
    err.replaceChildren();
    let body;
    try {
      body = { role: role.value, user_id: uid.value.trim() || null, tool: tool.value, args: parseObject(args.value, "ορίσματα"),
        ctx: parseObject(ctx.value, "περιβάλλον"), after_untrusted: after.checked };
    } catch (e) { err.replaceChildren(errorBox(e, "Έλεγξε τη φόρμα")); return; }
    if (btn) btn.disabled = true;
    out.replaceChildren(waiting("Ο φρουρός αποφασίζει…"));
    try {
      const r = await api.tryCall(S.sid, body);
      f.history = r.history; f.last = r; save();
      out.replaceChildren(decisionCard(r), el("h3", { text: "Τελευταίες δοκιμές", style: { "margin-top": "1.4rem" } }), historyTable(r.history));
    } catch (e) {
      out.replaceChildren(errorBox(e, e.code === "session_not_found" ? "Η συνεδρία έληξε" : e.code === "no_draft" ? "Δεν υπάρχει πολιτική" : "Η δοκιμή δεν ολοκληρώθηκε"));
    } finally { if (btn) btn.disabled = false; }
  }

  function applyProbe(p) {
    role.value = p.role; uid.value = p.user_id; tool.value = p.tool; args.value = pretty(p.args); after.checked = !!p.after_untrusted; ctx.value = "";
    persist(); run(null);
  }

  const go = el("button", { type: "button", class: "btn btn-primary btn-lg", onclick: () => run(go) }, "Τι θα αποφάσιζε ο φρουρός;", icon("arrow", { size: 20 }));
  if (f.last) out.append(decisionCard(f.last), el("h3", { text: "Τελευταίες δοκιμές", style: { "margin-top": "1.4rem" } }), historyTable(f.history));
  else out.append(el("div", { class: "card muted", text: "Διάλεξε ρόλο και εργαλείο και ρώτα τον φρουρό. Τίποτα δεν εκτελείται στ' αλήθεια: βλέπεις μόνο την απόφαση της μηχανής κανόνων." }));

  const stage = S.approved ? ["tag-mint", "εγκεκριμένο"] : ["tag-amber", "πρόχειρο"];
  host.replaceChildren(el("div", { class: "stack" },
    el("div", { class: "row-between" }, el("div", null, el("h2", { text: "Δοκίμασε τον φρουρό" }),
      el("p", { class: "muted", text: "Ρώτα τι θα αποφάσιζε ο φρουρός για μια κλήση του βοηθού σου, με τους κανόνες που έγραψες." })),
      el("span", { class: `tag ${stage[0]}`, text: `Δοκιμάζεις το ${stage[1]}` })),
    el("div", { class: "grid-2" },
      el("section", { class: "card stack-sm", "aria-labelledby": "h-try" }, el("h3", { id: "h-try", text: "Η κλήση" }),
        el("div", { class: "form-grid" },
          el("div", { class: "field" }, el("label", { for: "t-role", text: "Ρόλος" }), role),
          el("div", { class: "field" }, el("label", { for: "t-uid", text: "Αναγνωριστικό χρήστη" }), uid),
          el("div", { class: "field span-all" }, el("label", { for: "t-tool", text: "Εργαλείο" }), tool),
          el("div", { class: "field span-all" }, el("label", { for: "t-args", text: "Ορίσματα (JSON)" }), args),
          el("div", { class: "field span-all" }, el("label", { for: "t-ctx", text: "Περιβάλλον / ιδιότητες (JSON, προαιρετικό)" }),
            el("p", { class: "hint", text: S.session && S.session.preset === "demobank" ? "Για τη DemoBank τα γεγονότα (π.χ. ιδιοκτήτης λογαριασμού) βρίσκονται αυτόματα από τη δοκιμαστική βάση. Ό,τι γράψεις εδώ υπερισχύει." : "Γεγονότα που χρειάζονται οι κανόνες, π.χ. {\"account_owner_id\": \"c1\"}. Τα δίνεις εσύ: δεν υπάρχει βάση για αυτή την εφαρμογή στη δοκιμή." }), ctx)),
        el("label", { class: "checkline", for: "t-after" }, after, el("span", null, "Πριν από αυτή την κλήση, ο βοηθός ", el("strong", { text: "διάβασε μη έμπιστο κείμενο" }), " (π.χ. ticket, σημείωμα, email).")),
        err, el("div", { class: "row" }, go)),
      el("section", { class: "card stack-sm", "aria-label": "Απόφαση" }, out)),
    hints.probes.length ? el("section", { class: "card stack-sm" }, el("h3", { text: "Δοκίμασε ό,τι θα έκανε ένας κακόβουλος" }),
      el("p", { class: "muted", text: "Έτοιμες δοκιμές για τα εργαλεία υψηλού κινδύνου ή τα μη έμπιστα: ρόλος χωρίς δικαίωμα, ή αφού ο βοηθός διάβασε μη έμπιστο κείμενο." }),
      el("div", { class: "row" }, hints.probes.map((p) => el("button", { type: "button", class: "btn btn-sm", onclick: () => applyProbe(p) }, icon("bolt", { size: 16 }), p.label)))) : null,
    el("div", { class: "row-between" },
      el("button", { type: "button", class: "btn", onclick: () => studio.go("embed") }, icon("back", { size: 18 }), "Πίσω"),
      S.session && S.session.preset === "demobank" ? el("button", { type: "button", class: "btn btn-ghost btn-lg", onclick: () => studio.openAttack() }, icon("bolt", { size: 20 }), "Δες την επίθεση ζωντανά") : null)));
}
