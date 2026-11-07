// ui.js -- μικρά helpers του UI. Ποτέ HTML ως κείμενο προς ερμηνεία: ό,τι προέρχεται από εργαλεία, περιγραφές, Copilot,
// policy ή σφάλματα (μη έμπιστο κείμενο) μπαίνει ΜΟΝΟ με textContent / createTextNode.

const SVG_NS = "http://www.w3.org/2000/svg";
const URL_OK = /^(#|\/(?!\/)|https?:\/\/)/i;   // όχι javascript:, όχι data:

export const prefersReducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// ---------------------------------------------------------------- DOM
function append(node, items) {
  for (const c of items.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

/** el("div", {class: "x", text: "..."}, παιδιά...) -- το πρώτο όρισμα attrs μπορεί να παραλειφθεί. */
export function el(tag, attrs, ...children) {
  if (attrs instanceof Node || typeof attrs === "string" || typeof attrs === "number" || Array.isArray(attrs)) {
    children.unshift(attrs);
    attrs = null;
  }
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "style" && typeof v === "object") { for (const [p, val] of Object.entries(v)) node.style.setProperty(p, val); }
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
    else if ((k === "href" || k === "src") && !URL_OK.test(String(v))) continue;
    else if (v === true) node.setAttribute(k, "");
    else node.setAttribute(k, String(v));
  }
  append(node, children);
  return node;
}

export const $ = (sel, root = document) => root.querySelector(sel);

// ---------------------------------------------------------------- εικονίδια (inline SVG, χωρίς εικόνες)
const ICONS = {
  shield: [["path", { d: "M12 3l7 3v5.5c0 4.4-2.9 8.1-7 9.5-4.1-1.4-7-5.1-7-9.5V6l7-3z" }], ["path", { d: "M8.8 12.2l2.2 2.2 4.2-4.4" }]],
  check: [["path", { d: "M5 12.5l4.5 4.5L19 7.5" }]],
  x: [["path", { d: "M6 6l12 12M18 6L6 18" }]],
  half: [["circle", { cx: 12, cy: 12, r: 8 }], ["path", { d: "M12 4a8 8 0 0 1 0 16z", fill: "currentColor" }]],
  alert: [["path", { d: "M12 3.5l9.5 16.5h-19L12 3.5z" }], ["path", { d: "M12 10v4.5" }], ["path", { d: "M12 17.4v.1" }]],
  info: [["circle", { cx: 12, cy: 12, r: 9 }], ["path", { d: "M12 11v5.5" }], ["path", { d: "M12 7.6v.1" }]],
  arrow: [["path", { d: "M5 12h14M13 6l6 6-6 6" }]],
  back: [["path", { d: "M19 12H5M11 6l-6 6 6 6" }]],
  copy: [["rect", { x: 9, y: 9, width: 11, height: 11, rx: 2 }], ["path", { d: "M5 15V6a2 2 0 0 1 2-2h9" }]],
  download: [["path", { d: "M12 4v11M7.5 11l4.5 4.5 4.5-4.5M5 20h14" }]],
  upload: [["path", { d: "M12 16V5M7.5 9L12 4.5 16.5 9M5 20h14" }]],
  play: [["path", { d: "M8 5.5l11 6.5-11 6.5v-13z", fill: "currentColor" }]],
  lock: [["rect", { x: 5, y: 11, width: 14, height: 9, rx: 2 }], ["path", { d: "M8 11V8a4 4 0 0 1 8 0v3" }]],
  file: [["path", { d: "M7 3h7l4 4v14H7V3z" }], ["path", { d: "M14 3v4h4M9.5 13h5M9.5 16.5h5" }]],
  code: [["path", { d: "M8.5 7L3.5 12l5 5M15.5 7l5 5-5 5" }]],
  user: [["circle", { cx: 12, cy: 8, r: 3.6 }], ["path", { d: "M4.5 20c.9-3.6 3.8-5.4 7.5-5.4s6.6 1.8 7.5 5.4" }]],
  bolt: [["path", { d: "M13 3L5 13.5h6L10 21l8-10.5h-6L13 3z" }]],
  screen: [["rect", { x: 3, y: 4, width: 18, height: 12, rx: 2 }], ["path", { d: "M8 20h8M12 16v4" }]],
  refresh: [["path", { d: "M20 11a8 8 0 0 0-14.3-4M4 4v4h4M4 13a8 8 0 0 0 14.3 4M20 20v-4h-4" }]],
  chevron: [["path", { d: "M8 10l4 4 4-4" }]],
};

export function icon(name, { size = 20, cls = "" } = {}) {
  const svg = document.createElementNS(SVG_NS, "svg");
  for (const [k, v] of Object.entries({ viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor",
    "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false" })) svg.setAttribute(k, v);
  if (cls) svg.setAttribute("class", cls);
  for (const [tag, attrs] of ICONS[name] || ICONS.info) {
    const n = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    svg.append(n);
  }
  return svg;
}

// ---------------------------------------------------------------- μικρή κατάσταση και αποθήκευση περιόδου
export const store = (() => {
  const state = {}; const subs = {};
  return {
    get: (k) => state[k],
    set(k, v) { state[k] = v; (subs[k] || []).forEach((f) => f(v)); },
    on(k, f) { (subs[k] = subs[k] || []).push(f); return () => { subs[k] = subs[k].filter((x) => x !== f); }; },
  };
})();

/** sessionStorage με try/catch: η σελίδα δουλεύει και χωρίς αυτό. */
export const mem = {
  get(k, d = null) { try { const v = sessionStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { sessionStorage.setItem(k, JSON.stringify(v)); } catch { /* αγνοείται */ } },
  del(k) { try { sessionStorage.removeItem(k); } catch { /* αγνοείται */ } },
};

// ---------------------------------------------------------------- ειδοποιήσεις, παράθυρα
export function toast(message, kind = "info", ms = 4500) {
  const host = document.getElementById("toasts");
  if (!host) return;
  const t = el("div", { class: `toast ${kind}`, role: kind === "warn" ? "alert" : "status" },
    icon(kind === "ok" ? "check" : kind === "warn" ? "alert" : "info"), el("span", { text: message }));
  host.append(t);
  setTimeout(() => t.remove(), ms);
}

/** Σφάλμα (ApiError ή οτιδήποτε) ως κατανοητό amber μήνυμα στα ελληνικά. Ποτέ stack trace. */
export function errorBox(err, title = "Κάτι δεν πήγε καλά") {
  const message = err && err.message && !/^\s*at\s/.test(err.message) ? err.message : "Παρουσιάστηκε ένα απρόσμενο πρόβλημα. Δοκίμασε ξανά.";
  const reasons = err && Array.isArray(err.reasons) ? err.reasons : [];
  return el("div", { class: "alert", role: "alert" }, icon("alert", { size: 24 }),
    el("div", null,
      el("div", { class: "alert-title", text: title }),
      el("p", { text: message }),
      reasons.length ? el("ul", null, reasons.map((r) => el("li", { text: r }))) : null));
}

export function modal({ title, body, actions = [] }) {
  const previous = document.activeElement;
  let backdrop;
  const close = () => { backdrop.remove(); document.removeEventListener("keydown", onKey, true); if (previous && previous.focus) previous.focus(); };
  const focusables = () => [...backdrop.querySelectorAll("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])")].filter((n) => !n.disabled);
  function onKey(e) {
    if (e.key === "Escape") { e.stopPropagation(); close(); }
    if (e.key === "Tab") {
      const f = focusables(); if (!f.length) return;
      const first = f[0]; const last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }
  const buttons = actions.map((a) => el("button", { type: "button", class: `btn ${a.class || ""}`, onclick: () => { if (a.onClick) a.onClick(); if (a.close !== false) close(); } }, a.label));
  backdrop = el("div", { class: "backdrop", onclick: (e) => { if (e.target === backdrop) close(); } },
    el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title }, el("h3", { text: title }), body, el("div", { class: "modal-actions" }, buttons)));
  document.body.append(backdrop);
  document.addEventListener("keydown", onKey, true);
  (focusables()[0] || backdrop).focus();
  return { close };
}

/** tabs([{label, render: () => Node}], αρχικό) -- ARIA tablist με βέλη/Home/End. */
let tabSeq = 0;
export function tabs(items, initial = 0, onSelect = null) {
  const id = `tabs${++tabSeq}`;
  const list = el("div", { role: "tablist" });
  const panel = el("div", { role: "tabpanel", id: `${id}-p`, tabindex: "0" });
  const buttons = items.map((it, i) => el("button", { type: "button", role: "tab", id: `${id}-t${i}`, "aria-controls": `${id}-p`, tabindex: "-1", "aria-selected": "false",
    onclick: () => select(i), onkeydown: (e) => {
      const n = items.length; let to = null;
      if (e.key === "ArrowRight") to = (i + 1) % n; else if (e.key === "ArrowLeft") to = (i - 1 + n) % n;
      else if (e.key === "Home") to = 0; else if (e.key === "End") to = n - 1;
      if (to !== null) { e.preventDefault(); select(to); buttons[to].focus(); }
    } }, it.label));
  function select(i) {
    buttons.forEach((b, j) => { b.setAttribute("aria-selected", String(i === j)); b.setAttribute("tabindex", i === j ? "0" : "-1"); });
    panel.setAttribute("aria-labelledby", `${id}-t${i}`);
    panel.replaceChildren(items[i].render());
    if (onSelect) onSelect(i);
  }
  list.append(...buttons);
  select(initial);
  return el("div", { class: "tabs" }, list, panel);
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = el("textarea", { "aria-hidden": "true", tabindex: "-1" });
    ta.value = text;
    ta.style.setProperty("position", "fixed"); ta.style.setProperty("opacity", "0");
    document.body.append(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch { ok = false; }
    ta.remove();
    if (!ok) { toast("Η αντιγραφή δεν στάθηκε δυνατή· επίλεξε το κείμενο και πάτα Ctrl+C.", "warn"); return false; }
  }
  toast("Αντιγράφηκε στο πρόχειρο.", "ok", 2200);
  return true;
}

/** Μπλοκ κώδικα με κουμπί αντιγραφής. `text` μπαίνει με textContent. */
export function codeBlock(text, { title = "", copy = true } = {}) {
  const pre = el("pre", { tabindex: "0" }, el("code", { text }));
  pre.querySelector("code").style.setProperty("background", "none"); pre.querySelector("code").style.setProperty("padding", "0");
  return el("div", { class: "code" },
    title || copy ? el("div", { class: "code-head" }, el("span", { text: title }),
      copy ? el("button", { type: "button", class: "btn btn-sm", onclick: () => copyText(text) }, icon("copy", { size: 16 }), "Αντιγραφή") : null) : null,
    pre);
}

export function expander(summary, body, open = false) {
  return el("details", { class: "exp", open }, el("summary", { text: summary }), el("div", { class: "exp-body" }, body));
}

export function waiting(title, sub = "") {
  return el("div", { class: "card waiting", role: "status", "aria-live": "polite" }, el("span", { class: "spinner" }),
    el("div", null, el("div", { class: "w-title", text: title }), sub ? el("div", { class: "muted", text: sub }) : null));
}

/** Count-up στους αριθμούς (σεβασμός στο prefers-reduced-motion). */
export function countUp(node, to, { from = 0, ms = 900, format = (n) => String(Math.round(n)) } = {}) {
  if (prefersReducedMotion() || from === to) { node.textContent = format(to); return; }
  const t0 = performance.now();
  const tick = (now) => {
    const p = Math.min(1, (now - t0) / ms);
    node.textContent = format(from + (to - from) * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(tick);
  };
  node.textContent = format(from);
  requestAnimationFrame(tick);
}

export function fmtTime(iso) {
  try { return new Date(iso).toLocaleString("el-GR", { dateStyle: "medium", timeStyle: "short" }); } catch { return String(iso); }
}

export function setBusy(button, busy, label) {
  if (!button) return;
  button.disabled = !!busy;
  button.setAttribute("aria-busy", String(!!busy));
  if (label !== undefined) button.dataset.label = label;
}
