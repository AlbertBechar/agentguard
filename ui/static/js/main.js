// main.js -- hash router (#/, #/studio, #/results), πλοήγηση, λειτουργία παρουσίασης, κατάσταση AI.
import { api } from "./api.js";
import { $, errorBox, icon, mem, store, toast, el } from "./ui.js";
import { renderHome } from "./pages/home.js";
import { renderStudio } from "./pages/studio.js";
import { renderResults } from "./pages/results.js";

const ROUTES = { "/": renderHome, "/studio": renderStudio, "/results": renderResults };
const ENGINE_LABEL = { replay: "Replay", live: "Live Gemini", offline: "Χωρίς AI" };

function parseHash() {
  const raw = location.hash.replace(/^#/, "") || "/";
  const [path, qs = ""] = raw.split("?");
  return { path: Object.prototype.hasOwnProperty.call(ROUTES, path) ? path : "/", query: new URLSearchParams(qs) };
}

export function navigate(hash) {
  if (location.hash === hash) render(true); else location.hash = hash;
}

let renderSeq = 0;
async function render(focus = true) {
  const seq = ++renderSeq;
  const { path, query } = parseHash();
  const main = $("#main");
  for (const a of document.querySelectorAll(".nav a")) {
    if (a.dataset.route === path) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  }
  main.replaceChildren();
  try {
    await ROUTES[path](main, { query, navigate });
  } catch (err) {
    if (seq === renderSeq) main.replaceChildren(el("div", { class: "wrap section" }, errorBox(err, "Η σελίδα δεν μπόρεσε να φορτώσει")));
  }
  if (seq === renderSeq && focus) { window.scrollTo(0, 0); main.focus({ preventScroll: true }); }
}

// ---------------------------------------------------------------- κατάσταση AI (ετικέτα πλοήγησης)
function paintEngine(engine) {
  const badge = $("#ai-badge");
  if (!badge) return;
  badge.dataset.engine = engine || "none";
  $("#ai-badge-text").textContent = ENGINE_LABEL[engine] || "AI: δεν επιλέχθηκε";
  badge.title = {
    replay: "Καταγεγραμμένη πραγματική εκτέλεση Gemini· λειτουργεί χωρίς δίκτυο (μόνο DemoBank).",
    live: "Ζωντανές κλήσεις προς το Gemini με το κλειδί του περιβάλλοντος.",
    offline: "Μόνο ευρετικοί κανόνες, χωρίς AI.",
  }[engine] || "Η μηχανή επιλέγεται στο Studio.";
}
store.on("engine", paintEngine);

async function loadStatus() {
  try {
    const st = await api.status();
    store.set("status", st);
    if (!store.get("engine")) store.set("engine", st.live_available ? "live" : st.replay_available ? "replay" : "offline");
  } catch {
    paintEngine(null);
  }
}

// ---------------------------------------------------------------- λειτουργία παρουσίασης (κουμπί και πλήκτρο P)
function setPresent(on) {
  document.documentElement.classList.toggle("present", on);
  const btn = $("#present-btn");
  if (btn) btn.setAttribute("aria-pressed", String(on));
  mem.set("present", on);
}

function isTyping(t) {
  return t && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName));
}

function init() {
  const btn = $("#present-btn");
  btn.prepend(icon("screen", { size: 18 }));
  btn.addEventListener("click", () => setPresent(!document.documentElement.classList.contains("present")));
  document.addEventListener("keydown", (e) => {
    if ((e.key === "p" || e.key === "P") && !e.ctrlKey && !e.metaKey && !e.altKey && !isTyping(e.target)) {
      setPresent(!document.documentElement.classList.contains("present"));
    }
  });
  const logo = $("#logo-slot");
  if (logo) logo.append(icon("shield", { size: 28 }));
  setPresent(mem.get("present", false) === true);
  paintEngine(null);
  window.addEventListener("hashchange", () => render(true));
  window.addEventListener("unhandledrejection", (e) => { e.preventDefault(); toast("Κάτι δεν πήγε καλά. Δοκίμασε ξανά.", "warn"); });
  window.addEventListener("error", () => toast("Κάτι δεν πήγε καλά στη σελίδα. Δοκίμασε ξανά.", "warn"));
  loadStatus();
  render(false);
}

init();
