// studio/state.js -- η κατάσταση του Studio. Κρατιέται στον server (sid) και στο sessionStorage (δεν χάνεται με refresh).
import { mem } from "../ui.js";

const KEY = "ag.studio.v1";
export const STEPS = [
  ["app", "Εφαρμογή"], ["questions", "Ερωτήσεις"], ["check", "Έλεγχος"],
  ["approve", "Έγκριση"], ["embed", "Ενσωμάτωση"], ["try", "Δοκίμασε"],
];
export const STEP_IDS = STEPS.map(([id]) => id);

const blankForm = () => ({ company: "", agent: "", tools: "", requirements: "", roles: [], db_schema: "", context_attributes: null });
const blank = () => ({ view: "flow", step: "app", maxStep: 0, preset: null, mode: null, form: blankForm(), sid: null,
  session: null, reviewing: false, answers: {}, result: null, approved: null, tryForm: null, quickNote: false });

export const S = Object.assign(blank(), mem.get(KEY, {}) || {});

export function save() {
  mem.set(KEY, S);
}

export function reset() {
  Object.assign(S, blank());
  save();
}

export function newForm() {
  return blankForm();
}

export function reached(stepId) {
  return STEP_IDS.indexOf(stepId) <= S.maxStep;
}

/** Ό,τι εξαρτάται από τη συνεδρία (όχι η φόρμα) καθαρίζεται όταν η φόρμα αλλάζει ή ξεκινά νέα συνεδρία. */
export function dropSession() {
  Object.assign(S, { sid: null, session: null, reviewing: false, answers: {}, result: null, approved: null, tryForm: null, maxStep: 0 });
}
