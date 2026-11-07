// studio/dryrun.js -- το πλαίσιο «Τι θα σταλεί στο AI»: ΑΚΡΙΒΩΣ τα prompts που θα φύγουν προς το LLM.
import { codeBlock, el, expander, icon } from "../ui.js";

const LABEL = { questions: "1. Ερωτήσεις διευκρίνισης", policy: "2. Πρόχειρο αρχείο κανόνων", scenarios: "3. Σενάρια ελέγχου" };
const NOTE = {
  policy: "Πρώτη προσπάθεια. Αν το πρόχειρο έχει λάθη, μια δεύτερη κλήση στέλνει επιπλέον το πρόχειρο και τα λάθη του.",
  scenarios: "Στέλνεται μόνο αν το πρόχειρο κανόνων είναι έγκυρο.",
};

export function dryRunView(stages, { open = false } = {}) {
  return el("div", { class: "stack-sm" },
    el("div", { class: "alert alert-ok" }, icon("lock", { size: 22 }),
      el("div", null, el("div", { class: "alert-title", text: "Δεν φεύγουν δεδομένα πελατών" }),
        el("p", { text: "Στέλνονται μόνο: η περιγραφή της εταιρίας και του βοηθού, οι ορισμοί των εργαλείων, οι απαιτήσεις σου, η δομή της βάσης (μόνο σχήμα, ποτέ δεδομένα) και οι απαντήσεις σου." }))),
    stages.map((st) => expander(LABEL[st.stage] || st.stage,
      el("div", { class: "stack-sm" },
        NOTE[st.stage] ? el("p", { class: "muted", text: NOTE[st.stage] }) : null,
        st.truncated ? el("p", { class: "muted", text: "(Το κείμενο εμφανίζεται κομμένο, αλλά στέλνεται ολόκληρο.)" }) : null,
        st.system ? codeBlock(st.system, { title: "Οδηγίες συστήματος (system)" }) : null,
        codeBlock(st.user, { title: "Δεδομένα που στέλνονται (user)" })), open)));
}
