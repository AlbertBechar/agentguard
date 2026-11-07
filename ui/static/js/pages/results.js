// pages/results.js -- (προσωρινό) η σελίδα αποτελεσμάτων φτιάχνεται στο Βήμα 6, όταν ζητηθεί.
import { api } from "../api.js";
import { el, errorBox, icon } from "../ui.js";

export async function renderResults(root) {
  const box = el("div", { class: "wrap section stack" }, el("h2", { text: "Αποτελέσματα" }));
  root.append(box);
  try {
    await api.results();
    box.append(el("p", { class: "muted", text: "Υπάρχουν αποτελέσματα, αλλά η σελίδα προβολής δεν έχει φτιαχτεί ακόμα." }));
  } catch (err) {
    box.append(errorBox(err, "Δεν υπάρχουν αποτελέσματα ακόμα"),
      el("p", { class: "muted" }, icon("info", { size: 18 }), " Κανένα νούμερο δεν εμφανίζεται εδώ αν δεν προέρχεται από πραγματική εκτέλεση."));
  }
}
