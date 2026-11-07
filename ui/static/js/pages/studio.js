// pages/studio.js -- (προσωρινό στο Βήμα 2) το Studio υλοποιείται στα Βήματα 3-5.
import { el } from "../ui.js";

export async function renderStudio(root) {
  root.append(el("div", { class: "wrap section" },
    el("div", { class: "card" }, el("h2", { text: "Studio" }), el("p", { class: "muted", text: "Το Studio φτιάχνεται στο επόμενο βήμα." }))));
}
