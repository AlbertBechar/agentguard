// studio/embed.js -- (προσωρινό) υλοποιείται σε επόμενο βήμα.
import { el } from "../ui.js";

export async function renderEmbed(host) {
  host.replaceChildren(el("div", { class: "card" }, el("p", { class: "muted", text: "Ενσωμάτωση: έρχεται στο επόμενο βήμα." })));
}
