// studio/attack.js -- (προσωρινό) υλοποιείται σε επόμενο βήμα.
import { el } from "../ui.js";

export async function renderAttack(host) {
  host.replaceChildren(el("div", { class: "card" }, el("p", { class: "muted", text: "Επίθεση: έρχεται στο επόμενο βήμα." })));
}
