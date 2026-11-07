// studio/approve.js -- (προσωρινό) υλοποιείται σε επόμενο βήμα.
import { el } from "../ui.js";

export async function renderApprove(host) {
  host.replaceChildren(el("div", { class: "card" }, el("p", { class: "muted", text: "Έγκριση: έρχεται στο επόμενο βήμα." })));
}
