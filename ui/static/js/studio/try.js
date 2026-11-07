// studio/try.js -- (προσωρινό) υλοποιείται σε επόμενο βήμα.
import { el } from "../ui.js";

export async function renderTry(host) {
  host.replaceChildren(el("div", { class: "card" }, el("p", { class: "muted", text: "Δοκίμασε: έρχεται στο επόμενο βήμα." })));
}
