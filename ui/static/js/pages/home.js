// pages/home.js -- αρχική (#/): hero, φράση-κλειδί, «Πώς δουλεύει», λωρίδα DemoBank, footer.
import { el, icon } from "../ui.js";

function howCard(n, title, text, keyLine, delay) {
  return el("article", { class: "card how-card reveal", style: { "--d": delay } },
    el("span", { class: "num", "aria-hidden": "true", text: String(n) }),
    el("h3", { text: title }),
    el("p", { text }),
    keyLine);
}

// Απόσπασμα του πίνακα «εργαλείο × ρόλος» όπως βγήκε από πραγματική εκτέλεση replay στη DemoBank (δεν επινοείται τίποτα).
const EXCERPT = [
  ["get_account", ["cond", "allow", "allow"]],
  ["transfer_funds", ["cond", "deny", "cond"]],
  ["send_email", ["deny", "allow", "allow"]],
  ["run_sql", ["deny", "deny", "deny"]],
];
const EXCERPT_ROLES = ["customer", "teller", "admin"];
const CELL = { allow: ["cell-allow", "check", "επιτρέπεται"], deny: ["cell-deny", "x", "απαγορεύεται"], cond: ["cell-cond", "half", "υπό συνθήκη"] };

function excerptCard() {
  return el("aside", { class: "card excerpt reveal", style: { "--d": ".2s" }, "aria-label": "Παράδειγμα πίνακα κανόνων" },
    el("h3", { text: "Τι επιτρέπεται, ανά εργαλείο και ρόλο" }),
    EXCERPT.map(([tool, cells]) => el("div", { class: "excerpt-tool" },
      el("span", { class: "name", text: tool }),
      el("div", { class: "excerpt-chips" }, cells.map((c, i) => {
        const [cls, ic, label] = CELL[c];
        return el("div", { class: "col" }, el("span", { class: "who", text: EXCERPT_ROLES[i] }),
          el("span", { class: `cell ${cls}` }, icon(ic, { size: 16 }), label));
      })))),
    el("p", { class: "muted sec", text: "Απόσπασμα από πραγματική εκτέλεση (replay) στη δοκιμαστική DemoBank — όχι πραγματική εταιρία." }));
}

export async function renderHome(root, { navigate }) {
  const sep = () => el("span", { class: "sep", "aria-hidden": "true", text: "·" });

  const heroText = el("div", null,
      el("p", { class: "eyebrow reveal" }, icon("shield", { size: 18 }), "AI Security · Policy Copilot"),
      el("h1", { id: "hero-title", class: "hero-title reveal", style: { "--d": ".05s" } },
        "Ο AI βοηθός σου κάνει ενέργειες.", el("strong", { text: "Ποιος τον προστατεύει;" })),
      el("p", { class: "hero-sub reveal", style: { "--d": ".12s" },
        text: "Το Copilot προτείνει κανόνες ασφαλείας, εσύ τους εγκρίνεις και ένας απλός Guard τους επιβάλλει." }),
      el("div", { class: "hero-cta reveal", style: { "--d": ".2s" } },
        el("button", { type: "button", class: "btn btn-hot btn-lg", onclick: () => navigate("#/studio?quick=1") }, icon("play", { size: 20 }), "Γρήγορη επίδειξη"),
        el("button", { type: "button", class: "btn btn-ghost btn-lg", onclick: () => navigate("#/studio") }, "Άνοιξε το Studio", icon("arrow", { size: 20 }))),
      el("p", { class: "muted sec reveal", style: { "--d": ".28s", "margin-top": "1.1rem" },
        text: "Η γρήγορη επίδειξη τρέχει χωρίς δίκτυο, από καταγραφή πραγματικής εκτέλεσης στη δοκιμαστική εφαρμογή DemoBank." }));
  const hero = el("section", { class: "hero", "aria-labelledby": "hero-title" }, el("div", { class: "wrap hero-grid has-excerpt" }, heroText, excerptCard()));

  const phrase = el("section", { class: "phrase-band", "aria-label": "Η αρχή του προϊόντος" },
    el("div", { class: "wrap" },
      el("p", { class: "key-phrase" }, "AI γράφει πρόχειρο", sep(), "ο κώδικας επιβάλλει", sep(), "ο άνθρωπος ", el("span", { class: "hot", text: "υπογράφει" }))));

  const how = el("section", { class: "section", "aria-labelledby": "how-title" },
    el("div", { class: "wrap" },
      el("h2", { id: "how-title", class: "section-title", text: "Πώς δουλεύει" }),
      el("div", { class: "grid-3" },
        howCard(1, "Περιγράφεις τον βοηθό σου",
          "Εταιρία, τι κάνει ο βοηθός, τα εργαλεία του, οι απαιτήσεις σου και (προαιρετικά) η δομή της βάσης. Μόνο περιγραφές, ποτέ δεδομένα πελατών.",
          el("p", { class: "key-line muted", text: "Εσύ δίνεις το πλαίσιο." }), ".1s"),
        howCard(2, "Το AI γράφει πρόχειρους κανόνες, εσύ εγκρίνεις",
          "Το Copilot ρωτά λίγες ερωτήσεις, γράφει το αρχείο κανόνων και το ελέγχει με αυτόματους ελέγχους και σενάρια. Τίποτα δεν ισχύει χωρίς την υπογραφή σου.",
          el("p", { class: "key-line" }, "AI γράφει πρόχειρο · ο άνθρωπος ", el("span", { class: "hot", text: "υπογράφει" })), ".2s"),
        howCard(3, "Απλός κώδικας τους επιβάλλει",
          "Ο Guard είναι συνηθισμένος κώδικας, όχι AI: ελέγχει κάθε ενέργεια του βοηθού με τους εγκεκριμένους κανόνες. Σήμερα ενσωματώνεται με 3 γραμμές Python.",
          el("p", { class: "key-line" }, "Ο κώδικας επιβάλλει."), ".3s"))));

  const demo = el("section", { class: "section", style: { "padding-top": "0" } },
    el("div", { class: "wrap" },
      el("div", { class: "strip reveal", style: { "--d": ".1s" } }, icon("info", { size: 20 }),
        el("span", null, el("strong", { text: "Δοκιμαστική εφαρμογή DemoBank — όχι πραγματική εταιρία." }),
          " Οι επιθέσεις και τα δεδομένα της δοκιμής είναι δικά μας."))));

  const footer = el("footer", { class: "footer" },
    el("div", { class: "wrap row-between" },
      el("span", { text: "Πρωτότυπο διαγωνισμού· δεν είναι πιστοποιημένο προϊόν." }),
      el("span", { class: "sec" }, el("a", { href: "#/results", text: "Αποτελέσματα και όρια" }))));

  root.append(hero, phrase, how, demo, footer);
}
