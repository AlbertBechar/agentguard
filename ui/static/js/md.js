// md.js -- μικρός μετατροπέας markdown -> DOM για το review_md του Copilot.
// ΑΣΦΑΛΕΙΑ: δεν παράγεται ποτέ HTML-κείμενο. Κάθε κομμάτι κειμένου μπαίνει ως text node, άρα «escape πρώτα» ισχύει εξ ορισμού:
// ό,τι μοιάζει με <tag> εμφανίζεται ως απλό κείμενο και δεν γίνεται ποτέ στοιχείο. Οι περιγραφές εργαλείων είναι μη έμπιστο κείμενο.
import { codeBlock, el } from "./ui.js";

const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(__[^_\n]+__)|(\*[^*\s][^*\n]*\*)|((?<![\w])_[^_\s][^_\n]*_(?![\w]))/g;

export function inline(text) {
  const out = [];
  let last = 0;
  for (const m of String(text).matchAll(INLINE)) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const t = m[0];
    if (t.startsWith("`")) out.push(el("code", { text: t.slice(1, -1) }));
    else if (t.startsWith("**") || t.startsWith("__")) out.push(el("strong", { text: t.slice(2, -2) }));
    else out.push(el("em", { text: t.slice(1, -1) }));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

const cells = (line) => line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
const isRule = (line) => /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/.test(line);
const isSpecial = (line) => /^(#{1,3}\s|```|\s*[-*]\s+|\s*\d+\.\s+|\|)/.test(line);

export function mdToDom(md) {
  const root = el("div", { class: "md" });
  const lines = String(md).replace(/\r\n?/g, "\n").split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i += 1; continue; }
    if (/^```/.test(line)) {
      const lang = line.replace(/^```/, "").trim();
      const body = [];
      i += 1;
      while (i < lines.length && !/^```/.test(lines[i])) body.push(lines[i++]);
      i += 1;
      root.append(codeBlock(body.join("\n"), { title: lang, copy: false }));
      continue;
    }
    const h = /^(#{1,3})\s+(.*)$/.exec(line);
    if (h) { root.append(el(`h${h[1].length + 2}`, null, inline(h[2]))); i += 1; continue; }
    if (line.trim().startsWith("|") && i + 1 < lines.length && isRule(lines[i + 1])) {
      const head = cells(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) rows.push(cells(lines[i++]));
      root.append(el("div", { class: "table-wrap" }, el("table", null,
        el("thead", null, el("tr", null, head.map((c) => el("th", null, inline(c))))),
        el("tbody", null, rows.map((r) => el("tr", null, r.map((c) => el("td", null, inline(c)))))))));
      continue;
    }
    const ul = /^\s*[-*]\s+(.*)$/.exec(line);
    const ol = /^\s*\d+\.\s+(.*)$/.exec(line);
    if (ul || ol) {
      const items = [];
      const rx = ul ? /^\s*[-*]\s+(.*)$/ : /^\s*\d+\.\s+(.*)$/;
      while (i < lines.length && rx.test(lines[i])) items.push(rx.exec(lines[i++])[1]);
      root.append(el(ul ? "ul" : "ol", null, items.map((t) => el("li", null, inline(t)))));
      continue;
    }
    const para = [];
    while (i < lines.length && lines[i].trim() && (!isSpecial(lines[i]) || para.length === 0)) para.push(lines[i++].trim());
    root.append(el("p", null, inline(para.join(" "))));
  }
  return root;
}
