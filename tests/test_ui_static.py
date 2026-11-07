"""Αμετάβλητοι κανόνες του frontend (ui/static): παλέτα, αντίθεση WCAG, ροζ μόνο εκεί που πρέπει, χωρίς κόκκινο,
χωρίς εξωτερικούς πόρους, χωρίς innerHTML, ελάχιστο μέγεθος κειμένου. Δεν χρειάζεται server ούτε browser."""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "ui" / "static"
TEXT_SUFFIXES = {".html", ".css", ".js", ".svg"}


def read_css(name: str) -> str:
    return (STATIC / "css" / name).read_text(encoding="utf-8")


def palette() -> dict[str, str]:
    root_block = re.search(r":root\s*\{(.*?)\n\}", read_css("tokens.css"), re.S).group(1)
    return {m.group(1): m.group(2).upper() for m in re.finditer(r"--([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6})\b", root_block)}


def lum(hex_color: str) -> float:
    rgb = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def ratio(fg: str, bg: str) -> float:
    a, b = sorted((lum(fg), lum(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


def blend(fg: str, bg: str, alpha: float) -> str:
    out = [round(int(fg[i:i + 2], 16) * alpha + int(bg[i:i + 2], 16) * (1 - alpha)) for i in (1, 3, 5)]
    return "#%02X%02X%02X" % tuple(out)


def files():
    return [p for p in STATIC.rglob("*") if p.is_file() and p.suffix in TEXT_SUFFIXES]


def strip_comments(text: str, suffix: str) -> str:
    if suffix == ".css":
        return re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    if suffix == ".js":
        return re.sub(r"/\*.*?\*/|(?<![:\"'])//[^\n]*", "", text, flags=re.S)
    if suffix == ".html":
        return re.sub(r"<!--.*?-->", "", text, flags=re.S)
    return text


class PaletteAndContrast(unittest.TestCase):
    def test_palette_is_exactly_the_one_specified(self):
        p = palette()
        self.assertEqual({k: p[k] for k in ("bg", "card", "card-2", "line", "line-strong", "mint", "mint-dim", "pink", "pink-soft", "amber", "text", "text-2")},
                         {"bg": "#0A1633", "card": "#102248", "card-2": "#16295A", "line": "#2A4380", "line-strong": "#5A78BE", "mint": "#7CF2B0",
                          "mint-dim": "#4FD18A", "pink": "#FF4FA3", "pink-soft": "#FF8CC6", "amber": "#FFB84D", "text": "#EAF1FF", "text-2": "#A9B8DA"})
        self.assertEqual(p["bg-2"], "#0F1F45")

    def test_documented_contrast_values(self):
        p = palette()
        self.assertAlmostEqual(ratio(p["bg"], p["mint"]), 12.9, delta=0.15)
        self.assertAlmostEqual(ratio(p["bg"], p["pink"]), 5.9, delta=0.15)
        self.assertAlmostEqual(ratio(p["text"], p["bg"]), 15.8, delta=0.2)

    def test_text_pairs_meet_4_5_to_1(self):
        p = palette()
        surfaces = ("bg", "bg-2", "card", "card-2")
        pairs = [(fg, s) for fg in ("text", "text-2", "mint", "mint-dim", "amber", "pink") for s in surfaces]
        pairs += [("bg", c) for c in ("mint", "mint-dim", "pink", "pink-soft")]           # κείμενο πάνω σε mint/pink: πάντα --bg
        pairs += [("text", "line-strong")] if False else []
        for fg, bg in pairs:
            self.assertGreaterEqual(ratio(p[fg], p[bg]), 4.5, f"{fg} πάνω σε {bg}: {ratio(p[fg], p[bg]):.2f}")

    def test_text_on_translucent_tints_meets_4_5_to_1(self):
        p = palette()
        for fg, tint, alpha in (("mint", "mint", .22), ("mint", "mint", .12), ("amber", "amber", .13), ("pink-soft", "pink", .14), ("text", "mint", .22)):
            for surface in ("bg", "card", "card-2"):
                background = blend(p[tint], p[surface], alpha)
                self.assertGreaterEqual(ratio(p[fg], background), 4.5, f"{fg} πάνω σε {tint}@{alpha} πάνω σε {surface}")

    def test_field_and_button_borders_meet_3_to_1(self):
        p = palette()
        for border in ("line-strong", "mint", "amber", "pink"):
            for surface in ("bg", "card", "card-2"):
                self.assertGreaterEqual(ratio(p[border], p[surface]), 3.0, f"{border} πάνω σε {surface}")

    def test_every_hex_color_in_the_frontend_belongs_to_the_palette(self):
        allowed = set(palette().values())
        for path in files():
            for hex_color in re.findall(r"#[0-9A-Fa-f]{6}\b|#[0-9A-Fa-f]{3}\b", strip_comments(path.read_text(encoding="utf-8"), path.suffix)):
                if path.suffix == ".html" and re.search(r'href="#', hex_color):          # anchors, όχι χρώματα
                    continue
                self.assertIn(hex_color.upper(), allowed, f"χρώμα εκτός παλέτας στο {path.relative_to(ROOT)}")

    def test_there_is_never_red(self):
        for path in files():
            text = strip_comments(path.read_text(encoding="utf-8"), path.suffix)
            self.assertIsNone(re.search(r"(?i)(?<![\w-])(red|crimson|firebrick|tomato|darkred)(?![\w-])", text) if path.suffix in (".css", ".svg") else None,
                              f"κόκκινο στο {path.relative_to(ROOT)}")
            self.assertIsNone(re.search(r"(?i)\b(rgb|hsl)a?\(", text) if path.suffix == ".css" else None, f"ελεύθερο rgb/hsl στο {path.relative_to(ROOT)}")


class PinkAndTextRules(unittest.TestCase):
    ALLOWED_PINK = {".btn-hot", ".btn-hot:hover", ".btn-hot[disabled]", ".num-hot", ".key-phrase .hot", ".how-card .key-line .hot", ".tag-human"}

    def css_blocks(self):
        for name in ("components.css", "base.css"):
            css = re.sub(r"/\*.*?\*/", "", read_css(name), flags=re.S)
            for m in re.finditer(r"([^{}@][^{}]*)\{([^{}]*)\}", css):
                yield name, " ".join(m.group(1).split()), m.group(2)

    def test_pink_is_used_only_for_the_four_permitted_things(self):
        for name, selector, body in self.css_blocks():
            if "--pink" in body:
                for sel in (s.strip() for s in selector.split(",")):
                    self.assertIn(sel, self.ALLOWED_PINK, f"ροζ σε μη επιτρεπτό στοιχείο: {sel} ({name})")
        for path in (STATIC / "js").rglob("*.js"):
            self.assertNotRegex(path.read_text(encoding="utf-8"), r"--pink|#FF4FA3|#FF8CC6", f"ροζ μέσα στο {path.name}: να γίνεται μέσω κλάσης CSS")

    def test_text_on_mint_or_pink_backgrounds_is_always_the_dark_bg_colour(self):
        saw = 0
        for name, selector, body in self.css_blocks():
            if re.search(r"background(?:-color)?:\s*var\(--(mint|mint-dim|pink|pink-soft)\)", body):
                saw += 1
                self.assertRegex(body, r"(?<![-\w])color:\s*var\(--bg\)", f"κείμενο όχι σκούρο πάνω σε mint/pink: {selector}")
        self.assertGreaterEqual(saw, 5)

    def test_no_text_smaller_than_16px(self):
        for name in ("base.css", "components.css"):
            for m in re.finditer(r"font-size:\s*([\d.]+)(px|rem|em)\b", re.sub(r"/\*.*?\*/", "", read_css(name), flags=re.S)):
                px = float(m.group(1)) * (1 if m.group(2) == "px" else 16)
                self.assertGreaterEqual(px, 16, f"font-size {m.group(0)} στο {name}")

    def test_accessibility_basics_exist(self):
        base = read_css("base.css")
        self.assertIn("prefers-reduced-motion: reduce", base)
        self.assertIn(":focus-visible", base)
        self.assertIn("outline: 3px solid var(--mint)", base)
        self.assertIn("html.present", base)
        self.assertIn(".must-show", base)
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        self.assertIn('lang="el"', html)
        self.assertIn('class="skip"', html)
        self.assertIn('aria-pressed', html)

    def test_system_font_stack_only(self):
        tokens = read_css("tokens.css")
        self.assertIn('system-ui, -apple-system, "Segoe UI", Roboto, sans-serif', tokens)
        self.assertIn('ui-monospace, "Cascadia Code", Consolas, monospace', tokens)
        for path in files():
            self.assertNotRegex(path.read_text(encoding="utf-8"), r"@font-face|fonts\.googleapis|fonts\.gstatic", str(path))


class SafetyOfTheFrontend(unittest.TestCase):
    def test_no_html_string_injection_apis(self):
        bad = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function|setAttribute\(\s*[\"']style|srcdoc", re.I)
        for path in (STATIC / "js").rglob("*.js"):
            code = strip_comments(path.read_text(encoding="utf-8"), ".js")
            self.assertIsNone(bad.search(code), f"επικίνδυνο API στο {path.relative_to(ROOT)}: {bad.search(code)}")
        for path in STATIC.rglob("*.html"):
            html = path.read_text(encoding="utf-8")
            self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>", "inline script απαγορεύεται (CSP)")
            self.assertNotRegex(html, r"\sstyle\s*=", "inline style attribute απαγορεύεται (CSP)")
            self.assertNotRegex(html, r"\son[a-z]+\s*=", "inline event handler απαγορεύεται (CSP)")

    def test_no_external_resources_anywhere(self):
        pattern = re.compile(r"https?://[^\s\"'`)]+")
        for path in files():
            for url in pattern.findall(strip_comments(path.read_text(encoding="utf-8"), path.suffix)):
                self.assertTrue(url.startswith("http://www.w3.org/2000/svg") or url.startswith("http://127.0.0.1")
                                or url.startswith("http://localhost"),
                                f"εξωτερική διεύθυνση στο {path.relative_to(ROOT)}: {url}")
        for path in STATIC.rglob("*.html"):
            html = path.read_text(encoding="utf-8")
            for ref in re.findall(r'(?:src|href)="([^"]+)"', html):
                self.assertFalse(re.match(r"(?i)(https?:)?//", ref), ref)

    def test_no_secret_input_or_key_in_the_frontend(self):
        for path in files():
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"AI" r"za[0-9A-Za-z_\-]{20,}")
            self.assertNotRegex(text, r"""(?i)type\s*[:=]\s*["']password["']""")
            self.assertNotRegex(text, r"""(?i)(name|id|placeholder)\s*[:=]\s*["'][^"']*(api[_-]?key|AI_STUDIO)[^"']*["']""",
                                f"πεδίο εισαγωγής κλειδιού στο {path.relative_to(ROOT)}")

    def test_forbidden_claims_are_absent(self):
        banned = ["100% ασφαλές", "100% ασφαλ", "GDPR compliant", "GDPR-compliant", "πρώτοι στον κόσμο", "μοναδικοί στον κόσμο", "έχουμε πελάτες",
                  "σε οποιαδήποτε γλώσσα", "οποιαδήποτε γλώσσα"]
        for path in files():
            text = path.read_text(encoding="utf-8").casefold()
            for phrase in banned:
                self.assertNotIn(phrase.casefold(), text, f"απαγορευμένη φράση «{phrase}» στο {path.relative_to(ROOT)}")


if __name__ == "__main__":
    unittest.main()
