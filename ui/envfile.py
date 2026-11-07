"""
ui/envfile.py -- μικρός φορτωτής του .env της ρίζας του repo (μόνο standard library).

Κανόνες (εγκρίθηκε ρητά ως εξαίρεση του Κανόνα 6 για το AI_STUDIO_API_KEY):
* διαβάζεται ΜΟΝΟ το <ρίζα repo>/.env (η διαδρομή δεν δίνεται από τον χρήστη του UI)·
* φορτώνονται ΜΟΝΟ τα ονόματα της λευκής λίστας ALLOWED (όχι ό,τι άλλο τυχόν υπάρχει στο αρχείο)·
* μια μεταβλητή που υπάρχει ήδη στο περιβάλλον ΔΕΝ αλλάζει ποτέ·
* δεν τυπώνει, δεν καταγράφει και δεν επιστρέφει ποτέ τιμές -- μόνο τα ΟΝΟΜΑΤΑ που φορτώθηκαν·
* ποτέ exception: αν το αρχείο λείπει ή δεν διαβάζεται, απλώς δεν φορτώνεται τίποτα.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATH = ROOT / ".env"
ALLOWED = ("AI_STUDIO_API_KEY", "COPILOT_MODEL", "GEMINI_MODEL")


def _parse_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[len("export "):].lstrip()
    name, sep, value = line.partition("=")
    if not sep:
        return None
    name, value = name.strip(), value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    elif " #" in value:                      # σχόλιο στο τέλος μιας τιμής χωρίς εισαγωγικά
        value = value.split(" #", 1)[0].rstrip()
    return name, value


def load_env(path=None, environ=None) -> list[str]:
    """Επιστρέφει τη λίστα με τα ΟΝΟΜΑΤΑ που φορτώθηκαν (ποτέ τιμές). Η `path` υπάρχει μόνο για τα τεστ."""
    target = Path(path) if path is not None else DEFAULT_PATH
    env = os.environ if environ is None else environ
    try:
        text = target.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return []
    loaded: list[str] = []
    for raw in text.splitlines():
        parsed = _parse_line(raw)
        if not parsed:
            continue
        name, value = parsed
        if name in ALLOWED and value and not env.get(name):
            env[name] = value
            loaded.append(name)
    return loaded
