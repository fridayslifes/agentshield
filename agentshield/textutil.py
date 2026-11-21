"""Small text helpers shared by the simulator, defenses and judge."""
from __future__ import annotations

import base64
import re

_LEET = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def leet_normalize(s: str) -> str:
    """Undo simple leetspeak (1->i, 3->e, ...)."""
    return s.translate(_LEET)


def decode_base64_chunks(text: str) -> list[str]:
    """Return the printable-text decodings of every base64-looking token in `text`."""
    out: list[str] = []
    for tok in _B64.findall(text):
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("utf-8")
        except Exception:
            continue
        if raw and sum(c.isprintable() for c in raw) / len(raw) > 0.95:
            out.append(raw)
    return out


def words(text: str) -> list[str]:
    return re.findall(r"\w+", text.lower())


def alnum(text: str) -> str:
    """Lowercase and keep only letters/digits (defeats spacing/punctuation tricks)."""
    return re.sub(r"[^a-z0-9]", "", text.lower())
