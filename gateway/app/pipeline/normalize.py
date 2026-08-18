"""Robust Normalization v2 (closes G2 / neutralizes T2).

Character-injection evades almost every production guardrail: emoji/tag-char
smuggling, bidirectional override text, homoglyphs, and zero-width characters
achieve up to ~100% evasion against 6 production systems (Hackett et al. 2025).
AEGIS neutralizes these *before any classifier sees the text*.

Design contract (R9 / S2 — inspection/forward parity):
    ``sanitized`` is the single canonical text that every downstream layer
    inspects AND that is forwarded upstream. There is no parser differential:
    what we scanned is what we send.

``decoded_views`` are *auxiliary* strings recovered from multi-pass decoding
(base64/hex/rot13/url/leetspeak). They are used only as extra detection signal;
they are never forwarded. This is what lets a base64-wrapped injection be caught
without changing the bytes the upstream model receives.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Invisible / control character classes (the primary smuggling channels)
# ---------------------------------------------------------------------------

# Zero-width and BOM.
_ZERO_WIDTH = {
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "⁠",  # WORD JOINER
    "﻿",  # ZERO WIDTH NO-BREAK SPACE / BOM
}

# Bidirectional formatting / override controls (the bidi evasion channel).
_BIDI_CONTROLS = {
    "‪", "‫", "‬", "‭", "‮",  # LRE RLE PDF LRO RLO
    "⁦", "⁧", "⁨", "⁩",            # LRI RLI FSI PDI
    "‎", "‏",                                # LRM RLM
    "؜",                                          # ARABIC LETTER MARK
}


def _is_tag_char(ch: str) -> bool:
    """Unicode Tag block U+E0000..U+E007F — the 'emoji smuggling' channel."""
    return 0xE0000 <= ord(ch) <= 0xE007F


def _is_variation_selector(ch: str) -> bool:
    o = ord(ch)
    return 0xFE00 <= o <= 0xFE0F or 0xE0100 <= o <= 0xE01EF


# ---------------------------------------------------------------------------
# Homoglyph / confusables folding to canonical ASCII
# ---------------------------------------------------------------------------
# NFKC already folds fullwidth forms and most mathematical alphanumerics.
# What it does NOT fold are cross-script look-alikes (Cyrillic/Greek → Latin),
# which are the workhorse of homoglyph attacks. This explicit map covers the
# high-value confusables an attacker uses to spell "ignore instructions" etc.
_CONFUSABLES = {
    # Cyrillic → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "А": "A", "В": "B",
    "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ѕ": "S",
    "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q",
    "в": "B", "г": "r",
    # Greek → Latin
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ο": "o",
    "α": "a", "ι": "i", "ν": "v", "ρ": "p", "τ": "t",
    # Misc look-alikes
    "ı": "i",  # dotless i
    "⁄": "/",  # fraction slash
    "∕": "/",  # division slash
    "／": "/",  # fullwidth solidus (NFKC usually handles, belt-and-braces)
}

# Leetspeak folding used only to build an auxiliary decoded view (never the
# forwarded text) so signatures can match "1gn0r3" -> "ignore".
_LEET = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a",
    "$": "s", "!": "i", "|": "l",
})


@dataclass
class NormalizationResult:
    raw: str
    sanitized: str                       # inspected == forwarded (R9)
    decoded_views: list[str] = field(default_factory=list)  # auxiliary signal
    risk: float = 0.0                    # 0..1 obfuscation-risk score
    reasons: list[str] = field(default_factory=list)
    stripped_counts: dict[str, int] = field(default_factory=dict)

    @property
    def scan_text(self) -> str:
        """Everything a detector should read: sanitized + decoded views."""
        parts = [self.sanitized, *self.decoded_views]
        return "\n".join(p for p in parts if p)

    def diff(self) -> dict[str, str]:
        """Raw-vs-sanitized diff, stored in audit (4.1)."""
        return {"raw": self.raw, "sanitized": self.sanitized}


# ---------------------------------------------------------------------------
# Multi-pass decoding (base64 / hex / rot13 / url) — recover hidden payloads
# ---------------------------------------------------------------------------

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){8,}")


_COMMON_WORDS = {
    "the", "and", "you", "your", "ignore", "system", "prompt", "instruction",
    "instructions", "reveal", "previous", "all", "rules", "now", "act", "pretend",
    "developer", "mode", "password", "secret", "token", "disregard", "above",
}


def _printable_ratio(s: str) -> float:
    """Fraction of characters that are plain ASCII text (rejects binary junk)."""
    if not s:
        return 0.0
    ok = sum(1 for c in s if 32 <= ord(c) <= 126 or c in "\n\t")
    return ok / len(s)


def _word_hits(s: str) -> int:
    toks = re.findall(r"[a-z]+", s.lower())
    return sum(1 for t in toks if t in _COMMON_WORDS)


def _try_base64(text: str) -> list[str]:
    out = []
    for m in _B64_RE.findall(text):
        token = m
        pad = (-len(token)) % 4
        try:
            decoded = base64.b64decode(token + "=" * pad, validate=False)
            s = decoded.decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
        if len(s) >= 4 and _printable_ratio(s) > 0.9:
            out.append(s)
    return out


def _try_hex(text: str) -> list[str]:
    out = []
    for m in _HEX_RE.findall(text):
        cleaned = re.sub(r"[\s:]", "", m)
        if len(cleaned) % 2:
            cleaned = cleaned[:-1]
        try:
            s = bytes.fromhex(cleaned).decode("utf-8", "replace")
        except ValueError:
            continue
        if len(s) >= 4 and _printable_ratio(s) > 0.9:
            out.append(s)
    return out


def _try_url(text: str) -> list[str]:
    if "%" not in text:
        return []
    dec = urllib.parse.unquote(text)
    return [dec] if dec != text and _printable_ratio(dec) > 0.9 else []


def _decode_layers(text: str, max_depth: int = 3) -> list[str]:
    """Iteratively decode nested encodings; return distinct decoded views.

    Only *structural* encodings (base64/hex/url) recurse — feeding rot13 back in
    would cascade into binary junk, so rot13 is handled once at the top level.
    """
    seen: set[str] = {text}
    frontier = [text]
    views: list[str] = []
    for _ in range(max_depth):
        nxt: list[str] = []
        for chunk in frontier:
            for decoder in (_try_base64, _try_hex, _try_url):
                for dec in decoder(chunk):
                    if dec not in seen:
                        seen.add(dec)
                        views.append(dec)
                        nxt.append(dec)
        if not nxt:
            break
        frontier = nxt

    # rot13: a single top-level pass, kept only if it reveals more real words.
    rot = codecs.encode(text, "rot_13")
    if rot != text and _word_hits(rot) > _word_hits(text):
        views.append(rot)
    return views


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def normalize(text: str, *, max_chars: int = 32_000) -> NormalizationResult:
    """Neutralize obfuscation and produce the canonical inspected/forwarded text."""
    raw = text or ""
    # S14: cap oversized inputs safely BEFORE any heavy work.
    truncated = False
    if len(raw) > max_chars:
        raw = raw[:max_chars]
        truncated = True

    reasons: list[str] = []
    counts: dict[str, int] = {
        "zero_width": 0, "bidi": 0, "tag_chars": 0,
        "variation_selectors": 0, "homoglyphs": 0,
    }

    # Pass 1: character-level strip / fold, tracking what we removed.
    out_chars: list[str] = []
    for ch in raw:
        if ch in _ZERO_WIDTH:
            counts["zero_width"] += 1
            continue
        if ch in _BIDI_CONTROLS:
            counts["bidi"] += 1
            continue
        if _is_tag_char(ch):
            counts["tag_chars"] += 1
            continue
        if _is_variation_selector(ch):
            counts["variation_selectors"] += 1
            continue
        folded = _CONFUSABLES.get(ch)
        if folded is not None:
            counts["homoglyphs"] += 1
            out_chars.append(folded)
            continue
        # Drop remaining Unicode "Cf" (format) and "Co" (private use) controls.
        cat = unicodedata.category(ch)
        if cat in {"Cf", "Co"}:
            counts["zero_width"] += 1
            continue
        out_chars.append(ch)

    stripped = "".join(out_chars)

    # Pass 2: canonical Unicode normalization (folds fullwidth, math alnum, …).
    sanitized = unicodedata.normalize("NFKC", stripped)
    # Collapse runs of whitespace introduced by stripping, but preserve newlines.
    sanitized = re.sub(r"[ \t]{2,}", " ", sanitized)

    # Auxiliary decoded views (never forwarded — signal only).
    decoded_views = _decode_layers(sanitized)
    # A leetspeak-folded view helps signatures catch "1gn0r3 4ll rul3s".
    leet_view = sanitized.translate(_LEET)
    if leet_view != sanitized:
        decoded_views.append(leet_view)

    # ---- Normalization RISK score (heavy obfuscation is itself a signal) ----
    risk = 0.0
    if counts["tag_chars"]:
        risk += 0.6
        reasons.append(f"unicode-tag-smuggling:{counts['tag_chars']}")
    if counts["bidi"]:
        risk += 0.5
        reasons.append(f"bidi-override:{counts['bidi']}")
    if counts["zero_width"]:
        risk += min(0.4, 0.08 * counts["zero_width"])
        reasons.append(f"zero-width:{counts['zero_width']}")
    if counts["homoglyphs"]:
        risk += min(0.5, 0.05 * counts["homoglyphs"])
        reasons.append(f"homoglyph:{counts['homoglyphs']}")
    if counts["variation_selectors"]:
        risk += min(0.2, 0.05 * counts["variation_selectors"])
        reasons.append(f"variation-selector:{counts['variation_selectors']}")
    if decoded_views:
        # Something was hidden inside an encoding.
        risk += min(0.4, 0.15 * len(decoded_views))
        reasons.append(f"encoded-payload:{len(decoded_views)}")
    if truncated:
        reasons.append("input-truncated")

    # Non-ASCII density (excluding normal spaces) as a mild signal.
    if sanitized:
        non_ascii = sum(1 for c in sanitized if ord(c) > 0x7F)
        density = non_ascii / len(sanitized)
        if density > 0.30:
            risk += 0.15
            reasons.append(f"high-non-ascii:{density:.2f}")

    risk = min(1.0, risk)

    return NormalizationResult(
        raw=text or "",
        sanitized=sanitized,
        decoded_views=decoded_views,
        risk=round(risk, 4),
        reasons=reasons,
        stripped_counts=counts,
    )
