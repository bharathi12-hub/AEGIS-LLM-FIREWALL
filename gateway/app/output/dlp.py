"""Output DLP (4.10 / S12) — decode-then-scan so encoded exfiltration is caught.

Attackers ask the model to base64/rot13/hex a secret to slip it past naive DLP.
AEGIS normalizes the OUTPUT with the same Normalization v2 pipeline as the input,
which recovers decoded views, and then runs PII + secret detection over BOTH the
visible text and the decoded views. So a base64-wrapped secret in the model's
answer is decoded first, then flagged.

Presidio is used for PII when available; otherwise a dependency-free regex +
entropy detector runs (offline profile).
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from app.pipeline.normalize import normalize

# --- PII / secret regexes (fallback detector) ---
_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_api_key": re.compile(r"\b(?:sk|pk|api|key|token)[-_][A-Za-z0-9]{16,}\b", re.I),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "bearer": re.compile(r"\bBearer\s+[A-Za-z0-9._-]{16,}\b"),
}


@dataclass
class DLPFinding:
    kind: str
    where: str          # "visible" or "decoded"
    sample: str         # redacted preview (untrusted — escape when rendered)


@dataclass
class DLPResult:
    findings: list[DLPFinding] = field(default_factory=list)
    leaked: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.leaked or bool(self.findings)


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in re.sub(r"\D", "", digits)]
    if not 13 <= len(nums) <= 19:
        return False
    checksum, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(s: str) -> str:
    if len(s) <= 6:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


def _scan_text(text: str, where: str) -> list[DLPFinding]:
    findings: list[DLPFinding] = []
    for kind, pat in _PATTERNS.items():
        for m in pat.findall(text):
            val = m if isinstance(m, str) else m[0]
            if kind == "credit_card" and not _luhn_ok(val):
                continue
            findings.append(DLPFinding(kind=kind, where=where, sample=_redact(val)))
    # High-entropy token detector (catches secrets not matching a known shape).
    for tok in re.findall(r"\b[A-Za-z0-9+/=_-]{24,}\b", text):
        if _shannon_entropy(tok) >= 4.0:
            findings.append(DLPFinding(kind="high_entropy_secret", where=where,
                                       sample=_redact(tok)))
            break
    return findings


def _presidio_scan(text: str, where: str) -> list[DLPFinding] | None:  # pragma: no cover
    try:
        from presidio_analyzer import AnalyzerEngine  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    analyzer = AnalyzerEngine()
    out = []
    for r in analyzer.analyze(text=text, language="en"):
        out.append(DLPFinding(kind=r.entity_type.lower(), where=where,
                              sample=_redact(text[r.start:r.end])))
    return out


def scan_output(text: str, canary_tokens: list[str] | None = None) -> DLPResult:
    """Normalize output, decode-then-scan visible + decoded views for PII/secrets."""
    norm = normalize(text or "")
    result = DLPResult()

    # Canary leak check happens against decoded content too.
    haystacks = [("visible", norm.sanitized)] + [
        ("decoded", v) for v in norm.decoded_views
    ]
    for token in canary_tokens or []:
        for where, hay in haystacks:
            if token and token in hay:
                result.leaked = True
                result.reasons.append(f"canary-leak:{where}")

    for where, hay in haystacks:
        found = _presidio_scan(hay, where)
        if found is None:
            found = _scan_text(hay, where)
        result.findings.extend(found)

    if norm.decoded_views and any(f.where == "decoded" for f in result.findings):
        result.reasons.append("encoded-exfiltration")
    return result
