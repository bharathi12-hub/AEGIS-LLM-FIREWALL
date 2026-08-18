"""Signature layer (4.2).

Fast, high-precision regex matching. Its role is unchanged from v1, but the
rules now run on *normalized* text plus decoded views (from Normalization v2),
so evasion via encoding / homoglyph / zero-width injection no longer defeats it.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache

from app.util_yaml import load_yaml

_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "rules", "signatures.yaml",
)


@dataclass
class CompiledRule:
    id: str
    category: str
    severity: float
    description: str
    patterns: list[re.Pattern]


@dataclass
class SignatureMatch:
    rule_id: str
    category: str
    severity: float
    matched: str  # the substring that matched (untrusted — escape when rendered)


@dataclass
class SignatureResult:
    matches: list[SignatureMatch] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Highest-severity match dominates; multiple matches nudge it up."""
        if not self.matches:
            return 0.0
        top = max(m.severity for m in self.matches)
        bonus = min(0.1, 0.03 * (len(self.matches) - 1))
        return min(1.0, top + bonus)

    @property
    def categories(self) -> list[str]:
        seen: list[str] = []
        for m in self.matches:
            if m.category not in seen:
                seen.append(m.category)
        return seen


@lru_cache(maxsize=1)
def _load_rules(path: str = _RULES_PATH) -> list[CompiledRule]:
    doc = load_yaml(path) or {}
    compiled: list[CompiledRule] = []
    for rule in doc.get("rules", []):
        patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in rule.get("patterns", [])
        ]
        compiled.append(CompiledRule(
            id=rule["id"],
            category=rule.get("category", "LLM01:PromptInjection"),
            severity=float(rule.get("severity", 0.5)),
            description=rule.get("description", ""),
            patterns=patterns,
        ))
    return compiled


def scan(text: str) -> SignatureResult:
    """Scan already-normalized text (typically ``NormalizationResult.scan_text``)."""
    result = SignatureResult()
    for rule in _load_rules():
        for pat in rule.patterns:
            m = pat.search(text)
            if m:
                result.matches.append(SignatureMatch(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    matched=m.group(0)[:120],
                ))
                break  # one match per rule is enough
    return result
