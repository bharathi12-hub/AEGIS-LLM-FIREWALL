"""Policy schema + validation (S13).

Policy changes are validated against this schema before they are accepted and
written to the append-only audit trail. Invalid policies are rejected — an
attacker who reaches the policy endpoint cannot weaken protection with a
malformed document.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class PolicyValidationError(ValueError):
    pass


@dataclass
class EffectivePolicy:
    tenant_id: str
    fail_mode: str = "closed"
    block_threshold: float = 0.75
    review_threshold: float = 0.45
    judge_enabled: bool = True
    judge_budget_per_min: int = 30
    rate_limit_per_min: int = 120
    retention_days: int = 30
    allow_list: list[str] = field(default_factory=list)   # substrings never blocked
    deny_list: list[str] = field(default_factory=list)    # substrings always blocked
    languages: list[str] = field(default_factory=lambda: ["auto"])
    version: int = 1


_ALLOWED_FAIL_MODES = {"closed", "open"}


def validate(doc: dict) -> list[str]:
    """Return a list of error strings (empty == valid)."""
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["policy must be a mapping"]

    fm = doc.get("fail_mode", "closed")
    if fm not in _ALLOWED_FAIL_MODES:
        errors.append(f"fail_mode must be one of {_ALLOWED_FAIL_MODES}, got {fm!r}")

    for key, lo, hi in (("block_threshold", 0.0, 1.0), ("review_threshold", 0.0, 1.0)):
        if key in doc:
            v = doc[key]
            if not isinstance(v, (int, float)) or not lo <= v <= hi:
                errors.append(f"{key} must be a number in [{lo},{hi}], got {v!r}")

    if ("block_threshold" in doc and "review_threshold" in doc
            and isinstance(doc.get("block_threshold"), (int, float))
            and isinstance(doc.get("review_threshold"), (int, float))
            and doc["review_threshold"] > doc["block_threshold"]):
        errors.append("review_threshold must be <= block_threshold")

    for key in ("judge_budget_per_min", "rate_limit_per_min", "retention_days"):
        if key in doc:
            v = doc[key]
            if not isinstance(v, int) or v < 0:
                errors.append(f"{key} must be a non-negative integer, got {v!r}")

    for key in ("allow_list", "deny_list", "languages"):
        if key in doc and not isinstance(doc[key], list):
            errors.append(f"{key} must be a list")

    if "judge_enabled" in doc and not isinstance(doc["judge_enabled"], bool):
        errors.append("judge_enabled must be a boolean")

    return errors


def to_effective(tenant_id: str, doc: dict, version: int) -> EffectivePolicy:
    errs = validate(doc)
    if errs:
        raise PolicyValidationError("; ".join(errs))
    return EffectivePolicy(
        tenant_id=tenant_id,
        fail_mode=doc.get("fail_mode", "closed"),
        block_threshold=float(doc.get("block_threshold", 0.75)),
        review_threshold=float(doc.get("review_threshold", 0.45)),
        judge_enabled=bool(doc.get("judge_enabled", True)),
        judge_budget_per_min=int(doc.get("judge_budget_per_min", 30)),
        rate_limit_per_min=int(doc.get("rate_limit_per_min", 120)),
        retention_days=int(doc.get("retention_days", 30)),
        allow_list=list(doc.get("allow_list", [])),
        deny_list=list(doc.get("deny_list", [])),
        languages=list(doc.get("languages", ["auto"])),
        version=version,
    )
