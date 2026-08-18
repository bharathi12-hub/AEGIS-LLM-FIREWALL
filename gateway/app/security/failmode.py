"""Fail-mode policy (S4) — fail-closed vs fail-open, never silently.

High-security tenants BLOCK when a detection layer errors or times out
(fail-closed, the default). Others may fail open, but ALWAYS with a logged alarm.
The orchestrator implements the per-layer fallback; this module centralizes the
decision and the graceful-degradation ladder (Section 6).
"""
from __future__ import annotations

from dataclasses import dataclass

FAIL_CLOSED = "closed"
FAIL_OPEN = "open"


@dataclass
class FailDecision:
    verdict_block: bool
    alarm: str


def on_layer_failure(layer: str, fail_mode: str) -> FailDecision:
    if fail_mode == FAIL_OPEN:
        return FailDecision(verdict_block=False,
                            alarm=f"fail-open:{layer}:degraded-with-alarm")
    return FailDecision(verdict_block=True,
                        alarm=f"fail-closed:{layer}:blocked")


# Graceful-degradation ladder: if a heavy model layer is unavailable, degrade to
# lighter layers rather than silently disabling protection.
DEGRADATION_LADDER = [
    "judge",        # drop first (most expensive)
    "embeddings",
    "classifier",   # heavy models; heuristic fallback still runs beneath
]


def degrade(available_layers: set[str], unhealthy: set[str]) -> set[str]:
    """Return the set of layers to run, dropping unhealthy heavy layers in order."""
    active = set(available_layers)
    for layer in DEGRADATION_LADDER:
        if layer in unhealthy:
            active.discard(layer)
    return active
