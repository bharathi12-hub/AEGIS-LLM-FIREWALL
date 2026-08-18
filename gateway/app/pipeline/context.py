"""Multi-turn / conversation-context detection (4.6) — closes G5.

Single-turn guardrails miss crescendo attacks (gradual escalation) and
split-payload attacks (an injection cut across several innocuous-looking turns).
AEGIS maintains a per-session rolling window and, on each new turn, re-scans the
*concatenation* of the last N turns — not just the newest message — so a payload
that is benign in pieces is caught once assembled.

Session state lives in Redis in the gateway; here it is an in-process store so
the logic is testable offline. The store is injected, so the same code path runs
in both profiles.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from app.config import settings


@dataclass
class ContextResult:
    escalation: float          # 0..1 crescendo score across the window
    assembled_hit: bool        # a split payload became an attack once joined
    reasons: list[str] = field(default_factory=list)
    window_size: int = 0


class _InMemorySessionStore:
    """Fallback rolling-window store (deque per session, TTL-pruned)."""

    def __init__(self, ttl_seconds: int = 1800) -> None:
        self._data: dict[str, deque] = defaultdict(lambda: deque(maxlen=32))
        self._ttl = ttl_seconds

    def append(self, session_id: str, text: str) -> list[str]:
        now = time.time()
        dq = self._data[session_id]
        dq.append((now, text))
        # prune expired
        while dq and now - dq[0][0] > self._ttl:
            dq.popleft()
        return [t for _, t in dq]


# Escalation lexicon — softer than a block-worthy signature; the point is the
# *trend* over turns, not any single hit.
_ESCALATION_MARKERS = re.compile(
    r"\b(ignore|disregard|bypass|jailbreak|unfiltered|no restrictions|"
    r"system prompt|developer mode|pretend|act as|reveal|override|"
    r"forget|instead|actually|now )\b",
    re.I,
)


def _turn_intensity(text: str) -> int:
    return len(_ESCALATION_MARKERS.findall(text or ""))


def _looks_like_attack(text: str) -> bool:
    # Lightweight assembled-payload check, mirroring the strongest signatures.
    return bool(re.search(
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b"
        r"(previous|prior|above|instruction|instructions|rules|prompt)\b",
        text, re.I,
    ) or re.search(r"\b(reveal|print|repeat)\b.{0,20}\bsystem prompt\b", text, re.I))


class ContextTracker:
    def __init__(self, store=None) -> None:
        self._store = store or _InMemorySessionStore()

    def observe(self, session_id: str, new_turn: str) -> ContextResult:
        window = self._store.append(session_id, new_turn)
        n = settings.context_window_turns
        recent = window[-n:]
        reasons: list[str] = []

        # Crescendo: increasing intensity across turns.
        intensities = [_turn_intensity(t) for t in recent]
        escalation = 0.0
        if len(intensities) >= 2:
            cumulative = sum(intensities)
            trend = intensities[-1] - intensities[0]
            escalation = min(1.0, 0.12 * cumulative + 0.1 * max(0, trend))
            if trend > 0 and cumulative >= 3:
                reasons.append(f"crescendo:cumulative={cumulative},trend={trend}")

        # Split payload: no single recent turn is an attack, but the joined text is.
        joined = " ".join(recent)
        assembled = _looks_like_attack(joined) and not any(
            _looks_like_attack(t) for t in recent
        )
        if assembled:
            reasons.append("split-payload-assembled")

        return ContextResult(
            escalation=round(escalation, 4),
            assembled_hit=assembled,
            reasons=reasons,
            window_size=len(recent),
        )


_tracker: ContextTracker | None = None


def get_tracker() -> ContextTracker:
    global _tracker
    if _tracker is None:
        _tracker = ContextTracker()
    return _tracker
