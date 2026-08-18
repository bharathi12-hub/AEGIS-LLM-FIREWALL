"""Timing side-channel defense (S9).

Block-vs-allow latency can leak which layer fired, letting an attacker tune an
evasion. AEGIS normalizes response timing to a floor plus small random jitter so
the observable latency does not reveal the internal decision path.
"""
from __future__ import annotations

import secrets
import time


def normalized_delay(elapsed_ms: float, floor_ms: int, jitter_ms: int) -> float:
    """Return the additional seconds to sleep so total >= floor + jitter."""
    target = floor_ms + (secrets.randbelow(jitter_ms + 1) if jitter_ms > 0 else 0)
    remaining_ms = target - elapsed_ms
    return max(0.0, remaining_ms) / 1000.0


async def apply_async(start_perf: float, floor_ms: int, jitter_ms: int) -> None:
    import asyncio
    elapsed_ms = (time.perf_counter() - start_perf) * 1000.0
    delay = normalized_delay(elapsed_ms, floor_ms, jitter_ms)
    if delay > 0:
        await asyncio.sleep(delay)


def apply_sync(start_perf: float, floor_ms: int, jitter_ms: int) -> None:
    elapsed_ms = (time.perf_counter() - start_perf) * 1000.0
    delay = normalized_delay(elapsed_ms, floor_ms, jitter_ms)
    if delay > 0:
        time.sleep(delay)
