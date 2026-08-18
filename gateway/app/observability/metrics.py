"""Prometheus metrics (Section 6) with a no-op fallback.

When ``prometheus_client`` is installed the real counters/histograms are used and
exposed at /metrics; otherwise a lightweight in-process counter keeps the code
paths identical and still powers the dashboard's summary numbers.
"""
from __future__ import annotations

import threading

try:  # pragma: no cover - real metrics only in Docker
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
    _PROM = True
except Exception:  # noqa: BLE001
    _PROM = False
    CONTENT_TYPE_LATEST = "text/plain"


class _Fallback:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counters: dict[str, float] = {}
        self.latencies: list[float] = []

    def inc(self, name: str, value: float = 1.0) -> None:
        with self._lock:
            self.counters[name] = self.counters.get(name, 0.0) + value

    def observe_latency(self, ms: float) -> None:
        with self._lock:
            self.latencies.append(ms)
            if len(self.latencies) > 5000:
                self.latencies = self.latencies[-5000:]

    def render(self) -> bytes:
        lines = [f"aegis_{k} {v}" for k, v in self.counters.items()]
        return ("\n".join(lines) + "\n").encode()


_fb = _Fallback()

if _PROM:
    _requests = Counter("aegis_requests_total", "Total inspected requests", ["verdict"])
    _blocks = Counter("aegis_blocks_total", "Blocks by category", ["category"])
    _judge = Counter("aegis_judge_calls_total", "Judge invocations")
    _latency = Histogram("aegis_latency_ms", "Inspection latency (ms)",
                         buckets=(0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500))


def record_request(verdict: str, category: str, judge_used: bool, latency_ms: float) -> None:
    if _PROM:
        _requests.labels(verdict=verdict).inc()
        if verdict == "block":
            _blocks.labels(category=category).inc()
        if judge_used:
            _judge.inc()
        _latency.observe(latency_ms)
    else:
        _fb.inc(f"requests_{verdict}")
        if verdict == "block":
            _fb.inc(f"blocks_{category.replace(':', '_')}")
        if judge_used:
            _fb.inc("judge_calls")
        _fb.observe_latency(latency_ms)


def render_latest() -> tuple[bytes, str]:
    if _PROM:
        return generate_latest(), CONTENT_TYPE_LATEST
    return _fb.render(), CONTENT_TYPE_LATEST


def summary() -> dict:
    """Lightweight snapshot for the dashboard (fallback profile)."""
    if _PROM:
        return {"backend": "prometheus"}
    lat = sorted(_fb.latencies)
    def pct(p):
        return round(lat[min(len(lat) - 1, int(p / 100 * (len(lat) - 1)))], 3) if lat else 0.0
    return {
        "backend": "in-process",
        "counters": dict(_fb.counters),
        "latency_ms": {"p50": pct(50), "p95": pct(95), "p99": pct(99)},
        "n": len(lat),
    }
