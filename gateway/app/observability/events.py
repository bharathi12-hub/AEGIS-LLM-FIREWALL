"""Live inspection-event bus for real-time monitoring (deliverable 4).

The problem statement asks to "monitor AI interactions in real time" and
"provide security analytics dashboards". The audit log already records every
decision durably; this is its live counterpart — a bounded, in-process ring
buffer plus a publish/subscribe fan-out, so a dashboard can stream verdicts as
they happen instead of polling.

Deliberately in-memory and best-effort:
  * it is telemetry, not the system of record (that is the hash-chained audit
    log), so losing an event on restart is acceptable;
  * it must never slow down or fail an inspection — publish is non-blocking and
    swallows subscriber errors;
  * it is bounded, so a burst of traffic or a stalled subscriber cannot grow
    memory without limit.

Events are already redacted at the source: they carry the same non-sensitive
fields the audit meta does (verdict, category, score, latency, the ATLAS
technique, truncated reasons), never the raw prompt.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field

# Ring-buffer depth for the "recent events" REST endpoint, and per-subscriber
# queue depth for the live stream. Both bounded (S14 posture).
_RING_SIZE = 500
_SUBSCRIBER_QUEUE = 200


@dataclass
class InspectionEvent:
    ts: float
    tenant_id: str
    verdict: str
    category: str
    atlas: str
    score: float
    latency_ms: float
    layer: str = "input"
    surface: str = ""
    reasons: list = field(default_factory=list)
    request_id: str = ""
    seq: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ring: deque[InspectionEvent] = deque(maxlen=_RING_SIZE)
        self._subscribers: list[deque[InspectionEvent]] = []
        self._seq = 0

    def publish(self, event: InspectionEvent) -> None:
        """Record an event and fan it out. Never raises to the caller."""
        try:
            with self._lock:
                self._seq += 1
                event.seq = self._seq
                self._ring.append(event)
                for q in self._subscribers:
                    if len(q) >= _SUBSCRIBER_QUEUE:
                        # A subscriber that cannot keep up drops the OLDEST event
                        # rather than blocking the publisher — liveness over
                        # completeness for a telemetry stream.
                        try:
                            q.popleft()
                        except IndexError:
                            pass
                    q.append(event)
        except Exception:  # noqa: BLE001 — telemetry must never break inspection
            pass

    def recent(self, *, tenant_id: str = "", limit: int = 100) -> list[dict]:
        with self._lock:
            events = list(self._ring)
        if tenant_id:
            events = [e for e in events if e.tenant_id == tenant_id]
        return [e.as_dict() for e in events[-limit:]]

    def subscribe(self) -> deque[InspectionEvent]:
        q: deque[InspectionEvent] = deque(maxlen=_SUBSCRIBER_QUEUE)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: deque[InspectionEvent]) -> None:
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def stats(self) -> dict:
        with self._lock:
            return {"buffered": len(self._ring), "subscribers": len(self._subscribers),
                    "total_published": self._seq}


_bus: EventBus | None = None


def get_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def publish_inspection(*, tenant_id: str, verdict: str, category: str,
                       score: float, latency_ms: float, reasons: list,
                       layer: str = "input", surface: str = "",
                       request_id: str = "") -> None:
    """Convenience publisher used by the proxy; maps a decision to an event.

    Guarded as thoroughly as ``EventBus.publish``: it runs on the request hot
    path, so a malformed value must degrade the event, never raise into the
    caller and fail the inspection it is only reporting on.
    """
    try:
        from app.observability.logging import sanitize_for_render
        from app.taxonomy import atlas_for

        reasons = reasons or []
        atlas_id, _ = atlas_for(category or (reasons[0] if reasons else ""))
        get_bus().publish(InspectionEvent(
            ts=time.time(), tenant_id=str(tenant_id or "unknown"),
            verdict=str(verdict or "unknown"), category=str(category or "none"),
            atlas=atlas_id, score=round(_safe_float(score), 4),
            latency_ms=round(_safe_float(latency_ms), 3), layer=layer,
            surface=surface,
            reasons=[sanitize_for_render(str(r), 80) for r in reasons[:6]],
            request_id=request_id,
        ))
    except Exception:  # noqa: BLE001 — telemetry must never break inspection
        pass
