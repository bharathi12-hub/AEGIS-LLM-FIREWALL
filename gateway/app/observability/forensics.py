"""Forensic decision traces — reconstructing why a verdict happened.

WHY THIS EXISTS
---------------
The audit trail (:mod:`app.observability.audit`) answers "what did AEGIS
decide?" and proves the record was not altered afterwards. It deliberately does
not answer "why?", because keeping full reasoning on every record would store
attacker-controlled text at volume.

Incident response needs the "why", and it needs it in a specific shape:

    "At 14:02 a chunk from wiki://x was retrieved, it scored 0.82 on
     concealment + tool-directive, it was quarantined, the answer was still
     produced from the remaining two chunks, and no tool call followed."

That is a TIMELINE across layers and surfaces, and no single layer can produce
it. A trace is assembled during one request, then sealed: the volatile detail is
summarised, a digest is written into the hash-chained audit log, and the full
trace goes to the (retention-bounded) trace store.

PRIVACY / SAFETY
----------------
Traces hold attacker-controlled text, so:
  * every excerpt is passed through the same sanitizer the logs use and capped;
  * raw prompts are stored as digests, never verbatim, matching the existing
    audit behaviour;
  * the trace store is bounded and its records age out with the same retention
    job as audit records.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field

from app.observability import audit
from app.observability.logging import sanitize_for_render

# Bounded in-memory trace buffer. Durable stores can subscribe by wrapping
# ``seal`` — the audit digest is what makes a trace tamper-evident either way.
_MAX_TRACES = 500
_traces: dict[str, dict] = {}
_order: list[str] = []


@dataclass
class TraceEvent:
    """One step in the decision timeline."""

    t_ms: float
    layer: str
    action: str
    verdict: str = ""
    score: float = 0.0
    detail: dict = field(default_factory=dict)


@dataclass
class DecisionTrace:
    """Accumulates the full reasoning path for one request."""

    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    tenant_id: str = "default"
    session_id: str = ""
    started_at: float = field(default_factory=time.time)
    events: list[TraceEvent] = field(default_factory=list)
    normalized_prompt: str = ""
    decoded_payloads: list[str] = field(default_factory=list)
    triggered_rules: list[str] = field(default_factory=list)
    surfaces: dict = field(default_factory=dict)
    tool_requests: list[dict] = field(default_factory=list)
    policy_decisions: list[dict] = field(default_factory=list)
    model_response_digest: str = ""
    final_verdict: str = ""
    sealed: bool = False

    # -- recording ------------------------------------------------------
    def _elapsed_ms(self) -> float:
        return round((time.time() - self.started_at) * 1000, 3)

    def add(self, layer: str, action: str, *, verdict: str = "",
            score: float = 0.0, **detail) -> None:
        self.events.append(TraceEvent(
            t_ms=self._elapsed_ms(), layer=layer, action=action,
            verdict=verdict, score=round(float(score or 0.0), 4),
            detail={k: _safe(v) for k, v in detail.items()},
        ))

    def record_inspection(self, result) -> None:
        """Capture an ``InspectionResult`` from the prompt pipeline."""
        norm = getattr(result, "normalization", None)
        if norm is not None:
            self.normalized_prompt = sanitize_for_render(norm.sanitized, 2000)
            self.decoded_payloads = [sanitize_for_render(d, 400)
                                     for d in norm.decoded_views[:5]]
        decision = getattr(result, "decision", None)
        if decision is not None:
            self.triggered_rules.extend(
                sanitize_for_render(r, 160) for r in decision.reasons[:20])
            self.add("aggregator", "fuse", verdict=decision.verdict.value,
                     score=decision.score, contributions=decision.contributions,
                     tripwires=decision.tripwires, category=decision.category.value)
        for layer, ms in (getattr(result, "layer_ms", {}) or {}).items():
            self.add(layer, "timing", latency_ms=ms)

    def record_surface(self, result) -> None:
        """Capture any :class:`app.surfaces.base.SurfaceResult`."""
        name = getattr(result, "surface", "surface")
        payload = result.as_dict() if hasattr(result, "as_dict") else _safe(result)
        self.surfaces[name] = payload
        self.add(f"surface_{name}", "scan",
                 verdict=getattr(result, "verdict", "").value
                 if hasattr(getattr(result, "verdict", ""), "value") else "",
                 score=getattr(result, "risk", 0.0),
                 findings=len(getattr(result, "findings", []) or []),
                 enabled=getattr(result, "enabled", True))
        self.triggered_rules.extend(
            f"{name}:{f.kind}" for f in (getattr(result, "findings", []) or [])[:20])

    def record_tool(self, result) -> None:
        """Capture a tool-firewall decision (kept separate: it is the action edge)."""
        entry = result.as_dict() if hasattr(result, "as_dict") else _safe(result)
        self.tool_requests.append(entry)
        self.add("surface_tools", "tool-decision",
                 verdict=entry.get("verdict", ""), score=entry.get("risk", 0.0),
                 tool=entry.get("tool", ""),
                 execute_allowed=entry.get("execute_allowed", True))

    def record_policy(self, *, tenant_id: str, decision: str, **detail) -> None:
        self.policy_decisions.append(
            {"tenant_id": tenant_id, "decision": decision,
             **{k: _safe(v) for k, v in detail.items()}})
        self.add("policy", "evaluate", verdict=decision, **detail)

    def record_response(self, text: str, *, blocked: bool = False) -> None:
        self.model_response_digest = audit.payload_digest(text or "")
        self.add("upstream", "response", verdict="block" if blocked else "allow",
                 chars=len(text or ""))

    # -- sealing --------------------------------------------------------
    def summary(self) -> dict:
        return {
            "trace_id": self.trace_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "started_at": round(self.started_at, 3),
            "duration_ms": self._elapsed_ms(),
            "final_verdict": self.final_verdict,
            "layers": sorted({e.layer for e in self.events}),
            "surfaces": {k: v.get("verdict") for k, v in self.surfaces.items()},
            "triggered_rules": self.triggered_rules[:40],
            "tool_requests": len(self.tool_requests),
            "events": len(self.events),
        }

    def as_dict(self) -> dict:
        return {
            **self.summary(),
            "normalized_prompt": self.normalized_prompt,
            "decoded_payloads": self.decoded_payloads,
            "surface_detail": self.surfaces,
            "tool_detail": self.tool_requests,
            "policy_decisions": self.policy_decisions,
            "model_response_digest": self.model_response_digest,
            "timeline": [asdict(e) for e in self.events],
        }

    def seal(self, *, final_verdict: str = "", event: str = "trace") -> dict:
        """Freeze the trace, store it, and anchor a digest in the audit chain.

        The audit record holds only the SUMMARY. That keeps the tamper-evident
        chain small and free of attacker text while still binding the full trace
        to it: if the stored trace is later altered, its trace_id and verdict no
        longer match the sealed audit record.
        """
        if final_verdict:
            self.final_verdict = final_verdict
        self.sealed = True
        payload = self.as_dict()

        _traces[self.trace_id] = payload
        _order.append(self.trace_id)
        while len(_order) > _MAX_TRACES:
            _traces.pop(_order.pop(0), None)

        audit.record_event(
            tenant_id=self.tenant_id, event=event, layer="forensics",
            verdict=self.final_verdict or "unknown",
            reason=f"trace:{self.trace_id}",
            meta={"trace": self.summary()},
        )
        return payload


def _safe(value):
    """Recursively bound and sanitize values before they enter a trace."""
    if isinstance(value, str):
        return sanitize_for_render(value, 400)
    if isinstance(value, dict):
        return {str(k)[:80]: _safe(v) for k, v in list(value.items())[:40]}
    if isinstance(value, (list, tuple)):
        return [_safe(v) for v in list(value)[:40]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return sanitize_for_render(str(value), 200)


def new_trace(*, tenant_id: str = "default", session_id: str = "") -> DecisionTrace:
    return DecisionTrace(tenant_id=tenant_id, session_id=session_id)


def get_trace(trace_id: str) -> dict | None:
    return _traces.get(trace_id)


def list_traces(*, tenant_id: str = "", limit: int = 50) -> list[dict]:
    out = []
    for tid in reversed(_order):
        payload = _traces.get(tid)
        if not payload:
            continue
        if tenant_id and payload.get("tenant_id") != tenant_id:
            continue
        out.append({k: payload[k] for k in
                    ("trace_id", "tenant_id", "session_id", "started_at",
                     "duration_ms", "final_verdict", "surfaces") if k in payload})
        if len(out) >= limit:
            break
    return out


def clear() -> None:
    """Test hook — drop all buffered traces."""
    _traces.clear()
    _order.clear()
