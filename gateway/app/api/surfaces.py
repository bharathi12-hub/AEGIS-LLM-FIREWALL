"""Surface inspection endpoints (additive — v2.0 routes are untouched).

Every route here is new. Nothing in ``/v1/chat/completions`` or ``/aegis/inspect``
changes behaviour, so an existing deployment upgrades with no client changes and
adopts these surfaces at whatever pace it wants.

All routes:
  * require the same bearer credential as the rest of the proxy;
  * apply the caller's tenant policy and rate limit;
  * emit an audit record and a sealed forensic trace;
  * return the surface's ``sanitized`` content, which is what the caller should
    forward to the model instead of the raw artifact.

Routes
------
    POST /aegis/surface/browser     scan fetched HTML
    POST /aegis/surface/document    scan an uploaded document (base64 or text)
    POST /aegis/surface/rag         scan a retrieval set, get filtered chunks
    POST /aegis/surface/memory      gate a memory write / recall set
    POST /aegis/surface/tool        gate a proposed tool call
    POST /aegis/surface/agent       gate an inter-agent message
    POST /aegis/surface/multimodal  scan an image/audio artifact
    GET  /aegis/surfaces            which surfaces are enabled
    GET  /aegis/forensics/{id}      a sealed decision trace
"""
from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Header, HTTPException

from app.api.schemas import (
    AgentMessageRequest,
    BrowserScanRequest,
    DocumentScanRequest,
    MemoryScanRequest,
    MultimodalScanRequest,
    RagScanRequest,
    ToolCallRequest,
)
from app.api.proxy import _principal
from app.observability import audit, events, forensics, metrics
from app.security.ratelimit import get_rate_limiter
from app.surfaces import agent as agent_surface
from app.surfaces import browser as browser_surface
from app.surfaces import documents as document_surface
from app.surfaces import memory as memory_surface
from app.surfaces import multimodal as multimodal_surface
from app.surfaces import rag as rag_surface
from app.surfaces import status as surface_status
from app.surfaces import toolchain
from app.surfaces import tools as tool_surface

router = APIRouter(prefix="/aegis/surface", tags=["surfaces"])
_rate_limiter = get_rate_limiter()


def _guard(authorization: str | None):
    """Shared auth + rate limit for every surface route."""
    principal = _principal(authorization)
    if not _rate_limiter.allow(principal.key_id):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    return principal


def _finish(principal, result, trace, *, surface: str) -> dict:
    """Audit + seal + shape the response identically across surfaces."""
    trace.record_surface(result)
    trace.seal(final_verdict=result.verdict.value, event=f"surface_{surface}")

    audit.record_event(
        tenant_id=principal.tenant_id, event=f"surface_{surface}",
        layer=result.layer, verdict=result.verdict.value,
        reason=";".join(result.reasons[:6]) or "clean",
        meta={"risk": result.risk, "category": result.category.value,
              "findings": len(result.findings), "trace_id": trace.trace_id},
    )
    metrics.record_request(result.verdict.value, result.category.value, False,
                           result.latency_ms)
    payload = result.as_dict()
    payload["sanitized"] = result.sanitized
    payload["trace_id"] = trace.trace_id
    return payload


def _decode_artifact(content: str, encoding: str) -> bytes:
    if encoding == "base64":
        try:
            return base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(status_code=400,
                                detail=f"invalid base64 content: {exc}") from exc
    return (content or "").encode("utf-8", "replace")


@router.post("/browser")
async def scan_browser(body: BrowserScanRequest,
                       authorization: str | None = Header(default=None)):
    """Scan fetched HTML. Forward ``sanitized`` — the human-visible page only."""
    principal = _guard(authorization)
    trace = forensics.new_trace(tenant_id=principal.tenant_id, session_id=body.source)
    result = browser_surface.scan(body.html, source=body.source)
    return _finish(principal, result, trace, surface="browser")


@router.post("/document")
async def scan_document(body: DocumentScanRequest,
                        authorization: str | None = Header(default=None)):
    """Scan a document. ``content`` is UTF-8 text or base64 per ``encoding``."""
    principal = _guard(authorization)
    trace = forensics.new_trace(tenant_id=principal.tenant_id, session_id=body.filename)
    data = _decode_artifact(body.content, body.encoding)
    result = document_surface.scan(data, filename=body.filename,
                                   media_type=body.media_type, source=body.source)
    return _finish(principal, result, trace, surface="document")


@router.post("/rag")
async def scan_rag(body: RagScanRequest,
                   authorization: str | None = Header(default=None)):
    """Scan a retrieval set. Use ``kept_chunks`` — the poisoned ones are dropped."""
    principal = _guard(authorization)
    trace = forensics.new_trace(tenant_id=principal.tenant_id)
    chunks = [rag_surface.Chunk(text=c.text, source=c.source, trust=c.trust,
                                score=c.score, chunk_id=c.chunk_id,
                                metadata=c.metadata or {})
              for c in body.chunks]
    result = rag_surface.scan_chunks(chunks, query=body.query,
                                     registry=body.registry)
    payload = _finish(principal, result, trace, surface="rag")
    payload["kept_chunks"] = [
        {"chunk_id": c.chunk_id, "source": c.source, "text": c.text}
        for c in result.filtered_chunks
    ]
    return payload


@router.post("/memory")
async def scan_memory(body: MemoryScanRequest,
                      authorization: str | None = Header(default=None)):
    """Gate a memory write (``mode='write'``) or a recall set (``mode='recall'``)."""
    principal = _guard(authorization)
    trace = forensics.new_trace(tenant_id=principal.tenant_id)
    records = [memory_surface.MemoryRecord(
        text=r.text, origin=r.origin, record_id=r.record_id,
        tenant_id=principal.tenant_id) for r in body.records]
    if not records:
        raise HTTPException(status_code=400, detail="no records supplied")

    if body.mode == "recall":
        result = memory_surface.scan_recall(records)
    else:
        existing = [memory_surface.MemoryRecord(text=r.text, origin=r.origin,
                                                record_id=r.record_id)
                    for r in body.existing]
        result = memory_surface.scan_write(records[0], existing=existing)
    payload = _finish(principal, result, trace, surface="memory")
    payload["persist_allowed"] = result.persist_allowed
    payload["requires_approval"] = result.requires_approval
    return payload


@router.post("/tool")
async def scan_tool(body: ToolCallRequest,
                    authorization: str | None = Header(default=None)):
    """Gate a proposed tool call. Execute only when ``execute_allowed`` is true."""
    principal = _guard(authorization)
    trace = forensics.new_trace(tenant_id=principal.tenant_id)
    call = tool_surface.ToolCall(
        name=body.name, arguments=body.arguments or {}, description=body.description,
        server=body.server, caller_role=body.caller_role,
        user_intent=body.user_intent, schema=body.tool_schema or {},
    )
    policy = tool_surface.ToolPolicy(
        allowed_tools=body.policy.allowed_tools if body.policy else [],
        denied_tools=body.policy.denied_tools if body.policy else [],
        allowed_roots=body.policy.allowed_roots if body.policy else [],
        allowed_hosts=body.policy.allowed_hosts if body.policy else [],
        destructive_requires_approval=(
            body.policy.destructive_requires_approval if body.policy else True),
        allow_private_network=(
            body.policy.allow_private_network if body.policy else False),
        role_tools=body.policy.role_tools if body.policy else {},
    )
    result = tool_surface.scan_call(call, policy=policy)

    # Chain analysis: per-call checks are blind to staged exfiltration, where
    # every individual call is legitimate and the attack is the sequence.
    chain = None
    if body.session_id:
        chain = toolchain.observe(
            f"{principal.tenant_id}:{body.session_id}", call,
            result_text=body.result_text)
        trace.record_surface(chain)
        if not chain.execute_allowed:
            result.execute_allowed = False
            result.verdict = chain.verdict
            result.risk = max(result.risk, chain.risk)
            result.findings.extend(chain.findings)
            result.reasons.extend(chain.reasons[:4])
            result.requires_approval = chain.requires_approval

    trace.record_tool(result)
    payload = _finish(principal, result, trace, surface="tool")
    payload["execute_allowed"] = result.execute_allowed
    payload["requires_approval"] = result.requires_approval
    if chain is not None:
        payload["chain"] = {
            "length": chain.chain_length, "taint_hits": chain.taint_hits,
            "verdict": chain.verdict.value, "risk": chain.risk,
            "findings": [f.as_dict() for f in chain.findings[:10]],
        }
    return payload


@router.post("/agent")
async def scan_agent(body: AgentMessageRequest,
                     authorization: str | None = Header(default=None)):
    """Gate one inter-agent message. Deliver only when ``deliver_allowed``."""
    principal = _guard(authorization)
    trace = forensics.new_trace(tenant_id=principal.tenant_id)
    message = agent_surface.AgentMessage(
        content=body.content, sender=body.sender, recipient=body.recipient,
        taint=body.taint, hop=body.hop, origin=body.origin,
    )
    result = agent_surface.scan_message(message)
    payload = _finish(principal, result, trace, surface="agent")
    payload["deliver_allowed"] = result.deliver_allowed
    payload["propagated_taint"] = result.propagated_taint
    return payload


@router.post("/multimodal")
async def scan_multimodal(body: MultimodalScanRequest,
                          authorization: str | None = Header(default=None)):
    """Scan an image/audio artifact. Check ``coverage`` before trusting ALLOW."""
    principal = _guard(authorization)
    trace = forensics.new_trace(tenant_id=principal.tenant_id)
    data = _decode_artifact(body.content, body.encoding)
    result = multimodal_surface.scan(data, filename=body.filename,
                                     media_type=body.media_type,
                                     ocr_text=body.ocr_text,
                                     transcript=body.transcript)
    payload = _finish(principal, result, trace, surface="multimodal")
    payload["coverage"] = result.coverage
    return payload


# --- discovery + forensics -------------------------------------------------

meta_router = APIRouter(tags=["surfaces"])


@meta_router.get("/aegis/surfaces")
async def list_surfaces(authorization: str | None = Header(default=None)):
    """Which surfaces this deployment has enabled, and the effective thresholds."""
    _guard(authorization)
    from app.config import settings

    th = settings.surface_thresholds
    return {
        "surfaces": surface_status(),
        "thresholds": {"block": th.block, "quarantine": th.quarantine,
                       "density": th.density},
        "multimodal_providers": multimodal_surface.providers(),
        "pinned_tools": tool_surface.get_registry().pinned(),
    }


@meta_router.get("/aegis/forensics/{trace_id}")
async def get_trace(trace_id: str, authorization: str | None = Header(default=None)):
    """Fetch one sealed decision trace. Tenant-scoped."""
    principal = _guard(authorization)
    trace = forensics.get_trace(trace_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="trace not found or aged out")
    if trace.get("tenant_id") != principal.tenant_id:
        # Do not leak existence across tenants.
        raise HTTPException(status_code=404, detail="trace not found or aged out")
    return trace


@meta_router.get("/aegis/forensics")
async def list_traces(limit: int = 50,
                      authorization: str | None = Header(default=None)):
    """List recent traces for the caller's tenant."""
    principal = _guard(authorization)
    return {"traces": forensics.list_traces(tenant_id=principal.tenant_id,
                                            limit=min(max(limit, 1), 200))}


@meta_router.get("/aegis/events")
async def recent_events(limit: int = 100,
                        authorization: str | None = Header(default=None)):
    """Recent inspection events for this tenant (real-time monitoring, poll)."""
    principal = _guard(authorization)
    return {"events": events.get_bus().recent(
        tenant_id=principal.tenant_id, limit=min(max(limit, 1), 500)),
        "stats": events.get_bus().stats()}


@meta_router.get("/aegis/events/stream")
async def stream_events(authorization: str | None = Header(default=None),
                        token: str | None = None):
    """Server-sent event stream of live inspection decisions (deliverable 4).

    Each decision fans out to connected dashboards as it happens. EventSource
    cannot set an Authorization header, so a ``?token=<api-key>`` query fallback
    is accepted in addition to the bearer header — over TLS in production.
    """
    principal = _principal(authorization or (f"Bearer {token}" if token else None))
    tenant = principal.tenant_id

    async def gen():
        import asyncio
        import json

        q = events.get_bus().subscribe()
        try:
            # An initial comment so the client's connection opens immediately.
            yield ": aegis event stream connected\n\n"
            while True:
                if q:
                    ev = q.popleft()
                    if ev.tenant_id == tenant:
                        yield f"data: {json.dumps(ev.as_dict())}\n\n"
                else:
                    # Heartbeat keeps proxies from closing an idle connection.
                    yield ": heartbeat\n\n"
                    await asyncio.sleep(1.0)
        finally:
            events.get_bus().unsubscribe(q)

    from fastapi.responses import StreamingResponse
    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-store", "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    })
