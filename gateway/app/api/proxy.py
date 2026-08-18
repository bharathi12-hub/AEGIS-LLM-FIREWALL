"""OpenAI-compatible proxy (R6) + shared inspection service.

POST /v1/chat/completions is a drop-in OpenAI endpoint. Each request flows:

    auth -> rate-limit -> policy(allow/deny) -> INPUT inspection -> (block?)
         -> forward SANITIZED text upstream -> OUTPUT inspection (DLP+canary)
         -> timing-normalize -> respond, with an audit record either way.

The forwarded bytes are exactly ``InspectionResult.forward_text`` (R9/S2 parity).
The heavy work lives in the pure pipeline; this module is orchestration + policy.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse

from app.api.schemas import ChatCompletionRequest, InspectRequest
from app.auth import Principal
from app.security.oidc import principal_from_token
from app.config import Thresholds, settings
from app.observability import audit, events, metrics
from app.observability.logging import sanitize_for_render
from app.output import canary as canary_mod
from app.output.dlp import scan_output
from app.pipeline.conversation import inspect_conversation, latest_user_index
from app.pipeline.orchestrator import Orchestrator
from app.policy.engine import get_engine
from app.policy.rbac import AccessRequest, get_authorization_engine
from app.policy.schema import EffectivePolicy
from app.security.ratelimit import get_judge_budget, get_rate_limiter
from app.security.timing import apply_async
from app.storage.cache import get_cache
from app.taxonomy import Verdict
from app.upstream import llm_client

router = APIRouter()

# Shared singletons — Redis-backed across replicas when AEGIS_REDIS_URL is set,
# in-memory otherwise (single-node dev).
_judge_budget = get_judge_budget()
_rate_limiter = get_rate_limiter()
_orchestrator = Orchestrator(
    cache=get_cache(),
    judge_allowed=lambda tenant: _judge_budget.allow(tenant),
)


def authorize(principal: Principal, action: str, *, resource: dict | None = None,
              environment: dict | None = None):
    """RBAC + ABAC + OPA check. Raises 403 when denied.

    Separate from authentication on purpose: knowing WHO you are does not say
    WHAT you may do, and the trust score means the answer changes over time.
    """
    import datetime as _dt

    env = {
        "hour": _dt.datetime.now().hour,
        "timestamp": time.time(),
        **(environment or {}),
    }
    decision = get_authorization_engine().authorize(AccessRequest(
        action=action,
        principal={"key_id": principal.key_id, "tenant_id": principal.tenant_id,
                   "role": principal.role},
        resource=resource or {},
        environment=env,
    ))
    if not decision.allowed:
        audit.record_event(
            tenant_id=principal.tenant_id, event="authz_deny", layer="policy",
            verdict="block", reason=";".join(decision.reasons[:4]),
            meta={"action": action, "effect_source": decision.effect_source,
                  "matched_rules": decision.matched_rules},
        )
        raise HTTPException(status_code=403,
                            detail=f"not authorized for {action}")
    return decision


def _thresholds(policy: EffectivePolicy) -> Thresholds:
    base = settings.thresholds
    return Thresholds(
        block=policy.block_threshold,
        review_low=policy.review_threshold,
        over_defense_relief=base.over_defense_relief,
        normalization_tripwire=base.normalization_tripwire,
        disagreement_tripwire=base.disagreement_tripwire,
    )


def _principal(authorization: str | None) -> Principal:
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    principal = principal_from_token(token)  # OIDC JWT or first-party API key
    if not principal:
        raise HTTPException(status_code=401, detail="invalid or missing credentials")
    return principal


@dataclass
class InspectionOutcome:
    verdict: str
    blocked: bool
    category: str
    score: float
    reasons: list
    contributions: dict
    tripwires: list
    latency_ms: float
    judge_used: bool
    forward_text: str
    normalization: dict
    alarms: list
    kad_fingerprint: str


def run_input_inspection(text: str, principal: Principal, policy: EffectivePolicy,
                         session_id: str) -> InspectionOutcome:
    """The reusable inspection path (also powers the dashboard Test Console)."""
    low = (text or "").lower()
    # Policy deny/allow lists short-circuit (deny wins).
    forced = None
    if any(term.lower() in low for term in policy.deny_list):
        forced = Verdict.BLOCK
    elif any(term.lower() in low for term in policy.allow_list):
        forced = Verdict.ALLOW

    result = _orchestrator.inspect(
        text, session_id=session_id, tenant_id=principal.tenant_id,
        fail_mode=policy.fail_mode, run_judge=policy.judge_enabled,
        thresholds=_thresholds(policy),
    )
    d = result.decision
    verdict = d.verdict
    if forced is not None:
        verdict = forced
    elif verdict == Verdict.REVIEW:
        # Unresolved uncertainty: fail-closed tenants block, others allow+alarm.
        verdict = Verdict.BLOCK if policy.fail_mode == "closed" else Verdict.ALLOW
        if policy.fail_mode != "closed":
            result.alarms.append("review-failopen-allowed")

    return InspectionOutcome(
        verdict=verdict.value,
        blocked=(verdict == Verdict.BLOCK),
        category=d.category.value,
        score=d.score,
        reasons=d.reasons,
        contributions=d.contributions,
        tripwires=d.tripwires,
        latency_ms=result.latency_ms,
        judge_used=result.judge_used,
        forward_text=result.forward_text,
        normalization={
            "risk": result.normalization.risk,
            "reasons": result.normalization.reasons,
            "stripped": result.normalization.stripped_counts,
            "decoded_views": result.normalization.decoded_views[:3],
        },
        alarms=result.alarms,
        kad_fingerprint=result.kad_fingerprint,
    )


@router.get("/v1/models")
async def list_models():
    return {"object": "list", "data": [
        {"id": "aegis-guarded-gpt", "object": "model", "owned_by": "aegis"},
    ]}


@router.post("/v1/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    authorization: str | None = Header(default=None),
    x_aegis_session: str | None = Header(default=None),
):
    t0 = time.perf_counter()
    principal = _principal(authorization)

    # Rate limit per API key (S5).
    if not _rate_limiter.allow(principal.key_id):
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    model = body.model
    user_text = body.latest_user_text()
    if not user_text:
        raise HTTPException(status_code=400, detail="no user message")

    # S14: reject grossly oversized inputs rather than letting them exhaust limits.
    if len(user_text) > settings.max_prompt_chars * 4:
        raise HTTPException(status_code=413, detail="prompt too large")

    # Authorization (RBAC/ABAC/OPA). Distinct from the 401 above: that proved
    # identity, this decides entitlement — and the answer moves with the
    # principal's trust score.
    authorize(principal, "chat:complete")

    session_id = x_aegis_session or f"{principal.tenant_id}:{principal.key_id}"
    policy = get_engine().effective(principal.tenant_id)

    outcome = run_input_inspection(user_text, principal, policy, session_id)

    # WHOLE-CONVERSATION inspection (v2.1 audit fix). The block above covers the
    # latest user turn only — which is the one part of an agentic request the
    # attacker usually does NOT control. Tool results, replayed assistant turns,
    # client-supplied system messages, and tool definitions are inspected here.
    conversation = None
    if settings.inspect_conversation:
        conversation = inspect_conversation(
            body, skip_index=latest_user_index(body))
        if conversation.verdict != Verdict.ALLOW:
            # Fuse: the request is only as trustworthy as its most hostile part.
            outcome.reasons.extend(conversation.reasons[:6])
            outcome.score = max(outcome.score, conversation.risk)
            if conversation.blocked or policy.fail_mode == "closed":
                outcome.verdict = Verdict.BLOCK.value
                outcome.blocked = True
                if outcome.category == "none":
                    outcome.category = conversation.category.value
            else:
                outcome.alarms.append("conversation-review-failopen-allowed")

    # Close the detection -> authorization loop: a key that keeps getting
    # blocked loses trust, and ABAC withdraws its high-consequence actions
    # automatically. Detection that never changes entitlement is just logging.
    get_authorization_engine().trust.record(principal.key_id,
                                            blocked=outcome.blocked)

    # Real-time monitoring (deliverable 4): fan this decision out to any live
    # dashboard subscribers. Best-effort — never blocks or fails the request.
    events.publish_inspection(
        tenant_id=principal.tenant_id, verdict=outcome.verdict,
        category=outcome.category, score=outcome.score,
        latency_ms=outcome.latency_ms, reasons=outcome.reasons)

    if outcome.blocked:
        audit.record_event(
            tenant_id=principal.tenant_id, event="block", layer="input",
            verdict=outcome.verdict, reason=";".join(outcome.reasons[:6]),
            prompt=user_text,
            meta={"category": outcome.category, "score": outcome.score,
                  "tripwires": outcome.tripwires},
        )
        metrics.record_request("block", outcome.category, outcome.judge_used,
                               outcome.latency_ms)
        await apply_async(t0, settings.response_floor_ms, settings.response_jitter_ms)
        return JSONResponse(status_code=200, content={
            "id": "chatcmpl-aegis-blocked", "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "finish_reason": "content_filter",
                         "message": {"role": "assistant",
                                     "content": "[AEGIS] This request was blocked by the "
                                                "prompt firewall."}}],
            "aegis": _aegis_meta(outcome, None, conversation),
        })

    # Forward the SANITIZED bytes upstream, with a canary-decorated system prompt.
    system_prompt = "You are a helpful assistant."
    canary = canary_mod.get_manager().issue(session_id)
    decorated = canary_mod.get_manager().decorate_system_prompt(session_id, system_prompt)
    upstream = await llm_client.complete(
        model=model, sanitized_user_text=outcome.forward_text,
        system_prompt=decorated, canary_token=canary.token,
    )
    answer = upstream["choices"][0]["message"]["content"]

    # OUTPUT inspection: decode-then-scan DLP + canary leak (4.10 / S12).
    dlp = scan_output(answer, canary_tokens=canary_mod.get_manager().tokens_for(session_id))
    output_block = None
    if dlp.blocked:
        output_block = {"leaked": dlp.leaked, "reasons": dlp.reasons,
                        "findings": [{"kind": f.kind, "where": f.where} for f in dlp.findings]}
        category = "LLM07:SystemPromptLeakage" if dlp.leaked else "LLM06:SensitiveInformationDisclosure"
        audit.record_event(
            tenant_id=principal.tenant_id, event="output_block", layer="output",
            verdict="block", reason=";".join(dlp.reasons) or "dlp-finding",
            meta={"category": category, **output_block},
        )
        answer = "[AEGIS] The model response was withheld: it contained sensitive or leaked data."
        metrics.record_request("block", category, outcome.judge_used, outcome.latency_ms)
    else:
        audit.record_event(
            tenant_id=principal.tenant_id, event="allow", layer="output",
            verdict="allow", reason="clean", prompt=user_text,
            meta={"score": outcome.score},
        )
        metrics.record_request("allow", outcome.category, outcome.judge_used,
                               outcome.latency_ms)

    upstream["choices"][0]["message"]["content"] = answer
    upstream["aegis"] = _aegis_meta(outcome, output_block, conversation)
    await apply_async(t0, settings.response_floor_ms, settings.response_jitter_ms)
    return JSONResponse(content=upstream)


def _atlas_from_reasons(reasons: list) -> list[dict]:
    """Distinct MITRE ATLAS techniques implicated by a decision's reasons."""
    from app.taxonomy import atlas_for

    seen: dict[str, str] = {}
    for reason in reasons:
        # Reasons look like "struct:ssti:jinja-sandbox-escape" or "sig:LLM01:..".
        kind = reason.split(":", 1)[1] if ":" in reason else reason
        atlas_id, label = atlas_for(kind)
        seen.setdefault(atlas_id, label)
    return [{"id": tid, "label": label} for tid, label in seen.items()]


def _aegis_meta(outcome: InspectionOutcome, output_block, conversation=None) -> dict:
    meta = {
        "verdict": outcome.verdict,
        "category": outcome.category,
        "atlas": _atlas_from_reasons(outcome.reasons),
        "score": outcome.score,
        "input_reasons": [sanitize_for_render(r, 120) for r in outcome.reasons[:8]],
        "contributions": outcome.contributions,
        "tripwires": outcome.tripwires,
        "normalization_risk": outcome.normalization["risk"],
        "judge_used": outcome.judge_used,
        "latency_ms": outcome.latency_ms,
        "kad_fingerprint": outcome.kad_fingerprint,
        "output_block": output_block,
    }
    # Say WHICH part of the request was hostile — "message[2]:tool" is
    # actionable, "blocked" is not.
    if conversation is not None:
        meta["conversation"] = conversation.as_dict()
    return meta


@router.post("/aegis/inspect")
async def inspect_only(
    body: InspectRequest,
    authorization: str | None = Header(default=None),
    x_aegis_session: str | None = Header(default=None),
):
    """Inspect-only endpoint for the dashboard Test Console (no upstream call)."""
    principal = _principal(authorization)
    session_id = x_aegis_session or f"console:{principal.key_id}"
    policy = get_engine().effective(principal.tenant_id)
    outcome = run_input_inspection(body.text, principal, policy, session_id)
    # The Test Console is a real inspection too — stream it to the live monitor.
    events.publish_inspection(
        tenant_id=principal.tenant_id, verdict=outcome.verdict,
        category=outcome.category, score=outcome.score,
        latency_ms=outcome.latency_ms, reasons=outcome.reasons, layer="console")
    return asdict(outcome)
