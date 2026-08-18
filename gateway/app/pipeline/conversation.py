"""Whole-conversation inspection — every message, not just the last user turn.

WHY THIS EXISTS
---------------
This closes the single largest hole found in the v2.1 audit.

``ChatCompletionRequest.latest_user_text()`` returns exactly one string: the most
recent user turn. Inspecting only that is the industry-default integration, and
it is wrong, because in an agentic application the user's turn is the ONE part of
the request the attacker usually does not control. What they do control:

    role="tool"       tool results — a web page, a database row, an API response.
                      This is the primary indirect-injection carrier in every
                      agent framework, and it is fed back verbatim as context.
    role="assistant"  replayed turns. A client assembles this array; nothing
                      guarantees the "assistant" text was ever produced by the
                      model. It is a free write into the model's own voice.
    role="system"     client-supplied system messages. In a gateway the client is
                      not the operator, so a system turn asking to disable rules
                      is a privilege-escalation attempt, not configuration.
    tools[]           function/MCP definitions, whose descriptions are injected
                      into context on every turn.
    content parts     image_url / input_audio parts in multimodal requests.

Before this module, all five bypassed every detection layer AEGIS has. The
firewall was guarding the front door of a building with five open windows.

TRUST BY ROLE
-------------
Roles are not equally trustworthy, and the difference is the point:

  * The latest USER turn keeps the v2.0 prompt path unchanged — over-defense
    relief included — because a human is allowed to phrase a request oddly.
  * Every other message is DATA and gets the surface prior ("data must not
    instruct"), weighted by role. A tool result carries the heaviest weight
    because it is wholly attacker-reachable and wholly trusted by the model.

That asymmetry is what lets AEGIS block a poisoned tool result without becoming
unusable for people who type "ignore the formatting errors in my draft".

BACKWARD COMPATIBILITY
----------------------
The latest user turn still flows through ``Orchestrator.inspect`` exactly as in
v2.0, so existing verdicts, thresholds, and tests are unchanged. This module only
adds inspection of messages that previously received none.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.config import settings
from app.surfaces import base as surface_base
from app.surfaces.base import Segment, SurfaceFinding
from app.taxonomy import Channel, OwaspLLM, Verdict

_SURFACE = "conversation"


# Role -> (channel, risk weight, human label).
#
# Weights multiply the fused risk. They encode reachability, not suspicion: how
# easily can an attacker put bytes here, and how completely does the model trust
# them once they arrive?
ROLE_TRUST: dict[str, tuple[Channel, float, str]] = {
    # Tool output is the classic indirect vector: fully attacker-reachable
    # (it is a web page or a DB row), fully trusted by the model as ground truth.
    "tool": (Channel.STRUCTURED, 1.35, "tool result"),
    "function": (Channel.STRUCTURED, 1.35, "function result"),
    # A client-assembled "assistant" turn is an unauthenticated write into the
    # model's own voice — the strongest position from which to issue an
    # instruction, because models weight their own prior output heavily.
    "assistant": (Channel.STRUCTURED, 1.25, "prior assistant turn"),
    # Client-supplied system turns: legitimate persona-setting is common, so the
    # weight is modest, but guardrail-removal here is escalation, not config.
    "system": (Channel.STRUCTURED, 1.15, "client-supplied system message"),
    "developer": (Channel.STRUCTURED, 1.15, "developer message"),
    # Earlier user turns: already the user's own voice, so only mildly weighted.
    "user": (Channel.VISIBLE, 1.05, "earlier user turn"),
}
# An unrecognised role is not a reason to relax: unknown provenance is treated
# as attacker-reachable structured data.
DEFAULT_ROLE_TRUST = (Channel.STRUCTURED, 1.20, "message")


@dataclass
class MessageAssessment:
    index: int
    role: str
    risk: float
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    findings: list[SurfaceFinding] = field(default_factory=list)
    quarantined: bool = False
    chars: int = 0

    def as_dict(self) -> dict:
        return {
            "index": self.index, "role": self.role,
            "risk": round(self.risk, 4), "verdict": self.verdict.value,
            "quarantined": self.quarantined, "chars": self.chars,
            "reasons": self.reasons[:6],
        }


@dataclass
class ConversationResult:
    """Verdict over the whole request, excluding the latest user turn.

    The caller fuses this with the v2.0 prompt verdict for that turn; see
    ``api/proxy.py``. Keeping them separate preserves the v2.0 contract and makes
    the audit trail say plainly WHICH part of the request was hostile.
    """

    verdict: Verdict = Verdict.ALLOW
    risk: float = 0.0
    category: OwaspLLM = OwaspLLM.NONE
    messages: list[MessageAssessment] = field(default_factory=list)
    findings: list[SurfaceFinding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    quarantined_indices: list[int] = field(default_factory=list)
    tool_definition_risk: float = 0.0
    inspected: int = 0
    skipped: int = 0
    latency_ms: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "blocked": self.blocked,
            "risk": round(self.risk, 4),
            "category": self.category.value,
            "inspected": self.inspected,
            "skipped": self.skipped,
            "quarantined_indices": self.quarantined_indices,
            "tool_definition_risk": round(self.tool_definition_risk, 4),
            "reasons": self.reasons[:10],
            "messages": [m.as_dict() for m in self.messages
                         if m.verdict != Verdict.ALLOW][:20],
            "latency_ms": self.latency_ms,
        }


def _content_to_text(content) -> tuple[str, list[str]]:
    """Flatten OpenAI content (string or content-parts) to text + media refs."""
    if content is None:
        return "", []
    if isinstance(content, str):
        return content, []
    text_parts: list[str] = []
    media: list[str] = []
    if isinstance(content, list):
        for part in content:
            if not isinstance(part, dict):
                text_parts.append(str(part))
                continue
            ptype = part.get("type", "")
            if ptype == "text" or "text" in part:
                text_parts.append(str(part.get("text", "")))
            elif ptype in {"image_url", "image"}:
                url = part.get("image_url")
                url = url.get("url", "") if isinstance(url, dict) else str(url or "")
                media.append(url)
            elif ptype in {"input_audio", "audio"}:
                media.append("<audio>")
            else:
                # Unknown part types still carry attacker-controlled strings.
                for value in part.values():
                    if isinstance(value, str):
                        text_parts.append(value)
    return "\n".join(p for p in text_parts if p), media


def _extract_tool_definitions(body) -> list[tuple[str, str]]:
    """Return (tool_name, description) for tools/functions declared in a request.

    Tool descriptions are third-party text that goes straight into the model's
    context every turn — the MCP description-poisoning vector, arriving through
    the OpenAI-compatible API instead of an MCP server.
    """
    out: list[tuple[str, str]] = []
    raw = getattr(body, "model_extra", None) or {}

    for tool in (raw.get("tools") or [])[:200]:
        if not isinstance(tool, dict):
            continue
        fn = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        name = str(fn.get("name", "tool"))
        desc = str(fn.get("description", "") or "")
        params = fn.get("parameters")
        # Parameter descriptions are injected into context too, and are a
        # commonly-forgotten smuggling slot.
        if isinstance(params, dict):
            props = params.get("properties")
            if isinstance(props, dict):
                for pname, spec in list(props.items())[:100]:
                    if isinstance(spec, dict) and spec.get("description"):
                        desc += f"\n[param {pname}] {spec['description']}"
        if desc.strip():
            out.append((name, desc))

    for fn in (raw.get("functions") or [])[:200]:   # legacy functions API
        if isinstance(fn, dict) and fn.get("description"):
            out.append((str(fn.get("name", "function")), str(fn["description"])))
    return out


def inspect_conversation(body, *, skip_index: int | None = None,
                         max_messages: int | None = None) -> ConversationResult:
    """Inspect every message except ``skip_index`` (the latest user turn).

    ``skip_index`` exists so the caller can route that one message through the
    unchanged v2.0 prompt path and avoid double-counting it here.
    """
    t0 = time.perf_counter()
    result = ConversationResult()
    th = settings.surface_thresholds

    messages = list(getattr(body, "messages", None) or [])
    limit = max_messages or settings.conversation_max_messages
    # Inspect the most recent N. Older turns have already been inspected on the
    # requests that introduced them, and an unbounded array is a DoS vector.
    if len(messages) > limit:
        result.skipped = len(messages) - limit
        offset = len(messages) - limit
        window = list(enumerate(messages))[offset:]
        result.reasons.append(f"conversation-window:{limit}/{len(messages)}")
    else:
        window = list(enumerate(messages))

    peak = 0.0
    for index, message in window:
        if skip_index is not None and index == skip_index:
            continue
        role = (getattr(message, "role", None) or "user").lower()
        text, media = _content_to_text(getattr(message, "content", None))
        if not text.strip() and not media:
            continue

        channel, weight, label = ROLE_TRUST.get(role, DEFAULT_ROLE_TRUST)
        seg = Segment(text=text[: th.max_segment_chars], channel=channel,
                      location=f"message[{index}]:{role}", source=role)
        assessment = surface_base.assess_segment(seg, _SURFACE, th)
        risk = min(1.0, assessment.risk * weight)

        reasons = [f"{f.kind}" for f in assessment.findings[:6]]
        findings = list(assessment.findings)

        # A tool result that instructs is the canonical indirect injection: the
        # model asked a question and the answer told it what to do.
        if role in {"tool", "function"} and assessment.imperative.signals:
            findings.append(SurfaceFinding(
                surface=_SURFACE, location=f"message[{index}]:{role}",
                channel=channel.value, severity=0.85,
                kind="tool-result-instructs",
                reason=("a tool result is issuing instructions to the model — "
                        "tool output is data, not a directive"),
                excerpt=assessment.imperative.signals[0].matched,
                category=OwaspLLM.LLM01_PROMPT_INJECTION, source=role,
            ))
            risk = max(risk, 0.85)
            reasons.append("tool-result-instructs")

        # A client-supplied system/assistant turn that tries to remove guardrails
        # is escalation. Persona-setting is fine; disabling rules is not.
        if role in {"system", "developer", "assistant"}:
            kinds = {s.kind for s in assessment.imperative.signals}
            if kinds & {"concealment", "authority-claim", "recursive",
                        "delayed-trigger"}:
                findings.append(SurfaceFinding(
                    surface=_SURFACE, location=f"message[{index}]:{role}",
                    channel=channel.value, severity=0.80,
                    kind=f"{role}-turn-escalation",
                    reason=(f"client-supplied {label} attempts to alter standing "
                            f"behaviour rather than set context"),
                    excerpt=assessment.imperative.signals[0].matched,
                    category=OwaspLLM.LLM01_PROMPT_INJECTION, source=role,
                ))
                risk = max(risk, 0.80)
                reasons.append(f"{role}-turn-escalation")

        verdict = (Verdict.BLOCK if risk >= th.block else
                   Verdict.REVIEW if risk >= th.quarantine else Verdict.ALLOW)
        if verdict != Verdict.ALLOW:
            result.quarantined_indices.append(index)

        result.messages.append(MessageAssessment(
            index=index, role=role, risk=round(risk, 4), verdict=verdict,
            reasons=reasons, findings=findings,
            quarantined=(verdict != Verdict.ALLOW), chars=len(text),
        ))
        result.findings.extend(findings)
        result.inspected += 1
        peak = max(peak, risk)

    # --- tool / function definitions -------------------------------------
    for name, description in _extract_tool_definitions(body):
        seg = Segment(text=description[: th.max_segment_chars],
                      channel=Channel.METADATA,
                      location=f"tool-definition:{name}", source="tool-definition")
        assessment = surface_base.assess_segment(seg, _SURFACE, th)
        if assessment.risk >= th.quarantine:
            result.findings.append(SurfaceFinding(
                surface=_SURFACE, location=f"tool-definition:{name}",
                channel=Channel.METADATA.value,
                severity=max(0.80, assessment.risk),
                kind="poisoned-tool-definition",
                reason=("a declared tool's description contains instructions — "
                        "descriptions enter the model's context every turn"),
                excerpt=description[:160], category=OwaspLLM.LLM03_SUPPLY_CHAIN,
                source=name,
            ))
            result.findings.extend(assessment.findings)
            result.tool_definition_risk = max(result.tool_definition_risk,
                                              assessment.risk)
            peak = max(peak, max(0.80, assessment.risk))
            result.reasons.append(f"poisoned-tool-definition:{name}")
        result.inspected += 1

    result.risk = round(min(1.0, peak), 4)
    if result.findings:
        top = max(result.findings, key=lambda f: f.severity)
        result.category = top.category
        result.reasons.extend(f"{f.kind}@{f.location}" for f in result.findings[:6])

    result.verdict = (Verdict.BLOCK if result.risk >= th.block else
                      Verdict.REVIEW if result.risk >= th.quarantine else
                      Verdict.ALLOW)
    result.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
    return result


def latest_user_index(body) -> int | None:
    """Index of the message the v2.0 prompt path will inspect."""
    messages = list(getattr(body, "messages", None) or [])
    for i in range(len(messages) - 1, -1, -1):
        if (getattr(messages[i], "role", "") or "").lower() == "user":
            return i
    return None
