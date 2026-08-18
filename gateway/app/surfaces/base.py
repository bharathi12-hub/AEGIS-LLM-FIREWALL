"""Shared types and scanning engine for all non-prompt surfaces (v2.1).

WHY A SEPARATE ENGINE
---------------------
``app.pipeline.orchestrator`` inspects a *conversation turn*: it keeps per-session
state, escalates to a judge, and applies over-defense relief because a human is
allowed to phrase a request oddly. None of that fits a retrieved PDF chunk or a
tool argument, and running document text through the multi-turn tracker would
poison the conversation state with attacker-controlled content.

So surfaces reuse the pipeline's *layers* — the same normalizer, the same
signature rules, the same classifier ensemble — but fuse them with a different
prior:

    prompt surface : "the user may be odd"       -> relief, block at 0.75
    data surface   : "data must not instruct"    -> no relief, block at 0.60,
                                                    severity scaled by how
                                                    hidden the channel is

That single change of prior is what turns a jailbreak detector into an indirect
prompt-injection detector. Everything else is plumbing.

CONTRACT
--------
Every surface module returns a :class:`SurfaceResult`. The two fields callers
must honour:

  * ``verdict``   — BLOCK means do not give this content to the model at all.
  * ``sanitized`` — when you do proceed, forward THESE bytes. Hidden-channel and
    instruction-bearing segments have been removed. This mirrors the R9/S2
    inspection/forward parity guarantee the prompt path already makes.

All modules are pure stdlib and deterministic.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.config import SurfaceThresholds, settings
from app.pipeline import signatures, structural
from app.pipeline.classifier import get_ensemble
from app.pipeline.normalize import normalize
from app.surfaces import imperative
from app.taxonomy import CHANNEL_WEIGHT, Channel, Layer, OwaspLLM, Verdict


@dataclass
class Segment:
    """One extracted piece of text plus the provenance that makes it judgeable."""

    text: str
    channel: Channel = Channel.VISIBLE
    location: str = ""          # "html:comment[2]", "pdf:/Info:Title", "chunk[3]"
    source: str = ""            # document id, URL, tool name — the trust anchor

    @property
    def visible(self) -> bool:
        return self.channel == Channel.VISIBLE

    @property
    def concealed(self) -> bool:
        """Is this channel one a human reader genuinely cannot see?

        Distinct from ``not visible``. A RAG chunk or a JSON value (STRUCTURED)
        is the NORMAL content channel for its surface — it is usually rendered
        or cited — whereas an HTML comment, EXIF field, or 0px paragraph is
        concealed by construction. Only the latter earns the
        ``hidden-instruction`` finding; treating every structured value as
        concealed inflated risk on ordinary retrieved text.
        """
        return self.channel in {Channel.HIDDEN, Channel.COMMENT,
                                Channel.METADATA, Channel.ATTRIBUTE, Channel.CODE}


@dataclass
class SurfaceFinding:
    """A scored problem in one segment. ``excerpt`` is untrusted — escape it."""

    surface: str
    location: str
    channel: str
    severity: float
    kind: str
    reason: str
    excerpt: str = ""
    category: OwaspLLM = OwaspLLM.LLM01_PROMPT_INJECTION
    source: str = ""

    def as_dict(self) -> dict:
        from app.observability.logging import sanitize_for_render
        from app.taxonomy import atlas_for

        atlas_id, atlas_label = atlas_for(self.kind)
        return {
            "surface": self.surface,
            "location": self.location,
            "channel": self.channel,
            "severity": round(self.severity, 4),
            "kind": self.kind,
            "reason": self.reason,
            "category": self.category.value,
            "atlas": atlas_id,
            "atlas_label": atlas_label,
            "source": self.source,
            "excerpt": sanitize_for_render(self.excerpt, 160),
        }


@dataclass
class SurfaceResult:
    """Verdict for one artifact (page, document, chunk set, tool call, memory)."""

    surface: str
    verdict: Verdict = Verdict.ALLOW
    risk: float = 0.0
    category: OwaspLLM = OwaspLLM.NONE
    findings: list[SurfaceFinding] = field(default_factory=list)
    sanitized: str = ""                       # safe-to-forward rendering
    segments_scanned: int = 0
    segments_removed: int = 0
    quarantined: bool = False
    enabled: bool = True
    latency_ms: float = 0.0
    reasons: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    @property
    def layer(self) -> str:
        return f"surface_{self.surface}"

    def as_dict(self) -> dict:
        return {
            "surface": self.surface,
            "verdict": self.verdict.value,
            "blocked": self.blocked,
            "risk": round(self.risk, 4),
            "category": self.category.value,
            "quarantined": self.quarantined,
            "enabled": self.enabled,
            "segments_scanned": self.segments_scanned,
            "segments_removed": self.segments_removed,
            "latency_ms": self.latency_ms,
            "reasons": self.reasons[:12],
            "findings": [f.as_dict() for f in self.findings[:20]],
            "meta": self.meta,
        }


def disabled(surface: str, passthrough: str = "") -> SurfaceResult:
    """Result returned when a surface is switched off (requirement: each module
    independently enable/disable-able). Explicitly ALLOW + ``enabled=False`` so
    the audit trail records that the layer was skipped rather than clean."""
    return SurfaceResult(
        surface=surface, verdict=Verdict.ALLOW, enabled=False,
        sanitized=passthrough, reasons=[f"surface-disabled:{surface}"],
    )


def _noisy_or(parts: list[float]) -> float:
    """Same fusion the prompt aggregator uses — one strong detector can carry a
    decision, weak correlated ones do not stack into a false alarm."""
    prod = 1.0
    for p in parts:
        prod *= (1.0 - max(0.0, min(1.0, p)))
    return 1.0 - prod


@dataclass
class SegmentAssessment:
    segment: Segment
    risk: float
    imperative: imperative.ImperativeResult
    signature_score: float
    classifier_score: float
    normalization_risk: float
    findings: list[SurfaceFinding] = field(default_factory=list)


def assess_segment(seg: Segment, surface: str,
                   thresholds: SurfaceThresholds | None = None) -> SegmentAssessment:
    """Run the pipeline layers over one segment with the data-channel prior."""
    th = thresholds or settings.surface_thresholds
    text = (seg.text or "")[: th.max_segment_chars]

    # Layer 1 — the SAME normalizer the prompt path uses. Documents are a richer
    # obfuscation carrier than prompts (a PDF can hold bidi runs and tag chars
    # that no human ever sees), so this must run before any pattern matching.
    norm = normalize(text, max_chars=th.max_segment_chars)
    scan_text = norm.scan_text

    sig = signatures.scan(scan_text)
    clf = get_ensemble().classify(scan_text, obfuscation=norm.risk)
    imp = imperative.analyze(scan_text)
    # Structural payloads reach the model through data channels too — an SSTI
    # string in a retrieved chunk or a tool argument is the same RCE one hop
    # later as one typed into the prompt.
    struct = structural.scan(scan_text, coherence_text=norm.sanitized)

    weight = CHANNEL_WEIGHT.get(seg.channel, 1.0)

    # Fuse. The imperative signal is the primary evidence on a data surface;
    # signatures and the classifier are corroboration (they were trained/written
    # for prompts, so on documents they are precise but not sensitive).
    fused = _noisy_or([
        imp.score,
        sig.score,
        struct.score,
        0.85 * clf.max_score,
        0.5 * norm.risk,
    ])

    # Instruction DENSITY promotes a carrier document over one that merely
    # quotes an instruction in passing.
    if imp.density >= th.density and imp.signals:
        fused = min(1.0, fused + 0.10)

    risk = min(1.0, fused * weight)

    findings: list[SurfaceFinding] = []
    for s in imp.signals:
        findings.append(SurfaceFinding(
            surface=surface, location=seg.location, channel=seg.channel.value,
            severity=min(1.0, s.severity * weight), kind=f"instruction:{s.kind}",
            reason=f"data channel contains {s.kind.replace('-', ' ')}",
            excerpt=s.matched, category=s.category, source=seg.source,
        ))
    for m in sig.matches:
        try:
            cat = OwaspLLM(m.category)
        except ValueError:
            cat = OwaspLLM.LLM01_PROMPT_INJECTION
        findings.append(SurfaceFinding(
            surface=surface, location=seg.location, channel=seg.channel.value,
            severity=min(1.0, m.severity * weight), kind=f"signature:{m.rule_id}",
            reason=f"prompt-injection signature {m.rule_id} in data channel",
            excerpt=m.matched, category=cat, source=seg.source,
        ))
    for f in struct.findings:
        findings.append(SurfaceFinding(
            surface=surface, location=seg.location, channel=seg.channel.value,
            severity=min(1.0, f.severity * weight), kind=f"structural:{f.kind}",
            reason=(f.detail or
                    f"structural injection payload ({f.kind}) in data channel"),
            excerpt=f.matched, category=f.category, source=seg.source,
        ))
    for reason in norm.reasons:
        # Obfuscation inside a data channel has no benign explanation at all —
        # a legitimate document does not smuggle tag characters.
        if reason.split(":")[0] in {"unicode-tag-smuggling", "bidi-override",
                                    "zero-width", "homoglyph"}:
            findings.append(SurfaceFinding(
                surface=surface, location=seg.location, channel=seg.channel.value,
                severity=min(1.0, 0.65 * weight), kind=f"obfuscation:{reason.split(':')[0]}",
                reason=f"character-injection in data channel ({reason})",
                excerpt="", category=OwaspLLM.LLM01_PROMPT_INJECTION, source=seg.source,
            ))

    # --- OVER-DEFENSE GUARD (mirrors the prompt aggregator's G3/T3 relief) ---
    # The data-channel prior is "data must not instruct". When there is NO
    # instruction shape at all, the only thing left is vocabulary — and the
    # classifier's lexicon was tuned for prompts, so on ordinary prose it fires
    # on words like "admin password" or "ignore". A security policy, an FAQ, or
    # a threat-model doc is exactly this shape. Relief is withheld from
    # concealed channels: there, even vocabulary is anomalous.
    # The bar is "no STRONG instruction shape". The deliberately-weak rules
    # (bare "you must", severity 0.35) must not block relief — they exist as
    # corroboration and are common in ordinary policy and documentation prose.
    if (imp.score < 0.5 and struct.score < 0.5 and not seg.concealed
            and norm.risk < 0.3 and sig.score < 0.8):
        relief = min(0.35, risk * 0.6)
        if relief > 0:
            risk = max(0.0, risk - relief)

    # A concealed channel that carries ANY instruction shape is reported in
    # its own right: this is the white-on-white / HTML-comment attack, and it is
    # the single highest-precision indirect-injection indicator we have.
    if seg.concealed and imp.signals:
        findings.append(SurfaceFinding(
            surface=surface, location=seg.location, channel=seg.channel.value,
            severity=min(1.0, 0.85 * weight), kind="hidden-instruction",
            reason=(f"instructions found in a channel the user cannot see "
                    f"({seg.channel.value})"),
            excerpt=(imp.signals[0].matched if imp.signals else ""),
            category=OwaspLLM.LLM01_PROMPT_INJECTION, source=seg.source,
        ))
        risk = max(risk, min(1.0, 0.70 * weight))

    return SegmentAssessment(
        segment=seg, risk=round(risk, 4), imperative=imp,
        signature_score=sig.score, classifier_score=clf.max_score,
        normalization_risk=norm.risk, findings=findings,
    )


def scan_segments(segments: list[Segment], *, surface: str,
                  thresholds: SurfaceThresholds | None = None,
                  strip_invisible: bool = True) -> SurfaceResult:
    """Assess every segment and fuse into one artifact-level verdict.

    ``strip_invisible`` removes every non-visible segment from ``sanitized``
    even when it scored clean. That is deliberate: content the human reader
    cannot see has no legitimate reason to reach the model, so the safe
    rendering is the visible document. Set it False only for surfaces where
    metadata is genuinely part of the payload the caller needs.
    """
    th = thresholds or settings.surface_thresholds
    t0 = time.perf_counter()

    result = SurfaceResult(surface=surface)
    if not segments:
        result.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        return result

    # S14-equivalent cap: an attacker must not be able to force unbounded work
    # by supplying a document with a million elements.
    if len(segments) > th.max_segments:
        result.reasons.append(
            f"segment-cap-applied:{len(segments)}->{th.max_segments}")
        segments = segments[: th.max_segments]

    kept: list[str] = []
    peak = 0.0
    weighted_sum = 0.0
    for seg in segments:
        a = assess_segment(seg, surface, th)
        result.findings.extend(a.findings)
        peak = max(peak, a.risk)
        weighted_sum += a.risk

        drop = a.risk >= th.quarantine or (strip_invisible and not seg.visible)
        if drop:
            result.segments_removed += 1
        elif seg.text.strip():
            kept.append(seg.text)

    result.segments_scanned = len(segments)

    # Artifact risk: the worst segment dominates (one poisoned chunk is enough
    # to compromise the answer), with a small bump when contamination is broad.
    mean = weighted_sum / max(1, len(segments))
    risk = min(1.0, peak + min(0.10, 0.5 * mean))
    result.risk = round(risk, 4)

    if result.findings:
        top = max(result.findings, key=lambda f: f.severity)
        result.category = top.category
        for f in result.findings[:8]:
            result.reasons.append(f"{f.kind}@{f.location or 'root'}")

    if risk >= th.block:
        result.verdict = Verdict.BLOCK
        result.quarantined = True
    elif risk >= th.quarantine:
        result.verdict = Verdict.REVIEW
        result.quarantined = True
    else:
        result.verdict = Verdict.ALLOW

    result.sanitized = "\n".join(kept).strip()
    if result.segments_removed:
        result.reasons.append(f"segments-removed:{result.segments_removed}")

    result.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
    return result


def layer_for(surface: str) -> Layer:
    """Map a surface name onto its telemetry layer (falls back safely)."""
    try:
        return Layer(f"surface_{surface}")
    except ValueError:
        return Layer.AGGREGATOR
