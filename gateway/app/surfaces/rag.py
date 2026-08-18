"""RAG security layer — the retrieval boundary (LLM08, LLM04, LLM01-indirect).

WHY THIS EXISTS
---------------
Retrieval is a privilege escalation the system performs on the attacker's
behalf. The user asks a question; the retriever selects text by *similarity*
and the assembler pastes it into the prompt above the user's turn, where the
model treats it as established context. Nothing in that path asks whether the
text should be trusted — similarity is not authority.

That gives an attacker two distinct wins:

  1. POISONING. Get one document into the index (a public wiki the crawler
     scrapes, a shared drive, a support ticket, a product review) and its
     instructions execute whenever it is retrieved.
  2. RETRIEVAL HIJACKING. Because selection is by similarity, a chunk stuffed
     with high-frequency question terms is retrieved for queries it has nothing
     to do with. A chunk that ranks first for everything is not a good chunk,
     it is an attack — so this module scores *keyword stuffing* and
     *query-independence* directly.

THREAT MODEL
------------
  Attacker: can write to at least one document that will be indexed, but cannot
            change the retriever, the prompt template, or the user's question.
  Goals:    execute instructions via a retrieved chunk; be retrieved more often
            than legitimate chunks; make the model cite a source that does not
            support the claim.
  Defences implemented here:
      * per-chunk instruction scanning (the base data-channel prior)
      * SOURCE TRUST scoring — a chunk from an unverified/user-writable origin
        must clear a higher bar than one from a curated corpus
      * PROVENANCE verification — chunks whose declared source is missing,
        unregistered, or self-asserted are penalised
      * RETRIEVAL ANOMALY — keyword stuffing, query-term flooding, duplicate
        near-identical chunks, and outlier-length chunks
      * QUARANTINE — the poisoned chunk is dropped and the *rest* of the
        retrieval set is still usable, so a single bad document degrades recall
        instead of failing the request
      * CITATION verification — after generation, check that each cited source
        was actually retrieved and actually supports the sentence citing it

DESIGN NOTE
-----------
Quarantine, not block, is the default outcome. A RAG pipeline that hard-fails
whenever one chunk is dirty is a pipeline operators switch off. Dropping the
chunk and continuing preserves availability, which is why ``filtered_chunks``
is the field callers are expected to use.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from app.config import settings
from app.surfaces import base
from app.surfaces.base import Segment, SurfaceFinding, SurfaceResult
from app.taxonomy import Channel, OwaspLLM, Verdict

_SURFACE = "rag"


# ---------------------------------------------------------------------------
# Source trust
# ---------------------------------------------------------------------------

# Trust tiers. The multiplier scales a chunk's risk: the same instruction text
# is more dangerous from a source anyone can edit than from a curated corpus.
TRUST_TIERS = {
    "verified": 0.70,      # signed / hash-pinned, change-controlled corpus
    "curated": 0.85,       # internal, reviewed, restricted write access
    "internal": 1.00,      # internal but broadly writable (wiki, tickets, chat)
    "external": 1.25,      # public web, vendor docs, third-party feeds
    "user": 1.35,          # uploaded by an end user in this session
    "unknown": 1.40,       # no declared provenance — the worst case
}
DEFAULT_TIER = "unknown"


@dataclass
class Chunk:
    """One retrieved passage plus everything needed to judge whether to trust it."""

    text: str
    source: str = ""                 # document id / URL — the provenance anchor
    trust: str = DEFAULT_TIER        # key into TRUST_TIERS
    score: float = 0.0               # retriever similarity, if the caller has it
    chunk_id: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class ChunkAssessment:
    chunk: Chunk
    risk: float
    trust_multiplier: float
    quarantined: bool
    reasons: list[str] = field(default_factory=list)
    findings: list[SurfaceFinding] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "chunk_id": self.chunk.chunk_id or self.chunk.fingerprint,
            "source": self.chunk.source,
            "trust": self.chunk.trust,
            "risk": round(self.risk, 4),
            "trust_multiplier": self.trust_multiplier,
            "quarantined": self.quarantined,
            "reasons": self.reasons[:8],
        }


@dataclass
class RagResult(SurfaceResult):
    """SurfaceResult plus the retrieval-specific outputs callers act on."""

    chunks: list[ChunkAssessment] = field(default_factory=list)
    filtered_chunks: list[Chunk] = field(default_factory=list)
    quarantined_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = super().as_dict()
        d.update({
            "chunks": [c.as_dict() for c in self.chunks],
            "kept": len(self.filtered_chunks),
            "quarantined_ids": self.quarantined_ids,
        })
        return d


# ---------------------------------------------------------------------------
# Retrieval anomaly detection
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[a-z0-9']+")


def _tokens(text: str) -> list[str]:
    return _WORD_RE.findall((text or "").lower())


def _keyword_stuffing(text: str) -> tuple[float, str]:
    """Detect a chunk engineered to rank for everything.

    Two independent tells, both cheap:
      * low type/token ratio over a long chunk — the same terms repeated to
        inflate term-frequency scoring;
      * a single token occupying an implausible share of the chunk.
    Short chunks are exempt: a 12-word passage legitimately repeats words.
    """
    toks = _tokens(text)
    if len(toks) < 40:
        return 0.0, ""
    unique = len(set(toks))
    ttr = unique / len(toks)
    if ttr < 0.25:
        return 0.60, f"low-type-token-ratio:{ttr:.2f}"
    counts: dict[str, int] = {}
    for t in toks:
        if len(t) > 3:
            counts[t] = counts.get(t, 0) + 1
    if counts:
        top_tok, top_n = max(counts.items(), key=lambda kv: kv[1])
        share = top_n / len(toks)
        if share > 0.15 and top_n >= 8:
            return 0.50, f"term-flooding:{top_tok}x{top_n}({share:.2f})"
    return 0.0, ""


def _query_independence(text: str, query: str) -> tuple[float, str]:
    """A chunk that mirrors the query's vocabulary but shares no topic content.

    Classic retrieval-hijack shape: the attacker prepends the likely question to
    the payload so the embedding lands next to any query, then follows it with
    instructions. High query-term coverage plus instruction shape is the signal;
    this function only measures the coverage half.
    """
    q = set(_tokens(query))
    if len(q) < 3:
        return 0.0, ""
    toks = _tokens(text)
    if not toks:
        return 0.0, ""
    covered = len(q & set(toks)) / len(q)
    if covered > 0.85 and len(toks) > 60:
        return 0.35, f"query-mirroring:{covered:.2f}"
    return 0.0, ""


def _near_duplicates(chunks: list[Chunk]) -> dict[int, str]:
    """Index -> reason for chunks that are near-identical to an earlier one.

    Index flooding (the same payload inserted under many document ids) is how an
    attacker guarantees at least one copy survives top-k selection.
    """
    out: dict[int, str] = {}
    shingles: list[set[str]] = []
    for i, c in enumerate(chunks):
        toks = _tokens(c.text)
        sh = {" ".join(toks[j:j + 5]) for j in range(max(0, len(toks) - 4))}
        for j, prev in enumerate(shingles):
            if not sh or not prev:
                continue
            overlap = len(sh & prev) / max(1, min(len(sh), len(prev)))
            if overlap > 0.80 and chunks[j].source != c.source:
                out[i] = f"near-duplicate-of-chunk[{j}]:{overlap:.2f}"
                break
        shingles.append(sh)
    return out


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

@dataclass
class ProvenanceReport:
    ok: bool
    reasons: list[str] = field(default_factory=list)


def verify_provenance(chunk: Chunk, *, registry: dict[str, str] | None = None) -> ProvenanceReport:
    """Check a chunk's declared origin against a registry of known sources.

    ``registry`` maps source id -> trust tier. It is the deployment's statement
    of what it indexed. A chunk claiming a source that is not in the registry is
    either a misconfiguration or an injected record, and both deserve the
    penalty — this is what stops a poisoned vector-DB row from asserting
    ``trust="verified"`` about itself.
    """
    reasons: list[str] = []
    if not chunk.source:
        return ProvenanceReport(False, ["no-declared-source"])
    if chunk.trust not in TRUST_TIERS:
        reasons.append(f"unknown-trust-tier:{chunk.trust}")
    if registry is not None:
        declared = registry.get(chunk.source)
        if declared is None:
            reasons.append(f"source-not-in-registry:{chunk.source[:80]}")
        elif declared != chunk.trust:
            # The record claims more trust than the deployment granted it.
            if TRUST_TIERS.get(chunk.trust, 1.4) < TRUST_TIERS.get(declared, 1.4):
                reasons.append(
                    f"trust-escalation:claims={chunk.trust},registry={declared}")
    return ProvenanceReport(not reasons, reasons)


def effective_trust(chunk: Chunk, provenance: ProvenanceReport) -> float:
    """Trust multiplier after provenance penalties."""
    mult = TRUST_TIERS.get(chunk.trust, TRUST_TIERS[DEFAULT_TIER])
    if not provenance.ok:
        # Unverifiable provenance collapses the chunk to the unknown tier at best.
        mult = max(mult, TRUST_TIERS[DEFAULT_TIER])
        if any(r.startswith("trust-escalation") for r in provenance.reasons):
            mult = max(mult, TRUST_TIERS["external"] + 0.10)
    return round(mult, 3)


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def scan_chunks(chunks: list[Chunk], *, query: str = "",
                registry: dict[str, str] | None = None) -> RagResult:
    """Scan a retrieval set; quarantine poisoned chunks, keep the rest usable."""
    if not settings.surfaces.enabled("rag"):
        out = RagResult(surface=_SURFACE, enabled=False, verdict=Verdict.ALLOW,
                        reasons=[f"surface-disabled:{_SURFACE}"])
        out.filtered_chunks = list(chunks)
        out.sanitized = "\n\n".join(c.text for c in chunks)
        return out

    th = settings.surface_thresholds
    result = RagResult(surface=_SURFACE)
    if not chunks:
        return result

    if len(chunks) > th.max_segments:
        result.reasons.append(f"chunk-cap-applied:{len(chunks)}->{th.max_segments}")
        chunks = chunks[: th.max_segments]

    duplicates = _near_duplicates(chunks)
    peak = 0.0

    for i, chunk in enumerate(chunks):
        cid = chunk.chunk_id or f"chunk[{i}]"
        prov = verify_provenance(chunk, registry=registry)
        mult = effective_trust(chunk, prov)

        seg = Segment(text=chunk.text, channel=Channel.STRUCTURED,
                      location=cid, source=chunk.source or "unregistered")
        assessment = base.assess_segment(seg, _SURFACE, th)

        reasons = list(prov.reasons)
        risk = assessment.risk

        stuff_score, stuff_reason = _keyword_stuffing(chunk.text)
        if stuff_reason:
            reasons.append(stuff_reason)
        qi_score, qi_reason = _query_independence(chunk.text, query)
        if qi_reason:
            reasons.append(qi_reason)
        dup_reason = duplicates.get(i)
        if dup_reason:
            reasons.append(dup_reason)

        retrieval_anomaly = max(stuff_score, qi_score, 0.45 if dup_reason else 0.0)
        # Retrieval anomalies are corroborating evidence, not proof: a chunk that
        # is BOTH engineered for retrieval AND carries instructions is the
        # attack; either alone is merely suspicious.
        if retrieval_anomaly and assessment.imperative.signals:
            risk = min(1.0, risk + retrieval_anomaly * 0.5)
        elif retrieval_anomaly:
            risk = min(1.0, risk + retrieval_anomaly * 0.25)

        if prov.reasons:
            risk = min(1.0, risk + 0.05 * len(prov.reasons))

        risk = min(1.0, risk * mult)

        findings = list(assessment.findings)
        for r in reasons:
            findings.append(SurfaceFinding(
                surface=_SURFACE, location=cid, channel=Channel.STRUCTURED.value,
                severity=min(1.0, retrieval_anomaly or 0.30),
                kind=f"retrieval:{r.split(':')[0]}",
                reason=r, category=OwaspLLM.LLM08_VECTOR_WEAKNESS,
                source=chunk.source,
            ))

        quarantined = risk >= th.quarantine
        result.chunks.append(ChunkAssessment(
            chunk=chunk, risk=round(risk, 4), trust_multiplier=mult,
            quarantined=quarantined, reasons=reasons, findings=findings,
        ))
        result.findings.extend(findings)
        peak = max(peak, risk)

        if quarantined:
            result.quarantined_ids.append(cid)
            result.segments_removed += 1
        else:
            result.filtered_chunks.append(chunk)

    result.segments_scanned = len(chunks)
    result.risk = round(min(1.0, peak), 4)
    result.sanitized = "\n\n".join(c.text for c in result.filtered_chunks)

    if result.findings:
        top = max(result.findings, key=lambda f: f.severity)
        result.category = top.category
        result.reasons.extend(f"{f.kind}@{f.location}" for f in result.findings[:6])

    if result.quarantined_ids:
        result.quarantined = True
        # REVIEW, not BLOCK: the clean chunks are still served. Only escalate to
        # BLOCK when nothing survived — there is no answer to ground, so
        # answering anyway would mean answering from the poisoned context.
        result.verdict = Verdict.BLOCK if not result.filtered_chunks else Verdict.REVIEW
        if not result.filtered_chunks:
            result.reasons.insert(0, "all-chunks-quarantined")

    result.meta.update({
        "query_len": len(query or ""),
        "trust_tiers": {c.chunk.trust: 1 for c in result.chunks},
        "kept": len(result.filtered_chunks),
        "quarantined": len(result.quarantined_ids),
        "registry_supplied": registry is not None,
    })
    return result


# ---------------------------------------------------------------------------
# Citation verification (post-generation)
# ---------------------------------------------------------------------------

_CITATION_RE = re.compile(r"\[(?:source|doc|ref|citation)[:\s]*([^\]]{1,120})\]",
                          re.IGNORECASE)


@dataclass
class CitationReport:
    ok: bool
    cited: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)   # cited, never retrieved
    ungrounded: list[str] = field(default_factory=list)    # cited, no lexical support
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "cited": self.cited,
                "unsupported": self.unsupported, "ungrounded": self.ungrounded,
                "reasons": self.reasons}


def verify_citations(answer: str, chunks: list[Chunk], *,
                     min_overlap: float = 0.18) -> CitationReport:
    """Check that citations in a generated answer point at retrieved evidence.

    Two failure modes, both real:
      * FABRICATED source — the answer cites a document that was never
        retrieved. Nothing grounds it; the model invented the authority.
      * UNGROUNDED citation — the source was retrieved, but the sentence citing
        it shares almost no content with it. This is the shape a successful
        retrieval-poisoning attack leaves behind, because the injected
        instruction produced text the legitimate source does not support.

    Lexical overlap is a floor, not a semantic entailment check — it catches
    fabrication and gross mismatch, and it says so rather than implying more.
    """
    report = CitationReport(ok=True)
    if not answer:
        return report

    by_id: dict[str, Chunk] = {}
    for i, c in enumerate(chunks):
        by_id[(c.chunk_id or f"chunk[{i}]").lower()] = c
        if c.source:
            by_id[c.source.lower()] = c

    for sentence in re.split(r"(?<=[.!?])\s+", answer):
        for raw in _CITATION_RE.findall(sentence):
            cite = raw.strip()
            report.cited.append(cite)
            chunk = by_id.get(cite.lower())
            if chunk is None:
                report.unsupported.append(cite)
                report.reasons.append(f"citation-not-retrieved:{cite[:60]}")
                continue
            s_toks = {t for t in _tokens(sentence) if len(t) > 3}
            c_toks = {t for t in _tokens(chunk.text) if len(t) > 3}
            if s_toks:
                overlap = len(s_toks & c_toks) / len(s_toks)
                if overlap < min_overlap:
                    report.ungrounded.append(cite)
                    report.reasons.append(
                        f"citation-not-supported:{cite[:60]}:overlap={overlap:.2f}")

    report.ok = not report.unsupported and not report.ungrounded
    return report
