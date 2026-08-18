"""Detection baselines for comparison (Section 7).

Each baseline exposes ``predict(text, session_id) -> bool`` (True = block). The
benchmark runs the same labeled data + evasion transforms through every baseline
so the report can show single classifiers collapsing under evasion while the full
AEGIS stack holds.

Baselines:
  * regex_only            — signatures on the RAW text (no normalization).
  * protectai_like        — one heuristic classifier on RAW text (stands in for a
                            single fine-tuned classifier such as ProtectAI DeBERTa).
  * promptguard_like      — the other heuristic classifier on RAW text.
  * aegis_no_norm         — full ensemble/KAD but WITHOUT Normalization v2
                            (ablation: proves normalization's contribution).
  * aegis_v1_stack        — normalization + signatures + classifiers (no KAD, no
                            tripwires) — approximates the v1 "stack of detectors".
  * aegis_v2              — the complete pipeline.
"""
from __future__ import annotations

import os
import sys

# Make the gateway package importable when run as a script.
_GATEWAY = os.path.join(os.path.dirname(os.path.dirname(__file__)), "gateway")
if _GATEWAY not in sys.path:
    sys.path.insert(0, _GATEWAY)

from app.pipeline import signatures  # noqa: E402
from app.pipeline.aggregator import AggregatorInput, aggregate  # noqa: E402
from app.pipeline.classifier import get_ensemble  # noqa: E402
from app.pipeline.context import ContextResult  # noqa: E402
from app.pipeline.embeddings import query as emb_query  # noqa: E402
from app.pipeline.kad import check as kad_check  # noqa: E402
from app.pipeline.normalize import normalize, NormalizationResult  # noqa: E402
from app.pipeline.orchestrator import inspect_text  # noqa: E402
from app.taxonomy import Verdict  # noqa: E402

_BLOCK_THRESHOLD = 0.5  # for single-score baselines


def regex_only(text: str, session_id: str = "s") -> bool:
    # No normalization: the raw text is scanned directly (v1-era behavior).
    return signatures.scan(text).score >= 0.6


def protectai_like(text: str, session_id: str = "s") -> bool:
    ens = get_ensemble()
    scores = ens.classify(text, obfuscation=0.0)
    return scores.per_model.get("aegis-lexical-v1", 0.0) >= _BLOCK_THRESHOLD


def promptguard_like(text: str, session_id: str = "s") -> bool:
    ens = get_ensemble()
    scores = ens.classify(text, obfuscation=0.0)
    return scores.per_model.get("aegis-structural-v1", 0.0) >= _BLOCK_THRESHOLD


def aegis_no_norm(text: str, session_id: str = "s") -> bool:
    """Full detectors but fed RAW text (normalization ablated)."""
    raw = NormalizationResult(raw=text, sanitized=text, decoded_views=[], risk=0.0)
    sig = signatures.scan(text)
    clf = get_ensemble().classify(text, obfuscation=0.0)
    emb = emb_query(text)
    kad = kad_check(text)
    ctx = ContextResult(escalation=0.0, assembled_hit=False)
    decision = aggregate(AggregatorInput(raw, sig, clf, emb, kad, ctx))
    return decision.verdict == Verdict.BLOCK


def aegis_v1_stack(text: str, session_id: str = "s") -> bool:
    """Normalization + signatures + classifiers only (no KAD, no tripwires)."""
    norm = normalize(text)
    sig = signatures.scan(norm.scan_text)
    clf = get_ensemble().classify(norm.scan_text, obfuscation=norm.risk)
    # Emulate a plain stack: block if any single detector is confident.
    return sig.score >= 0.6 or clf.max_score >= _BLOCK_THRESHOLD


def aegis_v2(text: str, session_id: str = "s") -> bool:
    return inspect_text(text, session_id=session_id).verdict == Verdict.BLOCK


BASELINES = {
    "regex_only": regex_only,
    "protectai_like": protectai_like,
    "promptguard_like": promptguard_like,
    "aegis_no_norm": aegis_no_norm,
    "aegis_v1_stack": aegis_v1_stack,
    "aegis_v2": aegis_v2,
}
