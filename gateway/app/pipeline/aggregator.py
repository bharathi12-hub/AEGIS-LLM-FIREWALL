"""Aggregator + ensemble-disagreement tripwire + over-defense guard (4.7).

Fuses heterogeneous signals — normalization risk, signatures, both classifiers,
embedding similarity, KAD, and conversation context — into one verdict with an
OWASP-LLM category and a confidence, plus the two tripwires that make the
ensemble more than the sum of its parts:

  * DISAGREEMENT TRIPWIRE (T1). If the two classifiers strongly disagree, or if
    normalization risk is high while classifiers say benign (the classic evasion
    signature), escalate to the judge and bias toward BLOCK. Disagreement is
    itself a threat signal.
  * OVER-DEFENSE GUARD (G3/T3). A benign prompt that trips only isolated
    trigger-words — with no structural rule, no behavioral (KAD) hit, and no
    obfuscation — is calibrated *down* to control false positives.

Fusion uses a noisy-OR so that any single strong, trustworthy detector (e.g. KAD)
can carry a block, while weak correlated signals don't stack into a false alarm.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.config import Thresholds, settings
from app.pipeline.classifier import ClassifierScores
from app.pipeline.context import ContextResult
from app.pipeline.embeddings import EmbeddingResult
from app.pipeline.judge import JudgeResult
from app.pipeline.kad import KADResult
from app.pipeline.normalize import NormalizationResult
from app.pipeline.signatures import SignatureResult
from app.pipeline.structural import StructuralResult
from app.taxonomy import OwaspLLM, Verdict

# Trigger words that, ALONE, must not block (NotInject-style calibration set).
# Present in plenty of legitimate business prompts.
_BENIGN_TRIGGERS = {
    "ignore", "system", "prompt", "instructions", "reveal", "act", "pretend",
    "override", "password", "secret", "admin", "role", "developer",
}


@dataclass
class AggregatorInput:
    normalization: NormalizationResult
    signatures: SignatureResult
    classifiers: ClassifierScores
    embeddings: EmbeddingResult
    kad: KADResult
    context: ContextResult
    # Optional so existing callers constructing an AggregatorInput positionally
    # or by keyword keep working unchanged (v2.0 backward compatibility).
    structural: StructuralResult | None = None


@dataclass
class Decision:
    verdict: Verdict
    score: float
    category: OwaspLLM
    confidence: float
    escalate_to_judge: bool
    reasons: list[str] = field(default_factory=list)
    contributions: dict[str, float] = field(default_factory=dict)
    tripwires: list[str] = field(default_factory=list)
    judge: JudgeResult | None = None


def _noisy_or(parts: list[float]) -> float:
    prod = 1.0
    for p in parts:
        prod *= (1.0 - max(0.0, min(1.0, p)))
    return 1.0 - prod


def _pick_category(inp: AggregatorInput) -> OwaspLLM:
    if inp.signatures.matches:
        top = max(inp.signatures.matches, key=lambda m: m.severity)
        try:
            return OwaspLLM(top.category)
        except ValueError:
            return OwaspLLM.LLM01_PROMPT_INJECTION
    if inp.kad.injection_detected:
        return OwaspLLM.LLM01_PROMPT_INJECTION
    if inp.structural and inp.structural.findings:
        return inp.structural.category
    return OwaspLLM.NONE


def _structural_evidence(inp: AggregatorInput) -> bool:
    """Is there evidence beyond isolated trigger words?"""
    strong_sig = any(m.severity >= 0.8 for m in inp.signatures.matches)
    # A template/deserialization payload IS structural evidence by definition —
    # without this the over-defense guard would happily relieve an SSTI string
    # that tripped no trigger words.
    strong_struct = bool(inp.structural and inp.structural.score >= 0.6)
    return (
        strong_sig
        or strong_struct
        or inp.kad.injection_detected
        or inp.normalization.risk >= settings.thresholds.normalization_tripwire
        or inp.context.assembled_hit
        or inp.embeddings.max_similarity >= 0.85
    )


def aggregate(inp: AggregatorInput, thresholds: Thresholds | None = None,
              judge: JudgeResult | None = None) -> Decision:
    th = thresholds or settings.thresholds
    reasons: list[str] = []
    tripwires: list[str] = []

    # --- individual evidence contributions (0..1) ---
    sig = inp.signatures.score
    clf = inp.classifiers.max_score
    kad = 0.85 if inp.kad.injection_detected else 0.0
    emb = max(0.0, (inp.embeddings.max_similarity - 0.6) / 0.4)
    ctx = max(inp.context.escalation, 0.8 if inp.context.assembled_hit else 0.0)
    norm = inp.normalization.risk
    struct = inp.structural.score if inp.structural else 0.0

    contributions = {
        "signatures": round(sig, 3), "classifiers": round(clf, 3),
        "kad": round(kad, 3), "embeddings": round(emb, 3),
        "context": round(ctx, 3), "normalization": round(norm, 3),
        "structural": round(struct, 3),
    }

    # Normalization is a *booster*, not primary evidence — weight it modestly.
    fused = _noisy_or([sig, clf, kad, emb, ctx, 0.5 * norm, struct])

    # --- TRIPWIRE 1: ensemble disagreement ---
    disagree = inp.classifiers.disagreement
    if disagree >= th.disagreement_tripwire:
        tripwires.append(f"classifier-disagreement:{disagree:.2f}")
        fused = min(1.0, fused + 0.10)

    # --- TRIPWIRE 2: evasion signature (obfuscation high, classifiers calm) ---
    if norm >= th.normalization_tripwire and clf < th.review_low:
        tripwires.append(f"evasion-obfuscation-vs-benign-classifier:norm={norm:.2f}")
        fused = min(1.0, fused + 0.30)
        reasons.append("high-obfuscation-with-quiet-classifiers")

    # --- OVER-DEFENSE GUARD (only when there is no structural evidence) ---
    if not _structural_evidence(inp):
        matched_terms = {m.matched.lower() for m in inp.signatures.matches}
        only_triggers = matched_terms and matched_terms.issubset(_BENIGN_TRIGGERS)
        weak = clf < th.block and sig < 0.8
        if (only_triggers or not inp.signatures.matches) and weak:
            relief = min(th.over_defense_relief, fused * 0.5)
            if relief > 0:
                fused = max(0.0, fused - relief)
                reasons.append(f"over-defense-relief:-{relief:.2f}")

    fused = round(min(1.0, fused), 4)

    # --- fold in judge, if already run (fail-closed on invalid) ---
    escalate = False
    if judge is not None:
        reasons.append(f"judge:{judge.label}:valid={judge.valid}:{judge.backend}")
        if judge.is_malicious:
            fused = max(fused, max(0.8, judge.confidence))
            tripwires.append("judge-malicious")
        else:
            # A confident benign judge can pull a borderline case down.
            if fused < th.block:
                fused = min(fused, max(th.review_low, 1.0 - judge.confidence))
    else:
        # Should we escalate? Uncertainty band, or a tripwire fired.
        in_band = th.review_low <= fused < th.block
        escalate = in_band or bool(tripwires)

    # --- verdict ---
    if fused >= th.block:
        verdict = Verdict.BLOCK
    elif escalate:
        verdict = Verdict.REVIEW
    else:
        verdict = Verdict.ALLOW

    category = _pick_category(inp)
    if judge is not None and judge.is_malicious and category == OwaspLLM.NONE:
        category = judge.category

    confidence = fused if verdict != Verdict.ALLOW else round(1.0 - fused, 4)

    for r in inp.normalization.reasons:
        reasons.append(f"norm:{r}")
    for c in inp.signatures.categories:
        reasons.append(f"sig:{c}")
    if inp.structural:
        for f in inp.structural.findings[:6]:
            reasons.append(f"struct:{f.kind}")
    if inp.kad.injection_detected:
        reasons.append(f"kad:injection(conf={inp.kad.confidence})")
    for r in inp.context.reasons:
        reasons.append(f"ctx:{r}")

    return Decision(
        verdict=verdict, score=fused, category=category, confidence=confidence,
        escalate_to_judge=escalate, reasons=reasons, contributions=contributions,
        tripwires=tripwires, judge=judge,
    )
