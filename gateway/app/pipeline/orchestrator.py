"""Pipeline orchestrator — the layered, short-circuiting detection flow.

Order (each layer sees the normalized text, closing the char-injection gap):
    normalize -> signatures -> [classifiers, embeddings, KAD] -> context
    -> aggregate -> (judge, only in the uncertainty band / on a tripwire)

Cross-cutting guarantees:
  * R9/S2 parity: ``InspectionResult.forward_text`` is exactly the sanitized text
    every layer inspected — the caller forwards THESE bytes, no re-processing.
  * S4 fail modes: a layer that errors is handled per the tenant's fail mode —
    high-security tenants fail CLOSED (treat as attack); others may fail open but
    always raise an alarm. Never a silent fail-open.
  * S5 judge budget: the judge is only invoked when escalation is warranted AND
    the per-tenant budget allows, so attackers can't force expensive escalation.

Dependencies (cache, judge budget, session store) are injected with offline
defaults, so this module runs unchanged in tests, the benchmark, and the gateway.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from app.config import Thresholds, settings
from app.pipeline import embeddings, kad, signatures, structural
from app.pipeline.aggregator import AggregatorInput, Decision, aggregate
from app.pipeline.classifier import get_ensemble
from app.pipeline.context import get_tracker
from app.pipeline.judge import evaluate as judge_evaluate
from app.pipeline.normalize import NormalizationResult, normalize
from app.taxonomy import Layer, Verdict


@dataclass
class InspectionResult:
    verdict: Verdict
    decision: Decision
    forward_text: str                 # R9: inspected == forwarded bytes
    normalization: NormalizationResult
    latency_ms: float
    layer_ms: dict[str, float] = field(default_factory=dict)
    judge_used: bool = False
    alarms: list[str] = field(default_factory=list)
    kad_fingerprint: str = ""

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK


class Orchestrator:
    def __init__(
        self,
        *,
        cache=None,
        judge_allowed: Callable[[str], bool] | None = None,
        thresholds: Thresholds | None = None,
    ) -> None:
        self._cache = cache
        self._judge_allowed = judge_allowed or (lambda tenant: True)
        self._thresholds = thresholds or settings.thresholds
        self._ensemble = get_ensemble()
        self._tracker = get_tracker()

    def inspect(
        self,
        text: str,
        *,
        session_id: str = "default",
        tenant_id: str = "default",
        fail_mode: str = "closed",
        run_judge: bool = True,
        thresholds: Thresholds | None = None,
    ) -> InspectionResult:
        th = thresholds or self._thresholds
        t0 = time.perf_counter()
        layer_ms: dict[str, float] = {}
        alarms: list[str] = []

        def timed(layer: Layer, fn, fallback):
            start = time.perf_counter()
            try:
                out = fn()
            except Exception as exc:  # noqa: BLE001 — S4 fail-mode handling
                alarms.append(f"{layer.value}-error:{type(exc).__name__}")
                out = fallback(fail_mode)
            layer_ms[layer.value] = round((time.perf_counter() - start) * 1000, 3)
            return out

        # 1) Normalize (S14 cap inside).
        norm = timed(
            Layer.NORMALIZE,
            lambda: normalize(text, max_chars=settings.max_prompt_chars),
            lambda fm: normalize("", max_chars=settings.max_prompt_chars),
        )
        scan_text = norm.scan_text

        # 2) Signatures on normalized text.
        sig = timed(Layer.SIGNATURES, lambda: signatures.scan(scan_text),
                    lambda fm: signatures.SignatureResult())

        # 2b) Structural injection — template/deserialization payloads aimed at
        # the systems downstream of the model, plus many-shot and persuasion.
        struct = timed(
            Layer.STRUCTURAL,
            lambda: structural.scan(scan_text, coherence_text=norm.sanitized),
            lambda fm: structural.StructuralResult())

        # 3) Classifier ensemble (fail-closed -> high suspicion).
        clf = timed(
            Layer.CLASSIFIER,
            lambda: self._ensemble.classify(scan_text, obfuscation=norm.risk, cache=self._cache),
            lambda fm: _fail_classifier(fm),
        )

        # 4) Embedding similarity.
        emb = timed(Layer.EMBEDDINGS, lambda: embeddings.query(scan_text),
                    lambda fm: embeddings.EmbeddingResult(0.0, ""))

        # 5) KAD behavioral (fail-closed -> assume injection).
        kad_res = timed(
            Layer.KAD, lambda: kad.check(norm.sanitized),
            lambda fm: _fail_kad(fm),
        )

        # 6) Multi-turn context.
        ctx = timed(
            Layer.CONTEXT,
            lambda: self._tracker.observe(session_id, norm.sanitized),
            lambda fm: get_tracker().observe(session_id, ""),
        )

        # 7) Aggregate.
        agg_input = AggregatorInput(
            normalization=norm, signatures=sig, classifiers=clf,
            embeddings=emb, kad=kad_res, context=ctx, structural=struct,
        )
        decision = aggregate(agg_input, th)

        # 8) Judge — only on escalation and within budget (S5).
        judge_used = False
        if decision.escalate_to_judge and run_judge:
            if self._judge_allowed(tenant_id):
                jstart = time.perf_counter()
                judge = judge_evaluate(norm.sanitized, {
                    "normalization_risk": norm.risk,
                    "classifier_max": clf.max_score,
                    "signature_score": sig.score,
                })
                decision = aggregate(agg_input, th, judge)
                layer_ms[Layer.JUDGE.value] = round((time.perf_counter() - jstart) * 1000, 3)
                judge_used = True
            else:
                alarms.append("judge-budget-exhausted")
                # Budget exhausted on an escalated request: fail-closed biases block.
                if fail_mode == "closed" and decision.verdict == Verdict.REVIEW:
                    decision.verdict = Verdict.BLOCK
                    decision.reasons.append("judge-budget-exhausted->fail-closed-block")

        latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        return InspectionResult(
            verdict=decision.verdict, decision=decision, forward_text=norm.sanitized,
            normalization=norm, latency_ms=latency_ms, layer_ms=layer_ms,
            judge_used=judge_used, alarms=alarms,
            kad_fingerprint=kad_res.secret_fingerprint,
        )


def _fail_classifier(fail_mode: str):
    from app.pipeline.classifier import ClassifierScores
    if fail_mode == "closed":
        return ClassifierScores(per_model={"failsafe": 1.0}, backend="failclosed")
    return ClassifierScores(per_model={"failsafe": 0.0}, backend="failopen")


def _fail_kad(fail_mode: str):
    return kad.KADResult(
        injection_detected=(fail_mode == "closed"),
        confidence=1.0 if fail_mode == "closed" else 0.0,
        secret_fingerprint="failsafe", backend="failsafe",
    )


_default: Orchestrator | None = None


def get_orchestrator() -> Orchestrator:
    global _default
    if _default is None:
        _default = Orchestrator()
    return _default


def inspect_text(text: str, **kwargs) -> InspectionResult:
    """Convenience entry point used by tests, the benchmark, and the CLI."""
    return get_orchestrator().inspect(text, **kwargs)
