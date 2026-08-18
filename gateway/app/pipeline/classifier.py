"""Fine-tuned classifier ENSEMBLE (4.4) — offline heuristic profile + pluggable HF.

The spec calls for two *diverse* local models
(protectai/deberta-v3-base-prompt-injection-v2 and Llama-Prompt-Guard-2-86M) so a
single perturbation cannot evade both. Those models are hundreds of MB and the
Llama one is license-gated, which conflicts with the "runs fully offline, no
keys" hard rule (R1). So AEGIS ships two *diverse heuristic* detectors that give
genuine, deterministic probabilities offline, and transparently swaps in the
real transformers models when a local model directory is present
(``AEGIS_HF_MODEL_DIR``). safetensors-only loading is enforced in
``security/modelscan.py`` (S3).

The two heuristics are deliberately built on different feature families:
  * LexicalModel      — attack-vocabulary / intent lexicon (like ProtectAI's
                        semantic injection focus).
  * StructuralModel   — imperative-override *structure*, negation-of-rules, and
                        obfuscation density (like Prompt Guard's multilabel view).
Because they look at different things, they can disagree — and disagreement is
itself a threat signal the aggregator exploits (4.7 tripwire).
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field

from app.config import settings


@dataclass
class ClassifierScores:
    per_model: dict[str, float] = field(default_factory=dict)
    backend: str = "heuristic"  # or "transformers"

    @property
    def max_score(self) -> float:
        return max(self.per_model.values()) if self.per_model else 0.0

    @property
    def mean_score(self) -> float:
        vals = list(self.per_model.values())
        return sum(vals) / len(vals) if vals else 0.0

    @property
    def disagreement(self) -> float:
        """Spread between the most and least suspicious model."""
        if len(self.per_model) < 2:
            return 0.0
        vals = list(self.per_model.values())
        return max(vals) - min(vals)


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


# ---------------------------------------------------------------------------
# Heuristic model A — lexical / intent
# ---------------------------------------------------------------------------
_LEXICON = {
    # phrase: weight  (tuned so genuine attacks clear the bar while benign
    # trigger-word prompts stay low — see the FPR gate in the benchmark)
    "ignore previous": 3.0, "ignore all previous": 3.2, "ignore the previous": 3.0,
    "disregard the": 2.4, "disregard all": 2.6, "disregard your": 2.6,
    "system prompt": 1.3, "system instructions": 1.5, "developer mode": 1.6,
    "jailbroken": 3.2, "jailbreak": 3.0, "do anything now": 3.4,
    "you are now": 1.8, "pretend to be": 1.6, "roleplay as": 1.6,
    "act as a jailbroken": 3.2, "unfiltered": 2.4, "uncensored": 2.6,
    "unrestricted": 2.4, "no restrictions": 2.6, "zero restrictions": 3.0,
    "no rules": 2.2, "no ethics": 2.6, "without any restrictions": 3.0,
    "restrictions no longer apply": 3.0, "no longer apply to you": 2.6,
    "bypass": 1.6, "bypass your": 2.2, "bypass content": 2.8, "content policy": 1.6,
    "disable all guardrails": 3.0, "disable guardrails": 3.0, "guardrails": 1.4,
    "override": 1.6, "override all": 2.4, "confidential system": 2.2,
    "reveal your": 1.8, "reveal the": 1.6, "raw prompt": 2.4, "dump the": 1.6,
    "password": 1.0, "admin password": 2.0, "api key": 1.6, "api keys": 1.8,
    "secret key": 2.0, "exfiltrate": 3.0, "leak": 1.2, "encoded as": 1.2,
    "prompt injection": 2.0, "forget your": 2.6, "new instructions": 2.2,
    "must not refuse": 2.6, "ignore refusals": 3.0, "hypothetical": 0.6,
    "you have no rules": 3.0, "for educational purposes": 1.0,
}


class LexicalModel:
    name = "aegis-lexical-v1"

    def score(self, text: str) -> float:
        low = text.lower()
        acc = -2.2  # bias toward benign; only real attack vocab lifts it
        for phrase, w in _LEXICON.items():
            if phrase in low:
                acc += w
        return round(_sigmoid(acc), 4)


# ---------------------------------------------------------------------------
# Heuristic model B — structural / imperative-override
# ---------------------------------------------------------------------------
_STRUCT_PATTERNS = [
    (re.compile(r"\b(ignore|disregard|forget|override)\b.{0,30}\b(instruction|instructions|rule|rules|prompt|above|previous|prior)\b", re.I), 3.0),
    (re.compile(r"\byou are (now |a |an )", re.I), 1.8),
    (re.compile(r"\bfrom now on\b", re.I), 1.6),
    (re.compile(r"\b(do not|don't|never)\b.{0,20}\b(refuse|decline|follow|obey|filter)\b", re.I), 2.2),
    (re.compile(r"\b(reveal|print|show|repeat|output)\b.{0,20}\b(system )?(prompt|instructions)\b", re.I), 2.6),
    (re.compile(r"\b(base64|rot13|hex)\b.{0,20}\b(encode|decode)\b", re.I), 1.8),
    (re.compile(r"[.!?]\s*(ignore|disregard|now|instead|actually)\b", re.I), 1.0),  # instruction pivot
]


class StructuralModel:
    name = "aegis-structural-v1"

    def score(self, text: str, obfuscation: float = 0.0) -> float:
        acc = -2.4
        for pat, w in _STRUCT_PATTERNS:
            if pat.search(text):
                acc += w
        # Obfuscation density feeds this model directly (a structural anomaly).
        acc += 2.5 * obfuscation
        # Imperative-heavy short prompts are more suspicious.
        if len(text) < 240 and text.count("\n") == 0:
            imperatives = len(re.findall(r"\b(ignore|reveal|print|act|pretend|override|bypass)\b", text, re.I))
            acc += 0.4 * imperatives
        return round(_sigmoid(acc), 4)


# ---------------------------------------------------------------------------
# Optional transformers backend (pluggable, safetensors-only)
# ---------------------------------------------------------------------------
class _TransformersEnsemble:
    """Loaded lazily only if a local model dir is configured and importable."""

    # Label names (case-insensitive) that indicate the malicious/injection class.
    _POSITIVE_LABELS = {"injection", "jailbreak", "malicious", "unsafe", "attack",
                        "label_1", "1", "true", "positive"}

    def __init__(self, model_dir: str):
        from app.security.modelscan import assert_safetensors_only  # noqa: WPS433
        import os
        from transformers import (  # type: ignore
            AutoModelForSequenceClassification,
            AutoTokenizer,
        )
        import torch  # type: ignore

        self._torch = torch
        self._models = []
        for sub in sorted(os.listdir(model_dir)):
            path = os.path.join(model_dir, sub)
            if not os.path.isdir(path):
                continue
            assert_safetensors_only(path)  # S3: refuse pickle checkpoints (dir scan)
            tok = AutoTokenizer.from_pretrained(path)
            # use_safetensors=True forces safetensors weights and refuses to fall
            # back to a pickle .bin — S3 enforcement at the transformers layer too.
            mdl = AutoModelForSequenceClassification.from_pretrained(
                path, use_safetensors=True)
            mdl.eval()
            self._models.append((sub, tok, mdl, self._positive_index(mdl)))
        if not self._models:
            raise RuntimeError("no models found in AEGIS_HF_MODEL_DIR")

    def _positive_index(self, mdl) -> int:
        id2label = getattr(mdl.config, "id2label", None) or {}
        for idx, label in id2label.items():
            if str(label).strip().lower() in self._POSITIVE_LABELS:
                return int(idx)
        # Fallback: last class is the malicious one (common 2-class convention).
        return mdl.config.num_labels - 1

    def score(self, text: str) -> dict[str, float]:
        out: dict[str, float] = {}
        with self._torch.no_grad():
            for name, tok, mdl, pos in self._models:
                enc = tok(text, truncation=True, max_length=512, return_tensors="pt")
                probs = self._torch.softmax(mdl(**enc).logits[0], dim=-1)
                out[name] = float(probs[pos])
        return out


class ClassifierEnsemble:
    def __init__(self) -> None:
        self._lex = LexicalModel()
        self._struct = StructuralModel()
        self._cache: dict[str, ClassifierScores] = {}
        self._hf: _TransformersEnsemble | None = None
        if settings.hf_model_dir:
            try:
                self._hf = _TransformersEnsemble(settings.hf_model_dir)
            except Exception:  # noqa: BLE001 — never let model loading break the gateway
                self._hf = None

    def classify(self, text: str, obfuscation: float = 0.0,
                 cache=None) -> ClassifierScores:
        key = hashlib.sha256(f"{text}|{obfuscation:.3f}".encode()).hexdigest()
        # External cache (Redis) takes priority; falls back to in-process dict.
        if cache is not None:
            hit = cache.get_json(f"clf:{key}")
            if hit:
                return ClassifierScores(per_model=hit["per_model"], backend=hit["backend"])
        elif key in self._cache:
            return self._cache[key]

        if self._hf is not None:
            try:
                scores = ClassifierScores(per_model=self._hf.score(text), backend="transformers")
            except Exception:  # noqa: BLE001
                scores = self._heuristic(text, obfuscation)
        else:
            scores = self._heuristic(text, obfuscation)

        if cache is not None:
            cache.set_json(f"clf:{key}", {"per_model": scores.per_model, "backend": scores.backend})
        else:
            self._cache[key] = scores
        return scores

    def _heuristic(self, text: str, obfuscation: float) -> ClassifierScores:
        return ClassifierScores(per_model={
            self._lex.name: self._lex.score(text),
            self._struct.name: self._struct.score(text, obfuscation),
        }, backend="heuristic")


_ensemble: ClassifierEnsemble | None = None


def get_ensemble() -> ClassifierEnsemble:
    global _ensemble
    if _ensemble is None:
        _ensemble = ClassifierEnsemble()
    return _ensemble
