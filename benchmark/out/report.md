# AEGIS v2 — Benchmark & Red-Team Report

_Profile: **offline-heuristic** · generated 2026-08-18T14:54:43 · 30 attacks / 30 benign_

## Headline

> Under character-injection evasion (emoji-tag smuggling, bidi, homoglyph, zero-width, base64), a single classifier's attacks-through rate averages **95% ASR**. AEGIS v2 holds it to **0% ASR** by neutralizing the transform *before* classification and via behavioral KAD, while keeping clean recall at **100%** and FPR at **0.0%**.

## Clean detection quality

| Baseline | Precision | Recall | F1 | Accuracy | FPR | AUROC |
|---|---|---|---|---|---|---|
| `regex_only` | 1.000 | 0.967 | 0.983 | 0.983 | 0.000 | 0.983 |
| `protectai_like` | 0.950 | 0.633 | 0.760 | 0.800 | 0.033 | 0.800 |
| `promptguard_like` | 1.000 | 0.267 | 0.421 | 0.633 | 0.000 | 0.633 |
| `aegis_no_norm` | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 |
| `aegis_v1_stack` | 0.967 | 0.967 | 0.967 | 0.967 | 0.033 | 0.967 |
| `aegis_v2` | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 |

## Evasion ASR by transform (lower = better)

| Baseline | base64_wrap | bidi_override | char_perturb | emoji_tag_smuggle | homoglyph | leetspeak | plain | rot13_wrap | synonym_swap | zero_width |
|---|---|---|---|---|---|---|---|---|---|---|
| `regex_only` | 0.00 | 0.03 | 0.20 | 1.00 | 1.00 | 1.00 | 0.03 | 0.00 | 0.03 | 1.00 |
| `protectai_like` | 1.00 | 0.37 | 0.67 | 1.00 | 1.00 | 1.00 | 0.37 | 1.00 | 0.37 | 1.00 |
| `promptguard_like` | 1.00 | 0.73 | 0.83 | 1.00 | 1.00 | 1.00 | 0.73 | 1.00 | 0.80 | 1.00 |
| `aegis_no_norm` | 1.00 | 0.00 | 0.17 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 | 0.00 | 1.00 |
| `aegis_v1_stack` | 0.00 | 0.03 | 0.03 | 1.00 | 0.03 | 0.10 | 0.03 | 0.00 | 0.03 | 0.03 |
| `aegis_v2` | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.07 | 0.00 | 0.00 |

## Ablation — each layer earns its place

- Remove Normalization v2 (`aegis_no_norm`): headline ASR rises to **80%** — obfuscation walks through.
- v1-style stack (`aegis_v1_stack`, no KAD / no tripwires): **22%** headline ASR.
- Full `aegis_v2`: **0%** headline ASR. Normalization + KAD + tripwires are what close the gap.

## Operational

- Latency (AEGIS v2, full pipeline): p50 **0.288 ms**, p95 **0.349 ms**, p99 **0.389 ms**.
- Judge-call rate: **25.0%** (judge is budget-capped; most requests never reach it).
- Multi-turn crescendo/split-payload catch rate: **100%** (10/10).

## Charts

![asr_by_transform.png](asr_by_transform.png)
![f1_fpr.png](f1_fpr.png)
