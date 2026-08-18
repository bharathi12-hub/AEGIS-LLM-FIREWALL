"""Benchmark runner (Section 7).

Measures, for every baseline:
  * clean detection quality (precision/recall/F1/accuracy/FPR/AUROC) on plain
    attacks + benign (incl. hard trigger-word negatives), and
  * EVASION ASR per transform (the differentiator): how many attacks slip through
    once obfuscated.

Also measures, for the full AEGIS v2 pipeline: p50/p95/p99 latency, judge-call
rate, and a multi-turn crescendo/split-payload catch check.

Runs fully offline (heuristic detector profile). Writes machine-readable results
to benchmark/out/ and hands off to report.py for the human-readable report.
"""
from __future__ import annotations

import json
import os
import sys
import time

_HERE = os.path.dirname(__file__)
_GATEWAY = os.path.join(os.path.dirname(_HERE), "gateway")
for p in (_HERE, _GATEWAY, os.path.dirname(_HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from benchmark import datasets  # noqa: E402
from benchmark.baselines import BASELINES  # noqa: E402
from benchmark.metrics import Report  # noqa: E402
from redteam.transforms import TRANSFORMS, split_payload  # noqa: E402

from app.pipeline.orchestrator import inspect_text  # noqa: E402
from app.taxonomy import Verdict  # noqa: E402

OUT_DIR = os.path.join(_HERE, "out")


def _percentiles(values: list[float], pcts=(50, 95, 99)) -> dict[str, float]:
    if not values:
        return {f"p{p}": 0.0 for p in pcts}
    s = sorted(values)
    out = {}
    for p in pcts:
        idx = min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1))))
        out[f"p{p}"] = round(s[idx], 3)
    return out


def run() -> dict:
    rows = datasets.load()
    attacks = [r for r in rows if r["label"] == 1]
    benign = [r for r in rows if r["label"] == 0]
    print(f"Loaded {len(attacks)} attacks + {len(benign)} benign")

    results: dict[str, dict] = {}
    for name, predict in BASELINES.items():
        rep = Report()
        # --- clean detection quality ---
        for i, r in enumerate(rows):
            blocked = predict(r["text"], f"clean-{name}-{i}")
            rep.record(r["label"], blocked)
        # --- evasion ASR per transform (attacks only) ---
        for tname, tfn in TRANSFORMS.items():
            for i, a in enumerate(attacks):
                variant = tfn(a["text"])
                detected = predict(variant, f"ev-{name}-{tname}-{i}")
                rep.record_evasion(tname, detected)
        results[name] = rep.summary()
        clean = results[name]
        print(f"  {name:16s} F1={clean['f1']:.3f} FPR={clean['fpr']:.3f} "
              f"recall={clean['recall']:.3f} AUROC={clean['auroc']:.3f}")

    # --- AEGIS v2 latency + judge rate ---
    latencies, judge_calls = [], 0
    for i, r in enumerate(rows):
        res = inspect_text(r["text"], session_id=f"lat-{i}")
        latencies.append(res.latency_ms)
        judge_calls += 1 if res.judge_used else 0
    latency = _percentiles(latencies)
    judge_rate = round(judge_calls / len(rows), 4) if rows else 0.0

    # --- multi-turn crescendo / split-payload catch ---
    crescendo = _crescendo_check(attacks)

    meta = {
        "n_attacks": len(attacks),
        "n_benign": len(benign),
        "latency_ms": latency,
        "judge_call_rate": judge_rate,
        "crescendo": crescendo,
        "profile": "offline-heuristic",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    out = {"results": results, "meta": meta}
    _write(out)
    return out


def _crescendo_check(attacks: list[dict], n: int = 10) -> dict:
    """Feed split attack fragments across turns; count assembled-payload catches."""
    caught = 0
    considered = 0
    for i, a in enumerate(attacks[:n]):
        frags = split_payload(a["text"], parts=3)
        if len(frags) < 2:
            continue
        considered += 1
        session = f"cresc-{i}"
        blocked_any = False
        for frag in frags:
            res = inspect_text(frag, session_id=session)
            if res.verdict == Verdict.BLOCK:
                blocked_any = True
        if blocked_any:
            caught += 1
    return {"considered": considered, "caught": caught,
            "catch_rate": round(caught / considered, 4) if considered else 0.0}


def _write(out: dict) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    # Flat CSV of clean metrics + per-transform ASR.
    transforms = list(TRANSFORMS.keys())
    header = ["baseline", "precision", "recall", "f1", "accuracy", "fpr", "auroc"]
    header += [f"asr_{t}" for t in transforms]
    lines = [",".join(header)]
    for name, summ in out["results"].items():
        row = [name] + [f"{summ[k]:.4f}" for k in ("precision", "recall", "f1",
                                                    "accuracy", "fpr", "auroc")]
        row += [f"{summ['evasion'].get(t, {}).get('asr', 0.0):.4f}" for t in transforms]
        lines.append(",".join(row))
    with open(os.path.join(OUT_DIR, "metrics.csv"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {OUT_DIR}/metrics.json and metrics.csv")


if __name__ == "__main__":
    run()
    try:
        from benchmark import report
        report.generate()
    except Exception as exc:  # noqa: BLE001
        print(f"(report generation skipped: {exc})")
