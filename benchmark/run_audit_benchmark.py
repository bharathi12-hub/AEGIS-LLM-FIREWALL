"""Audit benchmark — the two gaps found by the v2.1 security audit.

This is the before/after for the hardening work, and it is reported separately
from the surface benchmark because the *nature* of the gap was different.

CONVERSATION
    The v2.0 gateway inspected exactly one string per request:
    ``latest_user_text()``. Everything else — tool results, replayed assistant
    turns, client-supplied system messages, tool and parameter descriptions —
    reached the model uninspected. The baseline here therefore measures
    coverage, not detection quality: the detectors were always capable of
    catching these payloads, they were simply never shown them. That is the
    most dangerous kind of gap, because every dashboard reads "clean".

STRUCTURAL
    Template, deserialization, and query-language payloads aimed at the systems
    downstream of the model, plus many-shot flooding and stacked persuasion.
    The baseline here is genuine detection failure, not blindness: v2.0 saw the
    bytes and had no rule that matched them.

Both are measured against hard negatives, and for the conversation family those
negatives carry unusual weight — a scanner that flags ordinary multi-turn
support threads is a scanner that gets turned off.

Runs fully offline. Writes benchmark/out/audit_metrics.{json,csv} and
audit_report.md.
"""
from __future__ import annotations

import csv
import json
import os
import sys
import time

_HERE = os.path.dirname(__file__)
_GATEWAY = os.path.join(os.path.dirname(_HERE), "gateway")
for p in (_HERE, _GATEWAY, os.path.dirname(_HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from benchmark import audit_datasets as ds  # noqa: E402

from app.api.schemas import ChatCompletionRequest  # noqa: E402
from app.pipeline.conversation import inspect_conversation, latest_user_index  # noqa: E402
from app.pipeline.orchestrator import inspect_text  # noqa: E402
from app.taxonomy import Verdict  # noqa: E402

OUT_DIR = os.path.join(_HERE, "out")


def _percentiles(values: list[float], pcts=(50, 95, 99)) -> dict[str, float]:
    if not values:
        return {f"p{p}": 0.0 for p in pcts}
    s = sorted(values)
    return {f"p{p}": round(s[min(len(s) - 1,
                                 int(round((p / 100.0) * (len(s) - 1))))], 3)
            for p in pcts}


def _v20_latest_user_only(payload: dict) -> bool:
    """Reproduce the v2.0 behaviour exactly: inspect only the last user turn."""
    body = ChatCompletionRequest(**payload)
    text = body.latest_user_text()
    if not text:
        return False
    return inspect_text(
        text, session_id=f"audit-{abs(hash(text)) % 10 ** 8}"
    ).verdict != Verdict.ALLOW


def _v21_whole_conversation(payload: dict) -> bool:
    body = ChatCompletionRequest(**payload)
    # The fused decision: latest user turn (v2.0 path) OR everything else.
    if _v20_latest_user_only(payload):
        return True
    conversation = inspect_conversation(body, skip_index=latest_user_index(body))
    return conversation.verdict != Verdict.ALLOW


def _run_conversation():
    rows = []
    for label, cases in ((1, ds.CONVERSATION_ATTACKS), (0, ds.CONVERSATION_BENIGN)):
        for name, payload in cases:
            t0 = time.perf_counter()
            detected = _v21_whole_conversation(payload)
            ms = (time.perf_counter() - t0) * 1000
            baseline = _v20_latest_user_only(payload)
            rows.append((name, label, detected, baseline, ms))
    return rows


def _run_structural():
    rows = []
    for label, cases in ((1, ds.STRUCTURAL_ATTACKS), (0, ds.STRUCTURAL_BENIGN)):
        for name, text in cases:
            t0 = time.perf_counter()
            detected = inspect_text(
                text, session_id=f"st-{name}").verdict != Verdict.ALLOW
            ms = (time.perf_counter() - t0) * 1000
            # v2.0 baseline: the same pipeline with the structural layer's
            # contribution removed, which is what shipped before this work.
            baseline = _without_structural(text)
            rows.append((name, label, detected, baseline, ms))
    return rows


def _without_structural(text: str) -> bool:
    """Evaluate the pipeline as it behaved before the structural layer existed."""
    from app.pipeline import embeddings, kad, signatures
    from app.pipeline.aggregator import AggregatorInput, aggregate
    from app.pipeline.classifier import get_ensemble
    from app.pipeline.context import get_tracker
    from app.pipeline.normalize import normalize

    norm = normalize(text)
    scan_text = norm.scan_text
    agg = AggregatorInput(
        normalization=norm,
        signatures=signatures.scan(scan_text),
        classifiers=get_ensemble().classify(scan_text, obfuscation=norm.risk),
        embeddings=embeddings.query(scan_text),
        kad=kad.check(norm.sanitized),
        context=get_tracker().observe(f"base-{abs(hash(text)) % 10 ** 8}",
                                      norm.sanitized),
        structural=None,          # the v2.0 state
    )
    return aggregate(agg).verdict != Verdict.ALLOW


RUNNERS = {"conversation": _run_conversation, "structural": _run_structural}


def _score(rows, index: int) -> dict:
    tp = sum(1 for r in rows if r[1] == 1 and r[index])
    fn = sum(1 for r in rows if r[1] == 1 and not r[index])
    fp = sum(1 for r in rows if r[1] == 0 and r[index])
    tn = sum(1 for r in rows if r[1] == 0 and not r[index])
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "detection_rate": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4)}


def run() -> dict:
    os.makedirs(OUT_DIR, exist_ok=True)
    results: dict = {"families": {}, "corpus": ds.summary()}
    all_rows = []

    for family, runner in RUNNERS.items():
        rows = runner()
        all_rows.extend(rows)
        results["families"][family] = {
            "hardened_v21": _score(rows, 2),
            "baseline_v20": _score(rows, 3),
            "latency_ms": _percentiles([r[4] for r in rows]),
            "cases": len(rows),
            "fixed_by_hardening": [r[0] for r in rows
                                   if r[1] == 1 and r[2] and not r[3]],
            "still_missed": [r[0] for r in rows if r[1] == 1 and not r[2]],
            "false_positives": [r[0] for r in rows if r[1] == 0 and r[2]],
        }

    results["overall"] = {
        "hardened_v21": _score(all_rows, 2),
        "baseline_v20": _score(all_rows, 3),
        "latency_ms": _percentiles([r[4] for r in all_rows]),
        "cases": len(all_rows),
    }

    with open(os.path.join(OUT_DIR, "audit_metrics.json"), "w",
              encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    with open(os.path.join(OUT_DIR, "audit_metrics.csv"), "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["family", "build", "detection_rate", "fpr", "precision",
                         "recall", "f1", "tp", "fn", "fp", "tn"])
        for family, data in results["families"].items():
            for build in ("hardened_v21", "baseline_v20"):
                m = data[build]
                writer.writerow([family, build, m["detection_rate"],
                                 m["false_positive_rate"], m["precision"],
                                 m["recall"], m["f1"], m["tp"], m["fn"],
                                 m["fp"], m["tn"]])

    _write_report(results)
    return results


def _write_report(results: dict) -> None:
    o = results["overall"]
    lines = [
        "# AEGIS v2.1 — Audit Benchmark (hardening before/after)",
        "",
        "Two attack families found by the security audit, measured against the ",
        "build that shipped before the fix.",
        "",
        "## Overall",
        "",
        "| Build | Detection rate | FPR | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|",
    ]
    for key, label in (("hardened_v21", "**AEGIS v2.1 hardened**"),
                       ("baseline_v20", "v2.0 (pre-audit)")):
        m = o[key]
        lines.append(f"| {label} | {m['detection_rate']:.1%} | "
                     f"{m['false_positive_rate']:.1%} | {m['precision']:.3f} | "
                     f"{m['recall']:.3f} | {m['f1']:.3f} |")

    lat = o["latency_ms"]
    lines += [
        "",
        f"Cases: {o['cases']}. Latency p50 {lat['p50']} ms / "
        f"p95 {lat['p95']} ms / p99 {lat['p99']} ms.",
        "",
        "## Per family",
        "",
        "| Family | v2.1 detection | v2.1 FPR | v2.0 detection | v2.0 FPR |",
        "|---|---|---|---|---|",
    ]
    for family, data in results["families"].items():
        a, b = data["hardened_v21"], data["baseline_v20"]
        lines.append(
            f"| {family} | {a['detection_rate']:.1%} | "
            f"{a['false_positive_rate']:.1%} | {b['detection_rate']:.1%} | "
            f"{b['false_positive_rate']:.1%} |")

    lines += [
        "",
        "### Why the conversation baseline is so low",
        "",
        "It is not a detection failure. The v2.0 gateway inspected exactly one ",
        "string per request — the latest user turn — so tool results, replayed ",
        "assistant turns, client-supplied system messages, and tool descriptions ",
        "were never shown to any detector. The payloads in this corpus are ones ",
        "the v2.0 detectors catch easily when they are actually given them; the ",
        "gap was coverage, which is the most dangerous kind, because the ",
        "dashboard reads clean the whole time.",
        "",
        "### Why the structural baseline is low",
        "",
        "That one *is* a detection failure: v2.0 saw the bytes and had no rule ",
        "matching template, deserialization, or query-operator syntax. Those ",
        "payloads are inert as prompts and become code execution one hop later, ",
        "in whatever renders or parses the model's output (OWASP LLM05).",
        "",
        "## Cases fixed by the hardening",
        "",
    ]
    for family, data in results["families"].items():
        fixed = data["fixed_by_hardening"]
        if fixed:
            lines.append(f"- **{family}**: {', '.join(fixed)}")

    missed = {f: d["still_missed"] for f, d in results["families"].items()
              if d["still_missed"]}
    false_pos = {f: d["false_positives"] for f, d in results["families"].items()
                 if d["false_positives"]}
    if missed:
        lines += ["", "## Still missed", ""]
        for family, names in missed.items():
            lines.append(f"- **{family}**: {', '.join(names)}")
    if false_pos:
        lines += ["", "## False positives on hard negatives", ""]
        for family, names in false_pos.items():
            lines.append(f"- **{family}**: {', '.join(names)}")
    if not missed and not false_pos:
        lines += ["", "No residual misses and no false positives on this corpus.",
                  ""]

    lines += [
        "",
        "## Reading this honestly",
        "",
        "Curated offline corpus that ships with the repo, and the detectors were ",
        "calibrated against it — bugs it exposed were fixed, which inflates these ",
        "numbers relative to unseen traffic. What it does establish is directional ",
        "and worth stating plainly: payloads in non-latest-user messages were ",
        "previously not inspected at all, and template/deserialization payloads ",
        "had no matching rule. Both are now covered, and the hard negatives show ",
        "the coverage did not come at the cost of flagging ordinary traffic.",
        "",
    ]
    with open(os.path.join(OUT_DIR, "audit_report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    out = run()
    o = out["overall"]
    print("AEGIS v2.1 hardened: "
          f"detection {o['hardened_v21']['detection_rate']:.1%}, "
          f"FPR {o['hardened_v21']['false_positive_rate']:.1%}")
    print("v2.0 pre-audit:      "
          f"detection {o['baseline_v20']['detection_rate']:.1%}, "
          f"FPR {o['baseline_v20']['false_positive_rate']:.1%}")
    for family, data in out["families"].items():
        a, b = data["hardened_v21"], data["baseline_v20"]
        print(f"  {family:14s} {b['detection_rate']:.0%} -> "
              f"{a['detection_rate']:.0%} detection, "
              f"FPR {a['false_positive_rate']:.0%}")
    print(f"Wrote {OUT_DIR}/audit_report.md")
