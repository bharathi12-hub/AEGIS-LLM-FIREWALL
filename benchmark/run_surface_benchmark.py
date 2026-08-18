"""Surface benchmark — indirect prompt injection across all seven surfaces.

WHAT THIS MEASURES
------------------
For every surface, two detectors are run over the SAME labeled corpus:

  BASELINE ("v2.0 flattened") — what a normal integration does today: extract
      the artifact to plain text, concatenate it, and hand it to the prompt
      firewall. This is not a straw man; it is how virtually every RAG and
      document pipeline wires a guardrail in, and the v2.0 pipeline is a strong
      direct-injection detector.

  AEGIS v2.1 SURFACE — the channel-aware scanner, which keeps provenance and
      applies the data-channel prior.

Reporting both is the honest way to state the contribution. The baseline catches
the payloads that read like jailbreaks; the delta is the indirect attacks that
carry no jailbreak vocabulary at all — a comment politely asking the assistant
to email a customer list, which is benign-looking text right up until you notice
a human was never meant to see it.

Metrics per surface and overall: detection rate (recall), false-positive rate,
precision, F1, and latency percentiles. FPR is measured on hard negatives —
real business content with trigger words, imperatives, formulas, and security
discussion — because a detector that flags every document would otherwise score
a perfect 100%.

Runs fully offline. Writes benchmark/out/surface_metrics.{json,csv} and
surface_report.md.
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

from benchmark import surface_datasets as ds  # noqa: E402

from app.pipeline.orchestrator import inspect_text  # noqa: E402
from app.surfaces import agent, browser, documents, memory, multimodal, rag, tools  # noqa: E402
from app.taxonomy import Verdict  # noqa: E402

OUT_DIR = os.path.join(_HERE, "out")


def _percentiles(values: list[float], pcts=(50, 95, 99)) -> dict[str, float]:
    if not values:
        return {f"p{p}": 0.0 for p in pcts}
    s = sorted(values)
    return {f"p{p}": round(s[min(len(s) - 1,
                                 int(round((p / 100.0) * (len(s) - 1))))], 3)
            for p in pcts}


def _flagged(result) -> bool:
    """A surface 'detects' when it does not simply ALLOW."""
    return result.verdict != Verdict.ALLOW


def _baseline_flagged(text: str) -> bool:
    """The v2.0 prompt pipeline over flattened artifact text."""
    if not text or not text.strip():
        return False
    return inspect_text(text, session_id=f"bench-{abs(hash(text)) % 10 ** 8}"
                        ).verdict != Verdict.ALLOW


# ---------------------------------------------------------------------------
# Per-surface runners: each returns (label, surface_flagged, baseline_flagged, ms)
# ---------------------------------------------------------------------------

def _run_browser():
    out = []
    for label, cases in ((1, ds.BROWSER_ATTACKS), (0, ds.BROWSER_BENIGN)):
        for name, html in cases:
            t0 = time.perf_counter()
            result = browser.scan(html, source=f"bench://{name}")
            ms = (time.perf_counter() - t0) * 1000
            flat = " ".join(s.text for s in browser.extract(html)[0])
            out.append((name, label, _flagged(result), _baseline_flagged(flat), ms))
    return out


def _run_documents():
    out = []
    for label, cases in ((1, ds.DOCUMENT_ATTACKS), (0, ds.DOCUMENT_BENIGN)):
        for name, artifact, filename in cases:
            t0 = time.perf_counter()
            result = documents.scan(artifact, filename=filename)
            ms = (time.perf_counter() - t0) * 1000
            try:
                segments, _ = documents.extract_segments(
                    artifact if isinstance(artifact, bytes)
                    else artifact.encode("utf-8", "replace"), filename=filename)
                flat = " ".join(s.text for s in segments)
            except Exception:  # noqa: BLE001 — baseline gets nothing on a parse failure
                flat = ""
            out.append((name, label, _flagged(result), _baseline_flagged(flat), ms))
    return out


def _run_rag():
    out = []
    for label, cases in ((1, ds.RAG_ATTACKS), (0, ds.RAG_BENIGN)):
        for name, text in cases:
            chunk = rag.Chunk(text=text, source=f"kb://{name}", trust="internal",
                              chunk_id=name)
            t0 = time.perf_counter()
            result = rag.scan_chunks([chunk], query="what is the refund policy?")
            ms = (time.perf_counter() - t0) * 1000
            out.append((name, label, _flagged(result), _baseline_flagged(text), ms))
    return out


def _run_memory():
    out = []
    for label, cases in ((1, ds.MEMORY_ATTACKS), (0, ds.MEMORY_BENIGN)):
        for name, text in cases:
            record = memory.MemoryRecord(text=text, origin="document",
                                         record_id=name)
            t0 = time.perf_counter()
            result = memory.scan_write(record)
            ms = (time.perf_counter() - t0) * 1000
            # For memory the actionable field is persist_allowed, not verdict.
            out.append((name, label, not result.persist_allowed,
                        _baseline_flagged(text), ms))
    return out


def _run_tools():
    out = []
    policy = tools.ToolPolicy(allowed_roots=["/srv/workspace"],
                              allowed_hosts=["api.example.com"])
    for label, cases in ((1, ds.TOOL_ATTACKS), (0, ds.TOOL_BENIGN)):
        for name, tool, description, arguments, intent in cases:
            call = tools.ToolCall(name=tool, description=description,
                                  arguments=arguments, user_intent=intent)
            t0 = time.perf_counter()
            result = tools.scan_call(call, policy=policy,
                                     registry=tools.ToolRegistry())
            ms = (time.perf_counter() - t0) * 1000
            flat = f"{tool} " + " ".join(str(v) for v in arguments.values())
            out.append((name, label, not result.execute_allowed,
                        _baseline_flagged(flat), ms))
    return out


def _run_agent():
    out = []
    for label, cases in ((1, ds.AGENT_ATTACKS), (0, ds.AGENT_BENIGN)):
        for name, content, sender, recipient, taint in cases:
            message = agent.AgentMessage(content=content, sender=sender,
                                         recipient=recipient, taint=taint)
            t0 = time.perf_counter()
            result = agent.scan_message(message)
            ms = (time.perf_counter() - t0) * 1000
            out.append((name, label, not result.deliver_allowed,
                        _baseline_flagged(content), ms))
    return out


def _run_multimodal():
    out = []
    for label, cases in ((1, ds.MULTIMODAL_ATTACKS), (0, ds.MULTIMODAL_BENIGN)):
        for name, data, filename in cases:
            t0 = time.perf_counter()
            result = multimodal.scan(data, filename=filename)
            ms = (time.perf_counter() - t0) * 1000
            # The baseline for an image is what a captioning pipeline would
            # concatenate: the metadata strings it can read.
            flat = result.sanitized
            out.append((name, label, _flagged(result), _baseline_flagged(flat), ms))
    return out


RUNNERS = {
    "browser": _run_browser,
    "documents": _run_documents,
    "rag": _run_rag,
    "memory": _run_memory,
    "tools": _run_tools,
    "agent": _run_agent,
    "multimodal": _run_multimodal,
}


def _score(rows, index: int) -> dict:
    """Confusion matrix + derived metrics for detector at tuple position ``index``."""
    tp = sum(1 for r in rows if r[1] == 1 and r[index])
    fn = sum(1 for r in rows if r[1] == 1 and not r[index])
    fp = sum(1 for r in rows if r[1] == 0 and r[index])
    tn = sum(1 for r in rows if r[1] == 0 and not r[index])
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "detection_rate": round(recall, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(1 - recall, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def run() -> dict:
    os.makedirs(OUT_DIR, exist_ok=True)
    results: dict = {"surfaces": {}, "corpus": ds.summary()}
    all_rows: list = []

    for surface, runner in RUNNERS.items():
        rows = runner()
        all_rows.extend(rows)
        latencies = [r[4] for r in rows]
        results["surfaces"][surface] = {
            "aegis_v21": _score(rows, 2),
            "baseline_v20_flattened": _score(rows, 3),
            "latency_ms": _percentiles(latencies),
            "cases": len(rows),
            "missed_by_baseline_caught_by_surface": [
                r[0] for r in rows if r[1] == 1 and r[2] and not r[3]
            ],
            "missed_by_both": [r[0] for r in rows if r[1] == 1 and not r[2]],
            "false_positives": [r[0] for r in rows if r[1] == 0 and r[2]],
        }

    results["overall"] = {
        "aegis_v21": _score(all_rows, 2),
        "baseline_v20_flattened": _score(all_rows, 3),
        "latency_ms": _percentiles([r[4] for r in all_rows]),
        "cases": len(all_rows),
    }

    with open(os.path.join(OUT_DIR, "surface_metrics.json"), "w",
              encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)

    with open(os.path.join(OUT_DIR, "surface_metrics.csv"), "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["surface", "detector", "detection_rate", "fpr",
                         "precision", "recall", "f1", "tp", "fn", "fp", "tn"])
        for surface, data in results["surfaces"].items():
            for detector in ("aegis_v21", "baseline_v20_flattened"):
                m = data[detector]
                writer.writerow([surface, detector, m["detection_rate"],
                                 m["false_positive_rate"], m["precision"],
                                 m["recall"], m["f1"], m["tp"], m["fn"],
                                 m["fp"], m["tn"]])

    _write_report(results)
    return results


def _write_report(results: dict) -> None:
    lines = [
        "# AEGIS v2.1 — Surface Benchmark (Indirect Prompt Injection)",
        "",
        "Measures detection of injection payloads that arrive through channels ",
        "other than the user's prompt: web pages, documents, retrieved chunks, ",
        "stored memories, tool arguments, and inter-agent messages.",
        "",
        "**Baseline** is the v2.0 prompt firewall applied to the flattened text of ",
        "the same artifact — i.e. what a normal guardrail integration does today. ",
        "**AEGIS v2.1** is the channel-aware surface scanner. Both run on the same ",
        "labeled corpus, and false-positive rate is measured on hard negatives ",
        "(real business content containing trigger words, imperatives and formulas).",
        "",
        "## Overall",
        "",
        "| Detector | Detection rate | FPR | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|",
    ]
    for key, label in (("aegis_v21", "**AEGIS v2.1 surfaces**"),
                       ("baseline_v20_flattened", "v2.0 prompt firewall (flattened)")):
        m = results["overall"][key]
        lines.append(f"| {label} | {m['detection_rate']:.1%} | "
                     f"{m['false_positive_rate']:.1%} | {m['precision']:.3f} | "
                     f"{m['recall']:.3f} | {m['f1']:.3f} |")

    lat = results["overall"]["latency_ms"]
    lines += [
        "",
        f"Cases: {results['overall']['cases']}. "
        f"Latency p50 {lat['p50']} ms / p95 {lat['p95']} ms / p99 {lat['p99']} ms.",
        "",
        "## Per surface",
        "",
        "| Surface | v2.1 detection | v2.1 FPR | baseline detection | baseline FPR | p95 ms |",
        "|---|---|---|---|---|---|",
    ]
    for surface, data in results["surfaces"].items():
        a, b = data["aegis_v21"], data["baseline_v20_flattened"]
        lines.append(
            f"| {surface} | {a['detection_rate']:.1%} | {a['false_positive_rate']:.1%} "
            f"| {b['detection_rate']:.1%} | {b['false_positive_rate']:.1%} "
            f"| {data['latency_ms']['p95']} |")

    lines += ["", "## The delta: attacks the flattened baseline misses", "",
              "These carry no jailbreak vocabulary. They are caught because the ",
              "surface layer knows the text arrived in a channel a human never sees.", ""]
    for surface, data in results["surfaces"].items():
        missed = data["missed_by_baseline_caught_by_surface"]
        if missed:
            lines.append(f"- **{surface}**: {', '.join(missed)}")

    residual = {s: d["missed_by_both"] for s, d in results["surfaces"].items()
                if d["missed_by_both"]}
    false_pos = {s: d["false_positives"] for s, d in results["surfaces"].items()
                 if d["false_positives"]}
    if residual:
        lines += ["", "## Residual misses (caught by neither)", ""]
        for surface, names in residual.items():
            lines.append(f"- **{surface}**: {', '.join(names)}")
    if false_pos:
        lines += ["", "## False positives on hard negatives", ""]
        for surface, names in false_pos.items():
            lines.append(f"- **{surface}**: {', '.join(names)}")
    if not residual and not false_pos:
        lines += ["", "No residual misses and no false positives on this corpus.", ""]

    lines += [
        "",
        "## Reading this honestly",
        "",
        "This is a curated offline corpus, not a public leaderboard run. It is ",
        "sized to be reproducible with zero network access and it is small, so ",
        "these rates carry wide confidence intervals. It measures whether the ",
        "channel-aware design catches a class the flattened approach structurally ",
        "cannot — not that any particular percentage generalises. Running against ",
        "the full BIPIA / AgentDojo suites requires network access and is the ",
        "documented next step in `docs/PRODUCTION.md`.",
        "",
    ]
    with open(os.path.join(OUT_DIR, "surface_report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    out = run()
    o = out["overall"]
    print("AEGIS v2.1 surfaces: "
          f"detection {o['aegis_v21']['detection_rate']:.1%}, "
          f"FPR {o['aegis_v21']['false_positive_rate']:.1%}")
    print("v2.0 flattened baseline: "
          f"detection {o['baseline_v20_flattened']['detection_rate']:.1%}, "
          f"FPR {o['baseline_v20_flattened']['false_positive_rate']:.1%}")
    print(f"Wrote {OUT_DIR}/surface_report.md")
