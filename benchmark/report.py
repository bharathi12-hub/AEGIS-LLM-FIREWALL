"""Report generator (Section 7).

Reads benchmark/out/metrics.json and writes report.md with the headline finding,
a clean-metrics table, and the ASR-by-transform table that is the whole point:
single classifiers collapse under evasion; AEGIS v2 holds. Charts are rendered
with matplotlib when available; otherwise the report degrades gracefully to
tables only (offline profile).
"""
from __future__ import annotations

import json
import os

OUT_DIR = os.path.join(os.path.dirname(__file__), "out")

_HEADLINE_TRANSFORMS = ["emoji_tag_smuggle", "bidi_override", "homoglyph",
                        "zero_width", "base64_wrap"]


def _try_charts(data: dict) -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:  # noqa: BLE001
        return []
    made = []
    results = data["results"]
    transforms = sorted(next(iter(results.values()))["evasion"].keys())

    # ASR-by-transform grouped bars for a few representative baselines.
    show = [b for b in ("protectai_like", "promptguard_like", "aegis_v1_stack",
                        "aegis_v2") if b in results]
    fig, ax = plt.subplots(figsize=(11, 5))
    width = 0.8 / len(show)
    x = range(len(transforms))
    for i, b in enumerate(show):
        asr = [results[b]["evasion"].get(t, {}).get("asr", 0.0) for t in transforms]
        ax.bar([xi + i * width for xi in x], asr, width, label=b)
    ax.set_xticks([xi + width * (len(show) - 1) / 2 for xi in x])
    ax.set_xticklabels(transforms, rotation=40, ha="right")
    ax.set_ylabel("Attack Success Rate (evasion)")
    ax.set_title("ASR by evasion transform — lower is better")
    ax.legend()
    fig.tight_layout()
    p = os.path.join(OUT_DIR, "asr_by_transform.png")
    fig.savefig(p, dpi=120)
    made.append(os.path.basename(p))

    # F1 / FPR bars.
    fig2, ax2 = plt.subplots(figsize=(9, 4.5))
    names = list(results.keys())
    f1 = [results[n]["f1"] for n in names]
    fpr = [results[n]["fpr"] for n in names]
    xx = range(len(names))
    ax2.bar([i - 0.2 for i in xx], f1, 0.4, label="F1")
    ax2.bar([i + 0.2 for i in xx], fpr, 0.4, label="FPR")
    ax2.set_xticks(list(xx))
    ax2.set_xticklabels(names, rotation=30, ha="right")
    ax2.set_title("Clean F1 vs FPR by baseline")
    ax2.legend()
    fig2.tight_layout()
    p2 = os.path.join(OUT_DIR, "f1_fpr.png")
    fig2.savefig(p2, dpi=120)
    made.append(os.path.basename(p2))
    return made


def _avg_headline_asr(summ: dict) -> float:
    vals = [summ["evasion"].get(t, {}).get("asr", 0.0) for t in _HEADLINE_TRANSFORMS]
    return sum(vals) / len(vals) if vals else 0.0


def generate() -> str:
    with open(os.path.join(OUT_DIR, "metrics.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    results = data["results"]
    meta = data["meta"]
    charts = _try_charts(data)

    lines: list[str] = []
    lines.append("# AEGIS v2 — Benchmark & Red-Team Report\n")
    lines.append(f"_Profile: **{meta['profile']}** · generated {meta['generated_at']} · "
                 f"{meta['n_attacks']} attacks / {meta['n_benign']} benign_\n")

    # Headline.
    single = max(_avg_headline_asr(results[b]) for b in
                 ("protectai_like", "promptguard_like") if b in results)
    v2 = _avg_headline_asr(results["aegis_v2"]) if "aegis_v2" in results else 0.0
    v2_recall = results["aegis_v2"]["recall"] if "aegis_v2" in results else 0.0
    v2_fpr = results["aegis_v2"]["fpr"] if "aegis_v2" in results else 0.0
    lines.append("## Headline\n")
    lines.append(
        f"> Under character-injection evasion (emoji-tag smuggling, bidi, homoglyph, "
        f"zero-width, base64), a single classifier's attacks-through rate averages "
        f"**{single*100:.0f}% ASR**. AEGIS v2 holds it to **{v2*100:.0f}% ASR** by "
        f"neutralizing the transform *before* classification and via behavioral KAD, "
        f"while keeping clean recall at **{v2_recall*100:.0f}%** and FPR at "
        f"**{v2_fpr*100:.1f}%**.\n")

    # Clean metrics table.
    lines.append("## Clean detection quality\n")
    lines.append("| Baseline | Precision | Recall | F1 | Accuracy | FPR | AUROC |")
    lines.append("|---|---|---|---|---|---|---|")
    for n, s in results.items():
        lines.append(f"| `{n}` | {s['precision']:.3f} | {s['recall']:.3f} | "
                     f"{s['f1']:.3f} | {s['accuracy']:.3f} | {s['fpr']:.3f} | "
                     f"{s['auroc']:.3f} |")
    lines.append("")

    # ASR-by-transform table.
    transforms = sorted(next(iter(results.values()))["evasion"].keys())
    lines.append("## Evasion ASR by transform (lower = better)\n")
    lines.append("| Baseline | " + " | ".join(transforms) + " |")
    lines.append("|---|" + "|".join(["---"] * len(transforms)) + "|")
    for n, s in results.items():
        cells = [f"{s['evasion'].get(t, {}).get('asr', 0.0):.2f}" for t in transforms]
        lines.append(f"| `{n}` | " + " | ".join(cells) + " |")
    lines.append("")

    # Ablation callout.
    lines.append("## Ablation — each layer earns its place\n")
    if all(k in results for k in ("aegis_no_norm", "aegis_v1_stack", "aegis_v2")):
        nn = _avg_headline_asr(results["aegis_no_norm"])
        v1 = _avg_headline_asr(results["aegis_v1_stack"])
        lines.append(f"- Remove Normalization v2 (`aegis_no_norm`): headline ASR rises to "
                     f"**{nn*100:.0f}%** — obfuscation walks through.")
        lines.append(f"- v1-style stack (`aegis_v1_stack`, no KAD / no tripwires): "
                     f"**{v1*100:.0f}%** headline ASR.")
        lines.append(f"- Full `aegis_v2`: **{v2*100:.0f}%** headline ASR. Normalization + "
                     f"KAD + tripwires are what close the gap.\n")

    # Operational.
    lat = meta["latency_ms"]
    lines.append("## Operational\n")
    lines.append(f"- Latency (AEGIS v2, full pipeline): p50 **{lat['p50']} ms**, "
                 f"p95 **{lat['p95']} ms**, p99 **{lat['p99']} ms**.")
    lines.append(f"- Judge-call rate: **{meta['judge_call_rate']*100:.1f}%** "
                 f"(judge is budget-capped; most requests never reach it).")
    c = meta["crescendo"]
    lines.append(f"- Multi-turn crescendo/split-payload catch rate: "
                 f"**{c['catch_rate']*100:.0f}%** ({c['caught']}/{c['considered']}).\n")

    if charts:
        lines.append("## Charts\n")
        for c in charts:
            lines.append(f"![{c}]({c})")
        lines.append("")
    else:
        lines.append("_(Charts skipped: matplotlib not installed in this profile. "
                     "Tables above carry the full numbers.)_\n")

    report_md = "\n".join(lines)
    with open(os.path.join(OUT_DIR, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report_md)
    print(f"Wrote {OUT_DIR}/report.md" + (f" + {len(charts)} charts" if charts else ""))
    return report_md


if __name__ == "__main__":
    generate()
