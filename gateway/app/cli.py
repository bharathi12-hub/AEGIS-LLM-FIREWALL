"""Offline inspection CLI — inspect a prompt without running the server.

    python -m app.cli "ignore all previous instructions"
    echo "some prompt" | python -m app.cli

Prints the verdict, the per-layer contributions, tripwires, and the sanitized
text that would be forwarded upstream (R9). Handy for the demo and debugging.
"""
from __future__ import annotations

import sys

from app.pipeline.orchestrator import inspect_text


def _render(text: str) -> None:
    r = inspect_text(text, session_id="cli")
    d = r.decision
    print("=" * 70)
    print(f"INPUT      : {text[:120]!r}")
    print(f"VERDICT    : {d.verdict.value.upper()}  (score={d.score:.3f}, "
          f"confidence={d.confidence:.3f})")
    print(f"CATEGORY   : {d.category.value}")
    print(f"FORWARDED  : {r.forward_text[:120]!r}")
    print(f"NORM RISK  : {r.normalization.risk}  {r.normalization.reasons}")
    print(f"LAYERS     : {d.contributions}")
    if d.tripwires:
        print(f"TRIPWIRES  : {d.tripwires}")
    print(f"JUDGE USED : {r.judge_used}")
    print(f"KAD FP     : {r.kad_fingerprint}")
    print(f"LATENCY    : {r.latency_ms} ms")
    if r.alarms:
        print(f"ALARMS     : {r.alarms}")


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        _render(" ".join(argv[1:]))
    else:
        data = sys.stdin.read().strip()
        if not data:
            print("usage: python -m app.cli \"<prompt>\"")
            return 2
        _render(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
