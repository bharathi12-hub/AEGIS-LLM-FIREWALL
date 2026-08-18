"""Red-team evasion sweep (Section 7).

Applies every evasion transform to the labeled attacks and reports Attack Success
Rate (fraction that EVADE detection) for a single classifier vs full AEGIS v2,
plus a multi-turn crescendo/split-payload probe. Offline, real numbers.

    python -m redteam.run_redteam
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(__file__)
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, os.path.join(_ROOT, "gateway")):
    if p not in sys.path:
        sys.path.insert(0, p)

from benchmark import datasets  # noqa: E402
from benchmark.baselines import protectai_like, aegis_v2  # noqa: E402
from redteam.transforms import TRANSFORMS, split_payload  # noqa: E402
from app.pipeline.orchestrator import inspect_text  # noqa: E402
from app.taxonomy import Verdict  # noqa: E402


def sweep() -> None:
    attacks = [r for r in datasets.load() if r["label"] == 1]
    print(f"Red-team sweep: {len(attacks)} attacks x {len(TRANSFORMS)} transforms\n")
    header = f"{'transform':20s}{'single-clf ASR':>16s}{'AEGIS v2 ASR':>16s}"
    print(header)
    print("-" * len(header))
    for tname, tfn in TRANSFORMS.items():
        single_evaded = 0
        aegis_evaded = 0
        for i, a in enumerate(attacks):
            variant = tfn(a["text"])
            if not protectai_like(variant):
                single_evaded += 1
            if not aegis_v2(variant, f"rt-{tname}-{i}"):
                aegis_evaded += 1
        n = len(attacks)
        print(f"{tname:20s}{single_evaded / n:>16.2f}{aegis_evaded / n:>16.2f}")

    # Multi-turn crescendo / split payload.
    print("\nMulti-turn split-payload probe:")
    caught = considered = 0
    for i, a in enumerate(attacks[:10]):
        frags = split_payload(a["text"], parts=3)
        if len(frags) < 2:
            continue
        considered += 1
        session = f"rt-cresc-{i}"
        if any(inspect_text(f, session_id=session).verdict == Verdict.BLOCK for f in frags):
            caught += 1
    if considered:
        print(f"  assembled-attack catch rate: {caught}/{considered} "
              f"({caught / considered * 100:.0f}%)")


if __name__ == "__main__":
    sweep()
