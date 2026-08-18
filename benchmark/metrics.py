"""Metrics (Section 7): precision/recall/F1/accuracy/FPR/AUROC + evasion ASR.

Pure standard library — no scikit-learn required (it is used automatically for
AUROC if importable, else a stdlib rank-based AUROC is computed).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, y_true: int, y_pred: int) -> None:
        if y_true == 1 and y_pred == 1:
            self.tp += 1
        elif y_true == 0 and y_pred == 1:
            self.fp += 1
        elif y_true == 0 and y_pred == 0:
            self.tn += 1
        else:
            self.fn += 1

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        d = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4), "recall": round(self.recall, 4),
            "f1": round(self.f1, 4), "accuracy": round(self.accuracy, 4),
            "fpr": round(self.fpr, 4),
        }


def auroc(scores: list[float], labels: list[int]) -> float:
    """Rank-based AUROC (Mann-Whitney U). Works on binary predictions too."""
    pos = [s for s, y in zip(scores, labels) if y == 1]
    neg = [s for s, y in zip(scores, labels) if y == 0]
    if not pos or not neg:
        return 0.0
    # Rank all scores; average ranks for ties.
    paired = sorted(zip(scores, range(len(scores))), key=lambda x: x[0])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(paired):
        j = i
        while j + 1 < len(paired) and paired[j + 1][0] == paired[i][0]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[paired[k][1]] = avg_rank
        i = j + 1
    sum_pos = sum(r for r, y in zip(ranks, labels) if y == 1)
    n_pos, n_neg = len(pos), len(neg)
    return (sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


@dataclass
class EvasionRow:
    transform: str
    total: int = 0
    detected: int = 0

    @property
    def asr(self) -> float:
        """Attack Success Rate = fraction of attacks that EVADE detection."""
        return (self.total - self.detected) / self.total if self.total else 0.0

    @property
    def recall(self) -> float:
        return self.detected / self.total if self.total else 0.0


@dataclass
class Report:
    confusion: Confusion = field(default_factory=Confusion)
    evasion: dict[str, EvasionRow] = field(default_factory=dict)
    scores: list[float] = field(default_factory=list)
    labels: list[int] = field(default_factory=list)

    def record(self, y_true: int, blocked: bool) -> None:
        self.confusion.add(y_true, 1 if blocked else 0)
        self.scores.append(1.0 if blocked else 0.0)
        self.labels.append(y_true)

    def record_evasion(self, transform: str, detected: bool) -> None:
        row = self.evasion.setdefault(transform, EvasionRow(transform))
        row.total += 1
        row.detected += 1 if detected else 0

    def summary(self) -> dict:
        return {
            **self.confusion.as_dict(),
            "auroc": round(auroc(self.scores, self.labels), 4),
            "evasion": {
                t: {"asr": round(r.asr, 4), "recall": round(r.recall, 4),
                    "n": r.total}
                for t, r in sorted(self.evasion.items())
            },
        }
