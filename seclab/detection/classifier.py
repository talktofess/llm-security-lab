"""A small, dependency-free injection classifier (Multinomial Naive Bayes).

The stretch goal from the scope: a guardrail classifier with *measured*
precision/recall, not vibes. Pure stdlib so it trains and evaluates offline in
CI. It complements the regex `input_filter` — a learned second opinion that
catches phrasings the patterns miss.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

_TOKEN = re.compile(r"[a-z0-9]+")
_DATASET = Path(__file__).resolve().parent.parent.parent / "data" / "injection_dataset.json"


def _tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class NaiveBayes:
    """Multinomial NB with Laplace smoothing. label 1 = injection, 0 = benign."""

    def __init__(self) -> None:
        self.classes: list[int] = []
        self.logprior: dict[int, float] = {}
        self.loglik: dict[int, dict[str, float]] = {}
        self.vocab: set[str] = set()
        self._total: dict[int, int] = {}

    def train(self, texts: list[str], labels: list[int]) -> "NaiveBayes":
        self.classes = sorted(set(labels))
        n_docs = len(texts)
        counts = {c: {} for c in self.classes}
        self._total = {c: 0 for c in self.classes}
        n_class = {c: 0 for c in self.classes}
        for text, label in zip(texts, labels):
            n_class[label] += 1
            for tok in _tokenize(text):
                self.vocab.add(tok)
                counts[label][tok] = counts[label].get(tok, 0) + 1
                self._total[label] += 1
        v = len(self.vocab)
        self.logprior = {c: math.log(n_class[c] / n_docs) for c in self.classes}
        self.loglik = {
            c: {tok: math.log((counts[c].get(tok, 0) + 1) / (self._total[c] + v)) for tok in self.vocab}
            for c in self.classes
        }
        self._v = v
        return self

    def predict(self, text: str) -> int:
        scores = {}
        for c in self.classes:
            s = self.logprior[c]
            for tok in _tokenize(text):
                s += self.loglik[c].get(tok, math.log(1 / (self._total[c] + self._v)))
            scores[c] = s
        return max(scores, key=scores.get)


def load_dataset(path: Path | None = None) -> tuple[list[str], list[int]]:
    raw = json.loads((path or _DATASET).read_text(encoding="utf-8"))
    return [r["text"] for r in raw], [int(r["label"]) for r in raw]


def evaluate(holdout_every: int = 4) -> dict:
    """Deterministic train/test split (every Nth example held out), trained on
    the rest. Returns precision/recall/F1 for the injection class."""
    texts, labels = load_dataset()
    train_x, train_y, test_x, test_y = [], [], [], []
    for i, (t, y) in enumerate(zip(texts, labels)):
        if i % holdout_every == 0:
            test_x.append(t); test_y.append(y)
        else:
            train_x.append(t); train_y.append(y)

    model = NaiveBayes().train(train_x, train_y)
    tp = fp = fn = tn = 0
    for t, y in zip(test_x, test_y):
        pred = model.predict(t)
        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 1:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "n_train": len(train_x), "n_test": len(test_x),
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def trained_on_all() -> NaiveBayes:
    texts, labels = load_dataset()
    return NaiveBayes().train(texts, labels)


if __name__ == "__main__":  # python -m seclab.detection.classifier
    import json as _json

    print(_json.dumps(evaluate(), indent=2))
