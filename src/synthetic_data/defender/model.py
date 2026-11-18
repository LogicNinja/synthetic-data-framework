"""Leakage-aware event classifier and failure analysis.

The optional classifier uses TF-IDF and logistic regression. Ground-truth
labels, event IDs, host/run/scenario IDs, timestamps, and detection results are
never used as features.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
from pathlib import PurePath
import random
import re
from typing import Any, Iterable, Sequence


class _NativeTfidfLogisticRegression:
    """Small sparse TF-IDF logistic model used when scikit-learn is absent."""

    _TOKEN_RE = re.compile(r"[a-z0-9_.:-]{2,}")

    def __init__(self, *, epochs: int = 80, learning_rate: float = 0.2, alpha: float = 0.001) -> None:
        self.epochs = epochs
        self.learning_rate = learning_rate
        self.alpha = alpha
        self.classes_ = ["benign", "malicious"]
        self.vocabulary: set[str] = set()
        self.idf: dict[str, float] = {}
        self.weights: dict[str, float] = {}
        self.bias = 0.0

    @classmethod
    def _counts(cls, text: str) -> Counter[str]:
        tokens = cls._TOKEN_RE.findall(text.casefold())
        counts = Counter(tokens)
        counts.update(f"{left}__{right}" for left, right in zip(tokens, tokens[1:]))
        return counts

    def _vectorize(self, text: str) -> dict[str, float]:
        counts = self._counts(text)
        weighted = {
            token: (1.0 + math.log(count)) * self.idf[token]
            for token, count in counts.items()
            if token in self.vocabulary and count > 0
        }
        norm = math.sqrt(sum(value * value for value in weighted.values()))
        if norm:
            return {token: value / norm for token, value in weighted.items()}
        return {}

    @staticmethod
    def _sigmoid(value: float) -> float:
        if value >= 0:
            return 1.0 / (1.0 + math.exp(-min(value, 40.0)))
        exponential = math.exp(max(value, -40.0))
        return exponential / (1.0 + exponential)

    def fit(self, texts: Sequence[str], labels: Sequence[str]) -> "_NativeTfidfLogisticRegression":
        document_counts = [self._counts(text) for text in texts]
        document_frequency: Counter[str] = Counter()
        for counts in document_counts:
            document_frequency.update(counts.keys())
        self.vocabulary = set(document_frequency)
        self.idf = {
            token: math.log((1 + len(texts)) / (1 + frequency)) + 1.0
            for token, frequency in document_frequency.items()
        }
        vectors = [self._vectorize(text) for text in texts]
        targets = [1.0 if label == "malicious" else 0.0 for label in labels]
        class_counts = Counter(labels)
        class_weights = {
            label: len(labels) / (2 * count)
            for label, count in class_counts.items()
        }
        self.weights = {token: 0.0 for token in self.vocabulary}
        self.bias = 0.0
        rng = random.Random(17)
        indices = list(range(len(vectors)))
        for epoch in range(self.epochs):
            rng.shuffle(indices)
            rate = self.learning_rate / (1.0 + epoch * 0.015)
            for index in indices:
                vector = vectors[index]
                probability = self._sigmoid(
                    self.bias + sum(self.weights[token] * value for token, value in vector.items())
                )
                error = (probability - targets[index]) * class_weights[labels[index]]
                for token, value in vector.items():
                    self.weights[token] -= rate * (
                        error * value + self.alpha * self.weights[token]
                    )
                self.bias -= rate * error
        return self

    def predict_proba(self, texts: Sequence[str]) -> list[list[float]]:
        probabilities = []
        for text in texts:
            vector = self._vectorize(text)
            probability = self._sigmoid(
                self.bias + sum(self.weights[token] * value for token, value in vector.items())
            )
            probabilities.append([1.0 - probability, probability])
        return probabilities


def _as_dict(event: Any) -> dict[str, Any]:
    if isinstance(event, dict):
        return event
    to_dict = getattr(event, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    raise TypeError("Events must be mappings or expose to_dict().")


def event_label_from_ground_truth(event: Any) -> str:
    """Derive event-level verdict from action-level technique labels."""
    data = _as_dict(event)
    labels = data.get("ground_truth_labels") or []
    return "malicious" if labels else "benign"


def event_feature_text(event: Any) -> str:
    """Build behavioral text while excluding labels and identity leakage."""
    data = _as_dict(event)
    process = data.get("process") or {}
    source = data.get("source") or {}
    fields = [
        ("event_source", data.get("event_source")),
        ("event_type", data.get("event_type")),
        ("channel", source.get("channel")),
        ("event_code", source.get("event_code")),
        ("image", process.get("image")),
        ("original_file_name", process.get("original_file_name")),
        ("command_line", process.get("command_line")),
        ("parent_image", process.get("parent_image")),
        ("parent_command_line", process.get("parent_command_line")),
    ]
    return " ".join(
        f"{name} {value}" for name, value in fields if value not in (None, "")
    )


def _safe_failure_summary(event: Any) -> dict[str, str]:
    data = _as_dict(event)
    process = data.get("process") or {}
    source = data.get("source") or {}
    return {
        "event_type": str(data.get("event_type", "")),
        "event_source": str(data.get("event_source", "")),
        "image_name": PurePath(str(process.get("image", ""))).name,
        "original_file_name": str(process.get("original_file_name", "")),
        "parent_image_name": PurePath(str(process.get("parent_image", ""))).name,
        "channel": str(source.get("channel", "")),
        "event_code": str(source.get("event_code", "")),
        "ground_truth_techniques": ",".join(data.get("ground_truth_labels") or []),
    }


@dataclass(frozen=True)
class DefenderPrediction:
    event_id: str
    predicted_label: str
    actual_label: str
    malicious_probability: float
    feature_summary: dict[str, str]


class DefenderModel:
    """Train and evaluate a binary event-level telemetry classifier."""

    def __init__(self, *, threshold: float = 0.5, estimator: Any | None = None) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1.")
        self.threshold = threshold
        self.estimator = estimator
        self.backend = "injected" if estimator is not None else "uninitialized"
        self.training_event_ids: set[str] = set()
        self.training_scenario_ids: set[str] = set()
        self._trained = False

    def fit(self, events: Sequence[Any], labels: Sequence[str] | None = None) -> "DefenderModel":
        if not events:
            raise ValueError("At least one training event is required.")
        if labels is None:
            labels = [event_label_from_ground_truth(event) for event in events]
        if len(events) != len(labels):
            raise ValueError("events and labels must have the same length.")
        if not set(labels).issubset({"malicious", "benign"}):
            raise ValueError("labels must contain only 'malicious' or 'benign'.")
        if set(labels) != {"malicious", "benign"}:
            raise ValueError("Training data must contain both benign and malicious events.")

        texts = [event_feature_text(event) for event in events]
        if self.estimator is None:
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer
                from sklearn.linear_model import LogisticRegression
                from sklearn.pipeline import make_pipeline
            except ImportError:
                self.estimator = _NativeTfidfLogisticRegression()
                self.backend = "native-tfidf-logistic-regression"
            else:
                self.estimator = make_pipeline(
                    TfidfVectorizer(
                        lowercase=True,
                        ngram_range=(1, 2),
                        max_features=30000,
                        sublinear_tf=True,
                    ),
                    LogisticRegression(
                        class_weight="balanced",
                        max_iter=1000,
                        random_state=17,
                    ),
                )
                self.backend = "scikit-learn-tfidf-logistic-regression"
        self.estimator.fit(
            texts,
            list(labels),
        )
        self.training_event_ids = {
            str(_as_dict(event).get("event_id", ""))
            for event in events
            if _as_dict(event).get("event_id") is not None
        }
        self.training_scenario_ids = {
            str(provenance["scenario_id"])
            for event in events
            if (provenance := (_as_dict(event).get("provenance") or {})).get("scenario_id")
        }
        self._trained = True
        return self

    def predict(self, events: Sequence[Any]) -> list[DefenderPrediction]:
        if not self._trained or self.estimator is None:
            raise RuntimeError("DefenderModel must be fitted before prediction.")
        features = [event_feature_text(event) for event in events]
        classes = list(self.estimator.classes_)
        if "malicious" not in classes or "benign" not in classes:
            raise RuntimeError("Fitted estimator must include both binary classes.")
        malicious_column = classes.index("malicious")
        probabilities = self.estimator.predict_proba(features)
        predictions: list[DefenderPrediction] = []
        for index, event in enumerate(events):
            data = _as_dict(event)
            probability = float(probabilities[index][malicious_column])
            predictions.append(
                DefenderPrediction(
                    event_id=str(data.get("event_id", f"row-{index}")),
                    predicted_label=(
                        "malicious" if probability >= self.threshold else "benign"
                    ),
                    actual_label=event_label_from_ground_truth(event),
                    malicious_probability=probability,
                    feature_summary=_safe_failure_summary(event),
                )
            )
        return predictions

    def evaluate(
        self,
        events: Sequence[Any],
        labels: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        if not events:
            raise ValueError("At least one held-out event is required.")
        event_ids = {
            str(_as_dict(event).get("event_id"))
            for event in events
            if _as_dict(event).get("event_id") is not None
        }
        overlap = event_ids & self.training_event_ids
        if overlap:
            raise ValueError(
                "Evaluation events overlap training IDs; use scenario- or "
                "environment-separated held-out data."
            )
        scenario_ids = {
            str(provenance["scenario_id"])
            for event in events
            if (provenance := (_as_dict(event).get("provenance") or {})).get("scenario_id")
        }
        scenario_overlap = scenario_ids & self.training_scenario_ids
        if scenario_overlap:
            raise ValueError(
                "Evaluation scenarios overlap training scenarios; split by "
                "scenario/template before evaluation."
            )
        actual = list(labels) if labels is not None else [
            event_label_from_ground_truth(event) for event in events
        ]
        if len(actual) != len(events):
            raise ValueError("events and labels must have the same length.")
        if not set(actual).issubset({"malicious", "benign"}):
            raise ValueError("labels must contain only 'malicious' or 'benign'.")

        predictions = self.predict(events)
        tp = sum(y == "malicious" and p.predicted_label == "malicious" for y, p in zip(actual, predictions))
        tn = sum(y == "benign" and p.predicted_label == "benign" for y, p in zip(actual, predictions))
        fp = sum(y == "benign" and p.predicted_label == "malicious" for y, p in zip(actual, predictions))
        fn = sum(y == "malicious" and p.predicted_label == "benign" for y, p in zip(actual, predictions))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        benign_precision = tn / (tn + fn) if tn + fn else 0.0
        benign_recall = tn / (tn + fp) if tn + fp else 0.0
        benign_f1 = (
            2 * benign_precision * benign_recall / (benign_precision + benign_recall)
            if benign_precision + benign_recall else 0.0
        )
        accuracy = (tp + tn) / len(events)
        false_negatives = [
            {
                "event_id": p.event_id,
                "failure_type": "false_negative",
                "actual_label": "malicious",
                "predicted_label": "benign",
                "malicious_probability": p.malicious_probability,
                "feature_summary": p.feature_summary,
            }
            for y, p in zip(actual, predictions)
            if y == "malicious" and p.predicted_label == "benign"
        ]
        false_positives = [
            {
                "event_id": p.event_id,
                "failure_type": "false_positive",
                "actual_label": "benign",
                "predicted_label": "malicious",
                "malicious_probability": p.malicious_probability,
                "feature_summary": p.feature_summary,
            }
            for y, p in zip(actual, predictions)
            if y == "benign" and p.predicted_label == "malicious"
        ]
        return {
            "model_backend": self.backend,
            "sample_count": len(events),
            "accuracy": accuracy,
            "precision_malicious": precision,
            "recall_malicious": recall,
            "f1_malicious": f1,
            "macro_f1": (f1 + benign_f1) / 2,
            "confusion_matrix": {
                "true_positive": tp,
                "false_positive": fp,
                "true_negative": tn,
                "false_negative": fn,
            },
            "false_negatives": false_negatives,
            "false_positives": false_positives,
        }


def balanced_labels(events: Iterable[Any]) -> Counter[str]:
    """Return event-level class counts for a quick dataset balance check."""
    return Counter(event_label_from_ground_truth(event) for event in events)
