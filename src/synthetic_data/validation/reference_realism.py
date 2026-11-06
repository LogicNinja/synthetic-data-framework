"""Reference-based statistical comparison for synthetic Windows telemetry.

Layer 4 compares synthetic events with a reference dataset. It measures
distribution similarity; it does not prove that synthetic events are real.
A score is only produced when both datasets contain usable events.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


MISSING_VALUE = "<missing>"


@dataclass
class ReferenceRealismReport:
    """Result of comparing synthetic events with reference telemetry."""

    status: str
    synthetic_event_count: int
    reference_event_count: int
    feature_distances: dict[str, float] = field(default_factory=dict)
    similarity_score: float | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True only when a comparison was completed."""
        return self.status == "evaluated" and not self.errors

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable report."""
        return asdict(self)


def _feature_value(event: dict[str, Any], feature: str) -> str:
    """Extract a comparable value for a selected feature."""
    if feature == "event_type":
        value = event.get("event_type")

    elif feature == "process_image":
        process = event.get("process")
        value = process.get("image") if isinstance(process, dict) else None

        if isinstance(value, str):
            # Normalize Windows and POSIX path separators and compare
            # executable names rather than machine-specific full paths.
            value = value.replace("\\", "/").rsplit("/", 1)[-1].lower()

    elif feature == "process_user":
        process = event.get("process")
        value = process.get("user") if isinstance(process, dict) else None

        if isinstance(value, str):
            value = value.strip().lower()

    else:
        raise ValueError(f"Unsupported feature: {feature}")

    if value is None or not str(value).strip():
        return MISSING_VALUE

    return str(value).strip().lower()


def _distribution(events: list[dict[str, Any]], feature: str) -> Counter[str]:
    """Build a normalized feature-value counter."""
    return Counter(_feature_value(event, feature) for event in events)


def _total_variation_distance(
    synthetic: Counter[str],
    reference: Counter[str],
) -> float:
    """Calculate total variation distance between two empirical distributions.

    Returns a value between 0 and 1:
      0 means identical distributions.
      1 means completely disjoint distributions.
    """
    synthetic_total = sum(synthetic.values())
    reference_total = sum(reference.values())

    if synthetic_total == 0 or reference_total == 0:
        raise ValueError("Cannot compare an empty feature distribution.")

    all_values = set(synthetic) | set(reference)

    distance = sum(
        abs(
            synthetic[value] / synthetic_total
            - reference[value] / reference_total
        )
        for value in all_values
    )

    return distance / 2


def compare_reference_realism(
    synthetic_events: Iterable[dict[str, Any]],
    reference_events: Iterable[dict[str, Any]],
) -> ReferenceRealismReport:
    """Compare selected event distributions against reference telemetry.

    The overall similarity score is 1 minus the mean feature distance.
    It is a statistical similarity indicator, not a probability or proof
    of authenticity.
    """
    synthetic = list(synthetic_events)
    reference = list(reference_events)

    if not reference:
        return ReferenceRealismReport(
            status="reference_unavailable",
            synthetic_event_count=len(synthetic),
            reference_event_count=0,
            errors=["Reference dataset is empty or unavailable."],
        )

    if not synthetic:
        return ReferenceRealismReport(
            status="synthetic_unavailable",
            synthetic_event_count=0,
            reference_event_count=len(reference),
            errors=["Synthetic dataset is empty."],
        )

    features = (
        "event_type",
        "process_image",
        "process_user",
    )

    distances: dict[str, float] = {}

    for feature in features:
        synthetic_distribution = _distribution(synthetic, feature)
        reference_distribution = _distribution(reference, feature)

        distances[feature] = _total_variation_distance(
            synthetic_distribution,
            reference_distribution,
        )

    mean_distance = sum(distances.values()) / len(distances)

    return ReferenceRealismReport(
        status="evaluated",
        synthetic_event_count=len(synthetic),
        reference_event_count=len(reference),
        feature_distances=distances,
        similarity_score=1.0 - mean_distance,
    )


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load JSONL events, rejecting malformed lines and non-object values."""
    events: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number} in {path}: {exc}"
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"Line {line_number} in {path} must contain a JSON object."
                )

            events.append(event)

    return events


def evaluate_reference_realism(
    synthetic_path: str | Path,
    reference_path: str | Path,
) -> ReferenceRealismReport:
    """Load two JSONL datasets and compare their event distributions."""
    synthetic_file = Path(synthetic_path)
    reference_file = Path(reference_path)

    if not reference_file.is_file():
        synthetic_count = 0

        if synthetic_file.is_file():
            try:
                synthetic_count = len(_load_jsonl(synthetic_file))
            except (OSError, ValueError):
                pass

        return ReferenceRealismReport(
            status="reference_unavailable",
            synthetic_event_count=synthetic_count,
            reference_event_count=0,
            errors=[f"Reference file does not exist: {reference_file}"],
        )

    if not synthetic_file.is_file():
        return ReferenceRealismReport(
            status="synthetic_unavailable",
            synthetic_event_count=0,
            reference_event_count=0,
            errors=[f"Synthetic file does not exist: {synthetic_file}"],
        )

    try:
        synthetic = _load_jsonl(synthetic_file)
        reference = _load_jsonl(reference_file)
    except (OSError, ValueError) as exc:
        return ReferenceRealismReport(
            status="invalid_dataset",
            synthetic_event_count=0,
            reference_event_count=0,
            errors=[str(exc)],
        )

    return compare_reference_realism(synthetic, reference)
