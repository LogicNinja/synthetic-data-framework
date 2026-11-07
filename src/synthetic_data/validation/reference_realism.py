
"""Reference-based statistical comparison for synthetic Windows telemetry.

Layer 4 compares synthetic process-creation events with reference
process-creation telemetry. It measures distribution similarity; it does
not prove that synthetic events are real.

The report also indicates whether the available sample sizes are large
enough for the similarity score to be interpreted with reasonable caution.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


MISSING_VALUE = "<missing>"
PROCESS_CREATION_EVENT_TYPE = "process_creation"
DEFAULT_MINIMUM_SAMPLE_SIZE = 30


@dataclass
class ReferenceRealismReport:
    """Result of comparing synthetic events with reference telemetry."""

    status: str
    synthetic_event_count: int
    reference_event_count: int
    feature_distances: dict[str, float] = field(default_factory=dict)
    similarity_score: float | None = None
    errors: list[str] = field(default_factory=list)
    sample_adequacy: str = "not_assessable"
    minimum_sample_size: int = DEFAULT_MINIMUM_SAMPLE_SIZE

    @property
    def ok(self) -> bool:
        """True only when a comparison was completed."""
        return self.status == "evaluated" and not self.errors

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable report."""
        return asdict(self)


def _process_creation_events(
    events: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return only canonical process-creation events."""
    return [
        event
        for event in events
        if event.get("event_type") == PROCESS_CREATION_EVENT_TYPE
    ]


def _feature_value(event: dict[str, Any], feature: str) -> str:
    """Extract a comparable value for a selected feature."""
    if feature == "process_image":
        process = event.get("process")
        value = process.get("image") if isinstance(process, dict) else None

        if isinstance(value, str):
            # Compare executable names rather than machine-specific paths.
            value = value.replace("\\", "/").rsplit("/", 1)[-1].lower()

    else:
        raise ValueError(f"Unsupported feature: {feature}")

    if value is None or not str(value).strip():
        return MISSING_VALUE

    return str(value).strip().lower()


def _distribution(
    events: list[dict[str, Any]],
    feature: str,
) -> Counter[str]:
    """Build a normalized feature-value counter."""
    return Counter(_feature_value(event, feature) for event in events)


def _total_variation_distance(
    synthetic: Counter[str],
    reference: Counter[str],
) -> float:
    """Calculate total variation distance between empirical distributions.

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


def _get_sample_adequacy(
    synthetic_count: int,
    reference_count: int,
    minimum_sample_size: int,
) -> str:
    """Classify sample size without changing the similarity calculation."""
    if (
        synthetic_count < minimum_sample_size
        or reference_count < minimum_sample_size
    ):
        return "low_sample"

    return "adequate"


def compare_reference_realism(
    synthetic_events: Iterable[dict[str, Any]],
    reference_events: Iterable[dict[str, Any]],
    *,
    minimum_sample_size: int = DEFAULT_MINIMUM_SAMPLE_SIZE,
) -> ReferenceRealismReport:
    """Compare process-image distributions against reference telemetry.

    The overall similarity score is 1 minus the mean feature distance.
    It is a statistical similarity indicator, not a probability or proof
    of authenticity.

    Sample adequacy is reported separately. A low sample size does not
    invalidate the descriptive score, but it limits its interpretation.

    Non-process-creation events are excluded from the comparison.
    """
    if (
        not isinstance(minimum_sample_size, int)
        or isinstance(minimum_sample_size, bool)
        or minimum_sample_size < 1
    ):
        raise ValueError("minimum_sample_size must be a positive integer.")

    synthetic = _process_creation_events(synthetic_events)
    reference = _process_creation_events(reference_events)

    if not reference:
        return ReferenceRealismReport(
            status="reference_unavailable",
            synthetic_event_count=len(synthetic),
            reference_event_count=0,
            errors=[
                "Reference dataset contains no process_creation events."
            ],
            minimum_sample_size=minimum_sample_size,
        )

    if not synthetic:
        return ReferenceRealismReport(
            status="synthetic_unavailable",
            synthetic_event_count=0,
            reference_event_count=len(reference),
            errors=[
                "Synthetic dataset contains no process_creation events."
            ],
            minimum_sample_size=minimum_sample_size,
        )

    features = ("process_image",)

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
        sample_adequacy=_get_sample_adequacy(
            len(synthetic),
            len(reference),
            minimum_sample_size,
        ),
        minimum_sample_size=minimum_sample_size,
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
    *,
    minimum_sample_size: int = DEFAULT_MINIMUM_SAMPLE_SIZE,
) -> ReferenceRealismReport:
    """Load two JSONL datasets and compare their process distributions."""
    if (
        not isinstance(minimum_sample_size, int)
        or isinstance(minimum_sample_size, bool)
        or minimum_sample_size < 1
    ):
        raise ValueError("minimum_sample_size must be a positive integer.")

    synthetic_file = Path(synthetic_path)
    reference_file = Path(reference_path)

    if not reference_file.is_file():
        synthetic_count = 0

        if synthetic_file.is_file():
            try:
                synthetic_events = _load_jsonl(synthetic_file)
                synthetic_count = len(
                    _process_creation_events(synthetic_events)
                )
            except (OSError, ValueError):
                pass

        return ReferenceRealismReport(
            status="reference_unavailable",
            synthetic_event_count=synthetic_count,
            reference_event_count=0,
            errors=[f"Reference file does not exist: {reference_file}"],
            minimum_sample_size=minimum_sample_size,
        )

    if not synthetic_file.is_file():
        return ReferenceRealismReport(
            status="synthetic_unavailable",
            synthetic_event_count=0,
            reference_event_count=0,
            errors=[f"Synthetic file does not exist: {synthetic_file}"],
            minimum_sample_size=minimum_sample_size,
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
            minimum_sample_size=minimum_sample_size,
        )

    return compare_reference_realism(
        synthetic,
        reference,
        minimum_sample_size=minimum_sample_size,
    )
