"""Dataset-level diversity and duplicate benchmarking for canonical events."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Iterable


def _dict(event: Any) -> dict[str, Any]:
    return event.to_dict() if hasattr(event, "to_dict") else dict(event)


def _semantic_event(event: dict[str, Any]) -> dict[str, Any]:
    """Strip identifiers and timing while preserving the event's meaning."""
    volatile = {
        "event_id", "process_id", "process_guid", "parent_process_id",
        "parent_process_guid", "source_event_id", "timestamp", "host_id",
        "run_id", "action_id", "parent_event_ids",
    }

    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items() if key not in volatile}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value

    return {
        "event_source": event.get("event_source"),
        "event_type": event.get("event_type"),
        "process": clean(event.get("process") or {}),
        "source": clean(event.get("source") or {}),
        "ground_truth_labels": sorted(event.get("ground_truth_labels") or []),
        "extensions": clean(event.get("extensions") or {}),
    }


def _signature(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _features(event: dict[str, Any]) -> set[str]:
    process = event.get("process") or {}
    source = event.get("source") or {}
    features = {
        f"type:{event.get('event_type', 'unknown')}",
        f"source:{event.get('event_source', 'unknown')}",
    }
    for key in ("image", "original_file_name", "parent_image"):
        if process.get(key):
            features.add(f"{key}:{str(process[key]).replace('\\\\', '/').split('/')[-1].casefold()}")
    if source.get("event_code") is not None:
        features.add(f"event_code:{source['event_code']}")
    features.update(f"technique:{label}" for label in event.get("ground_truth_labels") or [])
    return features


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


@dataclass(frozen=True)
class DiversityBenchmark:
    event_count: int
    unique_scenario_count: int
    unique_event_pattern_count: int
    exact_duplicate_event_count: int
    exact_duplicate_rate: float
    near_duplicate_event_pair_count: int
    repeated_scenario_count: int
    near_duplicate_scenario_pair_count: int
    event_distribution: dict[str, int]
    technique_coverage: list[str]
    technique_distribution: dict[str, int]
    label_distribution: dict[str, int]
    scenario_variation: dict[str, Any]
    near_duplicate_threshold: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def benchmark_dataset_diversity(
    events: Iterable[Any], *, near_duplicate_threshold: float = 0.9
) -> DiversityBenchmark:
    """Measure diversity and semantic repetition across one event dataset.

    Scenario identity is derived from provenance.scenario_id (falling back to
    run_id); scenario fingerprints use ordered event semantics. IDs and
    timestamps are excluded so replayed samples can be detected.
    """
    if not 0 <= near_duplicate_threshold <= 1:
        raise ValueError("near_duplicate_threshold must be in [0, 1].")
    records = [_dict(event) for event in events]
    event_patterns = [_semantic_event(event) for event in records]
    event_signatures = [_signature(pattern) for pattern in event_patterns]
    pattern_counts = Counter(event_signatures)
    exact_duplicates = sum(count - 1 for count in pattern_counts.values())

    event_distribution = Counter(str(e.get("event_type", "unknown")) for e in records)
    technique_distribution = Counter(
        str(label)
        for event in records
        for label in (event.get("ground_truth_labels") or [])
    )
    technique_coverage = sorted(technique_distribution)
    label_distribution = Counter(
        "malicious" if event.get("ground_truth_labels") else "benign"
        for event in records
    )

    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in records:
        provenance = event.get("provenance") or {}
        scenario_id = provenance.get("scenario_id") or "unknown"
        run_id = event.get("run_id") or "unknown"
        scenario_key = f"{scenario_id}@{run_id}"
        grouped.setdefault(str(scenario_key), []).append(event)

    scenario_features: dict[str, set[str]] = {}
    scenario_signatures: list[str] = []
    for key, group in grouped.items():
        group.sort(key=lambda item: (item.get("timestamp", ""), str((item.get("provenance") or {}).get("action_id", ""))))
        scenario_signatures.append(_signature([_semantic_event(event) for event in group]))
        features: set[str] = set()
        features.update(feature for event in group for feature in _features(event))
        # Include event order and transitions as behavior features.
        types = [str(event.get("event_type", "unknown")) for event in group]
        features.update(f"sequence:{a}->{b}" for a, b in zip(types, types[1:]))
        scenario_features[key] = features

    repeated_scenario_count = len(scenario_signatures) - len(set(scenario_signatures))
    near_event_pairs = 0
    event_feature_sets = [_features(event) for event in records]
    for i, left in enumerate(event_feature_sets):
        for j in range(i + 1, len(event_feature_sets)):
            if event_signatures[i] != event_signatures[j] and _jaccard(
                left, event_feature_sets[j]
            ) >= near_duplicate_threshold:
                near_event_pairs += 1

    scenario_items = list(scenario_features.items())
    near_scenario_pairs = sum(
        _jaccard(left_features, right_features) >= near_duplicate_threshold
        for index, (_, left_features) in enumerate(scenario_items)
        for _, right_features in scenario_items[index + 1:]
    )
    unique_scenarios = len(set(scenario_signatures))
    return DiversityBenchmark(
        event_count=len(records),
        unique_scenario_count=unique_scenarios,
        unique_event_pattern_count=len(pattern_counts),
        exact_duplicate_event_count=exact_duplicates,
        exact_duplicate_rate=exact_duplicates / len(records) if records else 0.0,
        near_duplicate_event_pair_count=near_event_pairs,
        repeated_scenario_count=repeated_scenario_count,
        near_duplicate_scenario_pair_count=near_scenario_pairs,
        event_distribution=dict(sorted(event_distribution.items())),
        technique_coverage=technique_coverage,
        technique_distribution=dict(sorted(technique_distribution.items())),
        label_distribution=dict(sorted(label_distribution.items())),
        scenario_variation={
            "scenario_count": len(grouped),
            "unique_fingerprint_count": unique_scenarios,
            "unique_scenario_rate": unique_scenarios / len(grouped) if grouped else 0.0,
            "behavior_feature_counts": {
                key: len(features) for key, features in sorted(scenario_features.items())
            },
        },
        near_duplicate_threshold=near_duplicate_threshold,
    )
