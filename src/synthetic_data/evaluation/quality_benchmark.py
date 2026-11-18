"""Reference fidelity and controlled cohort benchmarking for event datasets."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import re
from statistics import mean
from typing import Any, Iterable

from synthetic_data.evaluation.diversity import benchmark_dataset_diversity


def _data(event: Any) -> dict[str, Any]:
    return event.to_dict() if hasattr(event, "to_dict") else dict(event)


def _basename(value: Any) -> str:
    return str(value or "<missing>").replace("\\", "/").rsplit("/", 1)[-1].casefold()


def _features(events: list[dict[str, Any]]) -> dict[str, Counter[str]]:
    features: dict[str, Counter[str]] = defaultdict(Counter)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        features["event_type"][str(event.get("event_type", "<missing>"))] += 1
        features["event_source"][str(event.get("event_source", "<missing>"))] += 1
        process = event.get("process") or {}
        source = event.get("source") or {}
        features["process.image"][_basename(process.get("image"))] += 1
        features["process.parent_image"][_basename(process.get("parent_image"))] += 1
        relationship = (
            f"{_basename(process.get('parent_image'))} -> {_basename(process.get('image'))}"
        )
        features["process_relationship"][relationship] += 1
        features["source.channel"][str(source.get("channel") or "<missing>").casefold()] += 1
        features["source.event_code"][str(source.get("event_code") or "<missing>")] += 1
        # Compare command-line structure without retaining raw arguments or values.
        command = str(process.get("command_line") or "")
        executable = _basename(command.split(maxsplit=1)[0]) if command else "<missing>"
        flags = sorted({flag.casefold() for flag in re.findall(r"(?<!\S)(--?[A-Za-z][\w-]*)", command)})
        features["process.command_shape"][executable + " " + " ".join(flags)] += 1
        run = str(event.get("run_id") or event.get("provenance", {}).get("scenario_id") or "default")
        grouped[run].append(event)

    # Frequency per run is compared as per-type count buckets, so different
    # total dataset sizes do not dominate every other feature.
    for run_events in grouped.values():
        counts = Counter(str(event.get("event_type", "<missing>")) for event in run_events)
        for event_type, count in counts.items():
            bucket = "1" if count == 1 else "2-3" if count <= 3 else "4-7" if count <= 7 else "8+"
            features["event_frequency_per_run"][f"{event_type}:{bucket}"] += 1
        ordered = [str(event.get("event_type", "<missing>")) for event in sorted(run_events, key=lambda e: e.get("timestamp", ""))]
        features["event_pattern.bigram"].update(f"{a}->{b}" for a, b in zip(ordered, ordered[1:]))
        features["event_pattern.trigram"].update(
            f"{a}->{b}->{c}" for a, b, c in zip(ordered, ordered[1:], ordered[2:])
        )
    return features


def _total_variation_distance(left: Counter[str], right: Counter[str]) -> float:
    left_total, right_total = sum(left.values()), sum(right.values())
    if not left_total or not right_total:
        return 1.0
    return sum(
        abs(left.get(key, 0) / left_total - right.get(key, 0) / right_total)
        for key in left.keys() | right.keys()
    ) / 2


@dataclass(frozen=True)
class DatasetQualityReport:
    synthetic_event_count: int
    reference_event_count: int
    feature_total_variation_distances: dict[str, float]
    feature_similarities: dict[str, float]
    mean_reference_similarity: float | None
    diversity: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def benchmark_dataset_quality(
    synthetic_events: Iterable[Any], reference_events: Iterable[Any]
) -> DatasetQualityReport:
    """Compare telemetry type, field, relationship, frequency and pattern distributions.

    Each feature uses total variation distance (0 identical, 1 disjoint); its
    similarity is 1 - distance. It is a descriptive sample comparison, not a
    claim that synthetic records are authentic.
    """
    synthetic = [_data(event) for event in synthetic_events]
    reference = [_data(event) for event in reference_events]
    synthetic_features = _features(synthetic)
    reference_features = _features(reference)
    names = sorted(
        name
        for name in set(synthetic_features) | set(reference_features)
        if synthetic_features.get(name) or reference_features.get(name)
    )
    distances: dict[str, float] = {}
    for name in names:
        left = synthetic_features.get(name, Counter())
        right = reference_features.get(name, Counter())
        if not left or not right:
            distances[name] = 1.0
        else:
            distances[name] = _total_variation_distance(left, right)
    similarities = {name: 1.0 - score for name, score in distances.items()}
    diversity = benchmark_dataset_diversity(synthetic).to_dict()
    return DatasetQualityReport(
        synthetic_event_count=len(synthetic),
        reference_event_count=len(reference),
        feature_total_variation_distances=distances,
        feature_similarities=similarities,
        mean_reference_similarity=mean(similarities.values()) if similarities else None,
        diversity=diversity,
    )


def compare_experiment_cohorts(
    variants: dict[str, list[Any]],
    reference_events: list[Any],
    *,
    metadata: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare matched generator, critic, and feedback dataset cohorts.

    Metadata may contain `generation_latency_seconds`, `attempts`, `accepted`,
    `rejected`, and `critic_scores` (a list of per-criterion numeric scores).
    Missing fields remain null; they are never fabricated.
    """
    if not variants:
        raise ValueError("At least one experiment variant is required.")
    metadata = metadata or {}
    results: dict[str, Any] = {}
    for name, events in variants.items():
        quality = benchmark_dataset_quality(events, reference_events).to_dict()
        diversity = quality["diversity"]
        info = metadata.get(name, {})
        attempts = info.get("attempts", info.get("samples_evaluated"))
        accepted = info.get("accepted")
        rejected = info.get("rejected")
        acceptance_rate = (
            accepted / attempts
            if isinstance(accepted, (int, float)) and isinstance(attempts, (int, float)) and attempts > 0
            else info.get("acceptance_rate")
        )
        scores = info.get("critic_scores") or []
        if isinstance(scores, dict):
            scores = list(scores.values())
        numeric_scores = [value for value in scores if isinstance(value, (int, float))]
        results[name] = {
            "event_count": len(events),
            "diversity": diversity,
            "reference_quality": quality,
            "quality_score": mean(numeric_scores) if numeric_scores else None,
            "quality_score_definition": "Mean supplied Critic rubric score; null when not provided.",
            "generation_latency_seconds": info.get("generation_latency_seconds"),
            "attempts": attempts,
            "accepted": accepted,
            "rejected": rejected,
            "acceptance_rate": acceptance_rate,
            "filter_applied": info.get("filter_applied"),
            "cohort_samples_kept": info.get("cohort_samples_kept"),
        }
    baseline = results.get("generator")
    comparisons = {}
    if baseline:
        for name, result in results.items():
            if name == "generator":
                continue
            comparisons[name] = {
                "mean_reference_similarity_delta": _delta(
                    result["reference_quality"]["mean_reference_similarity"],
                    baseline["reference_quality"]["mean_reference_similarity"],
                ),
                "unique_scenario_rate_delta": _delta(
                    result["diversity"]["scenario_variation"]["unique_scenario_rate"],
                    baseline["diversity"]["scenario_variation"]["unique_scenario_rate"],
                ),
                "duplicate_rate_delta": _delta(
                    result["diversity"]["exact_duplicate_rate"],
                    baseline["diversity"]["exact_duplicate_rate"],
                ),
                "quality_score_delta": _delta(result["quality_score"], baseline["quality_score"]),
            }
    return {
        "report_version": "1.0",
        "reference_event_count": len(reference_events),
        "variants": results,
        "deltas_vs_generator_baseline": comparisons,
        "interpretation": (
            "Compare cohorts generated from the same request set, model, settings, and sample budget. "
            "Deltas are descriptive and do not establish causal improvement without matched runs."
        ),
        "token_usage_and_cost": "not_reported; API client does not expose usage metadata and cost analysis was previously excluded from scope.",
    }


def _delta(value: float | None, baseline: float | None) -> float | None:
    if value is None or baseline is None:
        return None
    return value - baseline
