import pytest

from synthetic_data.evaluation.diversity import benchmark_dataset_diversity


def _event(event_id, run_id, *, event_type="process_creation", image="powershell.exe", technique="T1059.001", timestamp="t1"):
    return {
        "event_id": event_id,
        "event_source": "windows",
        "event_type": event_type,
        "timestamp": timestamp,
        "host_id": "host",
        "run_id": run_id,
        "origin": "synthetic",
        "process": {"image": image},
        "ground_truth_labels": [technique] if technique else [],
        "provenance": {"scenario_id": "scenario", "action_id": event_id},
    }


def test_dataset_benchmark_reports_distributions_scenarios_and_duplicates():
    rows = [
        _event("1", "r1"),
        _event("2", "r2", timestamp="t2"),  # semantic exact duplicate
        _event("3", "r3", event_type="file_creation", image="cmd.exe", technique="T1105"),
    ]
    report = benchmark_dataset_diversity(rows)
    assert report.event_count == 3
    assert report.unique_event_pattern_count == 2
    assert report.exact_duplicate_event_count == 1
    assert report.exact_duplicate_rate == pytest.approx(1 / 3)
    assert report.repeated_scenario_count == 1
    assert report.unique_scenario_count == 2
    assert report.event_distribution == {"file_creation": 1, "process_creation": 2}
    assert report.technique_coverage == ["T1059.001", "T1105"]
    assert report.technique_distribution == {"T1059.001": 2, "T1105": 1}
    assert report.label_distribution == {"malicious": 3}


def test_near_duplicate_event_patterns_are_counted_separately_from_exact():
    rows = [
        _event("1", "r1", image="powershell.exe"),
        _event("2", "r2", image="pwsh.exe"),
    ]
    report = benchmark_dataset_diversity(rows, near_duplicate_threshold=0.5)
    assert report.exact_duplicate_event_count == 0
    assert report.near_duplicate_event_pair_count == 1
    assert report.near_duplicate_scenario_pair_count == 1


def test_near_duplicate_threshold_is_validated():
    with pytest.raises(ValueError, match="near_duplicate_threshold"):
        benchmark_dataset_diversity([], near_duplicate_threshold=1.1)
