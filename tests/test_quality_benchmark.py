from synthetic_data.evaluation.quality_benchmark import (
    benchmark_dataset_quality,
    compare_experiment_cohorts,
)


def _event(event_id, run, *, kind="process_creation", image="powershell.exe", parent="WmiPrvSE.exe"):
    return {
        "event_id": event_id,
        "event_source": "sysmon",
        "event_type": kind,
        "run_id": run,
        "timestamp": f"2026-01-01T00:00:0{event_id}+00:00",
        "process": {
            "image": f"C:\\Windows\\System32\\{image}",
            "parent_image": parent,
            "command_line": f"{image} -NoProfile",
        },
        "source": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_code": 1},
        "ground_truth_labels": ["T1059.001"],
    }


def test_quality_benchmark_compares_fields_relationships_frequency_and_patterns():
    reference = [
        _event("1", "ref1"),
        _event("2", "ref1", kind="file_creation", image="cmd.exe", parent="powershell.exe"),
    ]
    same = [
        _event("3", "syn1"),
        _event("4", "syn1", kind="file_creation", image="cmd.exe", parent="powershell.exe"),
    ]
    result = benchmark_dataset_quality(same, reference)
    assert result.mean_reference_similarity == 1.0
    assert result.feature_total_variation_distances["event_type"] == 0
    assert result.feature_total_variation_distances["process_relationship"] == 0
    assert result.feature_total_variation_distances["event_pattern.bigram"] == 0


def test_quality_benchmark_and_cohort_comparison_report_deltas_and_metadata():
    reference = [_event("1", "ref")]
    generator = [_event("2", "gen")]
    critic = [_event("3", "critic", image="cmd.exe")]
    report = compare_experiment_cohorts(
        {"generator": generator, "critic": critic},
        reference,
        metadata={
            "critic": {
                "samples_evaluated": 2,
                "accepted": 1,
                "rejected": 1,
                "generation_latency_seconds": 2.5,
                "critic_scores": {"accuracy": 4, "realism": 3},
            }
        },
    )
    assert report["variants"]["critic"]["acceptance_rate"] == 0.5
    assert report["variants"]["critic"]["quality_score"] == 3.5
    assert report["variants"]["critic"]["generation_latency_seconds"] == 2.5
    assert "critic" in report["deltas_vs_generator_baseline"]
