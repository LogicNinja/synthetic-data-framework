
import json

import pytest

from synthetic_data.validation.reference_realism import (
    DEFAULT_MINIMUM_SAMPLE_SIZE,
    compare_reference_realism,
    evaluate_reference_realism,
)


def make_event(
    event_type="process_creation",
    image="cmd.exe",
    user="alice",
):
    return {
        "event_type": event_type,
        "process": {
            "image": image,
            "user": user,
        },
    }


def test_identical_distributions_produce_perfect_similarity():
    synthetic = [
        make_event("process_creation", "cmd.exe", "alice"),
        make_event("process_creation", "powershell.exe", "bob"),
    ]
    reference = [
        make_event("process_creation", "cmd.exe", "someone_else"),
        make_event("process_creation", "powershell.exe", "another_user"),
    ]

    report = compare_reference_realism(synthetic, reference)

    assert report.status == "evaluated"
    assert report.ok
    assert report.synthetic_event_count == 2
    assert report.reference_event_count == 2
    assert report.similarity_score == pytest.approx(1.0)
    assert report.feature_distances["process_image"] == pytest.approx(0.0)
    assert "process_user" not in report.feature_distances
    assert report.sample_adequacy == "low_sample"
    assert report.minimum_sample_size == DEFAULT_MINIMUM_SAMPLE_SIZE


def test_different_process_image_distributions_reduce_similarity():
    synthetic = [
        make_event("process_creation", "cmd.exe"),
        make_event("process_creation", "cmd.exe"),
    ]
    reference = [
        make_event("process_creation", "notepad.exe"),
        make_event("process_creation", "notepad.exe"),
    ]

    report = compare_reference_realism(synthetic, reference)

    assert report.similarity_score == pytest.approx(0.0)
    assert report.feature_distances["process_image"] == pytest.approx(1.0)
    assert report.sample_adequacy == "low_sample"


def test_executable_path_is_normalized_to_basename():
    synthetic = [
        make_event(image=r"C:\Windows\System32\cmd.exe")
    ]
    reference = [
        make_event(image="/usr/bin/cmd.exe")
    ]

    report = compare_reference_realism(synthetic, reference)

    assert report.feature_distances["process_image"] == pytest.approx(0.0)
    assert report.similarity_score == pytest.approx(1.0)


def test_non_process_events_are_excluded_from_comparison():
    synthetic = [
        make_event("process_creation", "cmd.exe"),
        make_event("file_creation", "notepad.exe"),
    ]
    reference = [
        make_event("process_creation", "cmd.exe"),
        make_event("file_modification", "powershell.exe"),
    ]

    report = compare_reference_realism(synthetic, reference)

    assert report.status == "evaluated"
    assert report.synthetic_event_count == 1
    assert report.reference_event_count == 1
    assert report.similarity_score == pytest.approx(1.0)


def test_reference_without_process_creation_events_is_unavailable():
    report = compare_reference_realism(
        [make_event()],
        [make_event("file_creation", "notepad.exe")],
    )

    assert report.status == "reference_unavailable"
    assert report.similarity_score is None
    assert report.reference_event_count == 0
    assert report.sample_adequacy == "not_assessable"
    assert not report.ok


def test_synthetic_without_process_creation_events_is_unavailable():
    report = compare_reference_realism(
        [make_event("file_creation", "cmd.exe")],
        [make_event()],
    )

    assert report.status == "synthetic_unavailable"
    assert report.similarity_score is None
    assert report.synthetic_event_count == 0
    assert report.sample_adequacy == "not_assessable"


def test_empty_reference_does_not_produce_a_score():
    report = compare_reference_realism(
        [make_event()],
        [],
    )

    assert report.status == "reference_unavailable"
    assert report.similarity_score is None
    assert not report.ok
    assert report.sample_adequacy == "not_assessable"


def test_empty_synthetic_dataset_does_not_produce_a_score():
    report = compare_reference_realism(
        [],
        [make_event()],
    )

    assert report.status == "synthetic_unavailable"
    assert report.similarity_score is None
    assert report.sample_adequacy == "not_assessable"


def test_adequate_sample_sizes_are_marked_adequate():
    synthetic = [make_event("process_creation", "cmd.exe") for _ in range(30)]
    reference = [make_event("process_creation", "cmd.exe") for _ in range(30)]

    report = compare_reference_realism(synthetic, reference)

    assert report.status == "evaluated"
    assert report.sample_adequacy == "adequate"
    assert report.minimum_sample_size == 30
    assert report.similarity_score == pytest.approx(1.0)


def test_custom_minimum_sample_size_is_supported():
    synthetic = [make_event() for _ in range(5)]
    reference = [make_event() for _ in range(8)]

    report = compare_reference_realism(
        synthetic,
        reference,
        minimum_sample_size=5,
    )

    assert report.sample_adequacy == "adequate"
    assert report.minimum_sample_size == 5


@pytest.mark.parametrize("invalid_size", [0, -1, 1.5, True, "30"])
def test_invalid_minimum_sample_size_is_rejected(invalid_size):
    with pytest.raises(ValueError, match="minimum_sample_size"):
        compare_reference_realism(
            [make_event()],
            [make_event()],
            minimum_sample_size=invalid_size,
        )


def test_jsonl_evaluation(tmp_path):
    synthetic_path = tmp_path / "synthetic.jsonl"
    reference_path = tmp_path / "reference.jsonl"

    event = make_event()

    synthetic_path.write_text(
        json.dumps(event) + "\n",
        encoding="utf-8",
    )
    reference_path.write_text(
        json.dumps(event) + "\n",
        encoding="utf-8",
    )

    report = evaluate_reference_realism(
        synthetic_path,
        reference_path,
    )

    assert report.status == "evaluated"
    assert report.synthetic_event_count == 1
    assert report.reference_event_count == 1
    assert report.similarity_score == pytest.approx(1.0)
    assert report.sample_adequacy == "low_sample"


def test_missing_reference_file_reports_unavailable(tmp_path):
    synthetic_path = tmp_path / "synthetic.jsonl"
    synthetic_path.write_text(
        json.dumps(make_event()) + "\n",
        encoding="utf-8",
    )

    report = evaluate_reference_realism(
        synthetic_path,
        tmp_path / "missing_reference.jsonl",
    )

    assert report.status == "reference_unavailable"
    assert report.similarity_score is None
    assert report.sample_adequacy == "not_assessable"


def test_malformed_jsonl_reports_invalid_dataset(tmp_path):
    synthetic_path = tmp_path / "synthetic.jsonl"
    reference_path = tmp_path / "reference.jsonl"

    synthetic_path.write_text("{not valid json}\n", encoding="utf-8")
    reference_path.write_text(
        json.dumps(make_event()) + "\n",
        encoding="utf-8",
    )

    report = evaluate_reference_realism(
        synthetic_path,
        reference_path,
    )

    assert report.status == "invalid_dataset"
    assert report.similarity_score is None
    assert report.sample_adequacy == "not_assessable"
    assert report.errors
