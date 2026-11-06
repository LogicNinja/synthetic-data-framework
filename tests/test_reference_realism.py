import json

import pytest

from synthetic_data.validation.reference_realism import (
    compare_reference_realism,
    evaluate_reference_realism,
)


def make_event(event_type="process_creation", image="cmd.exe", user="alice"):
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
        make_event("process_creation", "cmd.exe", "alice"),
        make_event("process_creation", "powershell.exe", "bob"),
    ]

    report = compare_reference_realism(synthetic, reference)

    assert report.status == "evaluated"
    assert report.ok
    assert report.similarity_score == pytest.approx(1.0)
    assert all(distance == pytest.approx(0.0)
               for distance in report.feature_distances.values())


def test_different_distributions_reduce_similarity():
    synthetic = [
        make_event("process_creation", "cmd.exe", "alice"),
        make_event("process_creation", "cmd.exe", "alice"),
    ]
    reference = [
        make_event("file_creation", "notepad.exe", "bob"),
        make_event("file_creation", "notepad.exe", "bob"),
    ]

    report = compare_reference_realism(synthetic, reference)

    assert report.status == "evaluated"
    assert report.similarity_score == pytest.approx(0.0)


def test_executable_path_is_normalized_to_basename():
    synthetic = [
        make_event(image=r"C:\Windows\System32\cmd.exe")
    ]
    reference = [
        make_event(image="/usr/bin/cmd.exe")
    ]

    report = compare_reference_realism(synthetic, reference)

    assert report.feature_distances["process_image"] == pytest.approx(0.0)


def test_empty_reference_does_not_produce_a_score():
    report = compare_reference_realism(
        [make_event()],
        [],
    )

    assert report.status == "reference_unavailable"
    assert report.similarity_score is None
    assert not report.ok


def test_empty_synthetic_dataset_does_not_produce_a_score():
    report = compare_reference_realism(
        [],
        [make_event()],
    )

    assert report.status == "synthetic_unavailable"
    assert report.similarity_score is None


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
    assert report.errors
