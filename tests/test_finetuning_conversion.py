import hashlib
import json

import pytest

from synthetic_data.fine_tuning.converter import convert_validated_telemetry
from synthetic_data.models.event import CanonicalEvent, ProcessInfo, ProvenanceInfo
from synthetic_data.serialization.event_serializer import write_jsonl
from scripts.export_finetuning_dataset import load_validated_source


def _event(index, scenario, labels=None):
    return {
        "event_id": f"event-{index}",
        "event_source": "windows_process_creation",
        "event_type": "process_creation",
        "timestamp": f"2026-01-01T00:00:{index:02d}+00:00",
        "host_id": "synthetic-host",
        "origin": "synthetic",
        "run_id": f"run-{scenario}",
        "process": {
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent_image": "C:\\Windows\\System32\\WmiPrvSE.exe",
            "command_line": "powershell.exe -NoProfile",
        },
        "provenance": {"scenario_id": scenario, "action_id": f"a-{index}"},
        "ground_truth_labels": labels or [],
    }


def test_converter_builds_diverse_grounded_chat_examples_and_group_splits():
    events = [
        _event(1, "scenario-a", ["T1059.001"]),
        _event(2, "scenario-b"),
        _event(3, "scenario-c", ["T1047"]),
        _event(4, "scenario-d"),
    ]
    dataset = convert_validated_telemetry(events, split_ratios=(0.5, 0.25, 0.25), seed=1)
    assert set(dataset.splits) == {"train", "validation", "test"}
    assert all(dataset.splits.values())
    assert dataset.report["task_distribution"]["event_classification"] == 4
    assert dataset.report["task_distribution"]["process_analysis"] == 4
    all_examples = [example for rows in dataset.splits.values() for example in rows]
    class_examples = [item for item in all_examples if item.task == "event_classification"]
    assert any("Ground-truth classification: malicious." == item.messages[-1]["content"] for item in class_examples)
    assert any("Ground-truth classification: benign." == item.messages[-1]["content"] for item in class_examples)
    assert "ground_truth_labels" not in "".join(message["content"] for message in class_examples[0].messages)
    groups = [set(item.scenario_group for item in rows) for rows in dataset.splits.values()]
    assert not (groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2])


def test_converter_rejects_too_few_groups_for_leakage_free_splits():
    with pytest.raises(ValueError, match="three distinct scenario groups"):
        convert_validated_telemetry([_event(1, "only-a"), _event(2, "only-b")])


def test_source_loader_requires_validated_four_layer_manifest_and_checksum(tmp_path):
    path = tmp_path / "validated.jsonl"
    event = CanonicalEvent(
        event_id="e1",
        event_source="windows_process_creation",
        event_type="process_creation",
        timestamp="2026-01-01T00:00:00+00:00",
        host_id="host",
        origin="synthetic",
        run_id="r1",
        process=ProcessInfo(image="powershell.exe", parent_image="WmiPrvSE.exe"),
        provenance=ProvenanceInfo(scenario_id="scenario-1", action_id="a1"),
        ground_truth_labels=["T1059.001"],
    )
    write_jsonl([event], path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    validation_report = {
        "decision": "validated",
        "layers": {name: {"status": "passed"} for name in ("L1", "L2", "L3", "L4")},
    }
    manifest = {
        "sha256": digest,
        "event_count": 1,
        "metadata": {"validated": True, "validation_report": validation_report},
    }
    path.with_suffix(".jsonl.meta.json").write_text(json.dumps(manifest), encoding="utf-8")
    events, loaded_manifest, loaded_digest = load_validated_source(path)
    assert len(events) == 1
    assert loaded_manifest["metadata"]["validated"]
    assert loaded_digest == digest

    manifest["metadata"]["validated"] = False
    path.with_suffix(".jsonl.meta.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="not marked as four-layer validated"):
        load_validated_source(path)
