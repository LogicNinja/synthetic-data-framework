
import hashlib
import json

import pytest

from synthetic_data.factory.event_factory import EventFactory
from synthetic_data.storage import dataset_store
from synthetic_data.storage.dataset_store import DatasetStore


def create_event(event_id, host_id="host-001", run_id="run-001"):
    return EventFactory.create_event(
        event_id=event_id,
        event_source="windows_process_creation",
        event_type="process_create",
        timestamp="2026-10-29T10:30:00Z",
        host_id=host_id,
        origin="synthetic",
        run_id=run_id,
    )


def configure_dataset_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(
        DatasetStore,
        "DATASET_TYPES",
        {"generated": tmp_path},
    )


def test_save_and_load_dataset(tmp_path, monkeypatch):
    configure_dataset_directory(tmp_path, monkeypatch)

    events = [create_event("evt-001"), create_event("evt-002")]

    path = DatasetStore.save(
        events,
        dataset_type="generated",
        filename="test_dataset.jsonl",
    )

    loaded = DatasetStore.load(
        dataset_type="generated",
        filename="test_dataset.jsonl",
    )

    assert path.exists()
    assert len(loaded) == 2
    assert loaded[0].event_id == "evt-001"
    assert loaded[1].event_id == "evt-002"


def test_unknown_dataset_type_rejected():
    with pytest.raises(ValueError):
        DatasetStore.get_dataset_path("unknown", "events.jsonl")


def test_invalid_filename_rejected():
    with pytest.raises(ValueError):
        DatasetStore.get_dataset_path("generated", "..\\secret.jsonl")


def test_non_jsonl_filename_rejected():
    with pytest.raises(ValueError):
        DatasetStore.get_dataset_path("generated", "events.csv")


def test_failed_write_preserves_existing_dataset(tmp_path, monkeypatch):
    configure_dataset_directory(tmp_path, monkeypatch)

    filename = "existing.jsonl"
    original_events = [create_event("evt-original")]

    path = DatasetStore.save(
        original_events,
        dataset_type="generated",
        filename=filename,
    )
    original_content = path.read_bytes()

    def fail_write(*args, **kwargs):
        raise OSError("Simulated write failure")

    monkeypatch.setattr(dataset_store, "write_jsonl", fail_write)

    with pytest.raises(OSError, match="Simulated write failure"):
        DatasetStore.save(
            [create_event("evt-new")],
            dataset_type="generated",
            filename=filename,
        )

    assert path.read_bytes() == original_content


def test_failed_write_removes_temporary_file(tmp_path, monkeypatch):
    configure_dataset_directory(tmp_path, monkeypatch)

    def fail_write(*args, **kwargs):
        raise OSError("Simulated write failure")

    monkeypatch.setattr(dataset_store, "write_jsonl", fail_write)

    with pytest.raises(OSError, match="Simulated write failure"):
        DatasetStore.save(
            [create_event("evt-001")],
            dataset_type="generated",
            filename="failure.jsonl",
        )

    assert list(tmp_path.glob(".failure.jsonl.*.tmp")) == []


def test_duplicate_event_id_with_identical_content_is_rejected(
    tmp_path,
    monkeypatch,
):
    configure_dataset_directory(tmp_path, monkeypatch)

    event = create_event("evt-duplicate")

    with pytest.raises(ValueError, match="identical event content"):
        DatasetStore.save(
            [event, event],
            dataset_type="generated",
            filename="duplicates.jsonl",
        )


def test_duplicate_event_id_with_different_content_is_rejected(
    tmp_path,
    monkeypatch,
):
    configure_dataset_directory(tmp_path, monkeypatch)

    first_event = create_event("evt-duplicate", host_id="host-001")
    second_event = create_event("evt-duplicate", host_id="host-002")

    with pytest.raises(ValueError, match="event content differs"):
        DatasetStore.save(
            [first_event, second_event],
            dataset_type="generated",
            filename="conflicts.jsonl",
        )


def test_duplicate_event_id_does_not_overwrite_existing_dataset(
    tmp_path,
    monkeypatch,
):
    configure_dataset_directory(tmp_path, monkeypatch)

    filename = "preserved.jsonl"
    original_events = [create_event("evt-existing")]

    path = DatasetStore.save(
        original_events,
        dataset_type="generated",
        filename=filename,
    )
    original_content = path.read_bytes()

    with pytest.raises(ValueError, match="Duplicate event_id"):
        DatasetStore.save(
            [
                create_event("evt-duplicate"),
                create_event("evt-duplicate"),
            ],
            dataset_type="generated",
            filename=filename,
        )

    assert path.read_bytes() == original_content


def test_manifest_contains_dataset_details_and_caller_metadata(
    tmp_path,
    monkeypatch,
):
    configure_dataset_directory(tmp_path, monkeypatch)

    events = [
        create_event("evt-001", run_id="run-001"),
        create_event("evt-002", run_id="run-002"),
    ]
    caller_metadata = {
        "scenario": "S2",
        "labels": ["process_creation", "powershell"],
        "generation_config": {"seed": 42},
    }

    path = DatasetStore.save(
        events,
        dataset_type="generated",
        filename="manifest_test.jsonl",
        metadata=caller_metadata,
    )

    manifest_path = path.with_suffix(path.suffix + ".meta.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["dataset_filename"] == "manifest_test.jsonl"
    assert manifest["event_count"] == 2
    assert manifest["run_ids"] == ["run-001", "run-002"]
    assert manifest["schema_versions"] == sorted(
        {event.schema_version for event in events}
    )
    assert manifest["metadata"] == caller_metadata


def test_manifest_checksum_matches_dataset_bytes(tmp_path, monkeypatch):
    configure_dataset_directory(tmp_path, monkeypatch)

    path = DatasetStore.save(
        [create_event("evt-001"), create_event("evt-002")],
        dataset_type="generated",
        filename="checksum_test.jsonl",
    )

    manifest = DatasetStore.load_metadata(
        dataset_type="generated",
        filename="checksum_test.jsonl",
    )
    expected_checksum = hashlib.sha256(path.read_bytes()).hexdigest()

    assert manifest["sha256"] == expected_checksum
    assert DatasetStore.verify_metadata(
        dataset_type="generated",
        filename="checksum_test.jsonl",
    )


def test_verify_metadata_detects_dataset_modification(tmp_path, monkeypatch):
    configure_dataset_directory(tmp_path, monkeypatch)

    path = DatasetStore.save(
        [create_event("evt-001")],
        dataset_type="generated",
        filename="modified.jsonl",
    )

    path.write_bytes(path.read_bytes() + b'{"tampered": true}\n')

    assert not DatasetStore.verify_metadata(
        dataset_type="generated",
        filename="modified.jsonl",
    )


def test_load_metadata_raises_when_manifest_is_missing(
    tmp_path,
    monkeypatch,
):
    configure_dataset_directory(tmp_path, monkeypatch)

    path = DatasetStore.save(
        [create_event("evt-001")],
        dataset_type="generated",
        filename="missing_manifest.jsonl",
    )
    manifest_path = path.with_suffix(path.suffix + ".meta.json")
    manifest_path.unlink()

    with pytest.raises(FileNotFoundError, match="Dataset metadata not found"):
        DatasetStore.load_metadata(
            dataset_type="generated",
            filename="missing_manifest.jsonl",
        )
