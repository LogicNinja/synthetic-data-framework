import pytest

from synthetic_data.factory.event_factory import EventFactory
from synthetic_data.storage.dataset_store import DatasetStore


def create_event(event_id):
    return EventFactory.create_event(
        event_id=event_id,
        event_source="windows_process_creation",
        event_type="process_create",
        timestamp="2026-10-29T10:30:00Z",
        host_id="host-001",
        origin="synthetic",
        run_id="run-001",
    )


def test_save_and_load_dataset(tmp_path, monkeypatch):
    monkeypatch.setattr(
        DatasetStore,
        "DATASET_TYPES",
        {"generated": tmp_path},
    )

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
    monkeypatch.setattr(
        DatasetStore,
        "DATASET_TYPES",
        {"generated": tmp_path},
    )

    filename = "safe_dataset.jsonl"
    original_events = [create_event("evt-original")]

    path = DatasetStore.save(
        original_events,
        dataset_type="generated",
        filename=filename,
    )

    original_content = path.read_text(encoding="utf-8")

    def failing_write(events, output_path):
        output_path.write_text(
            '{"incomplete": ',
            encoding="utf-8",
        )
        raise OSError("Simulated write failure")

    monkeypatch.setattr(
        "synthetic_data.storage.dataset_store.write_jsonl",
        failing_write,
    )

    with pytest.raises(OSError, match="Simulated write failure"):
        DatasetStore.save(
            [create_event("evt-new")],
            dataset_type="generated",
            filename=filename,
        )

    assert path.read_text(encoding="utf-8") == original_content

    loaded = DatasetStore.load(
        dataset_type="generated",
        filename=filename,
    )

    assert [event.event_id for event in loaded] == ["evt-original"]


def test_failed_write_removes_temporary_file(tmp_path, monkeypatch):
    monkeypatch.setattr(
        DatasetStore,
        "DATASET_TYPES",
        {"generated": tmp_path},
    )

    def failing_write(events, output_path):
        output_path.write_text(
            '{"incomplete": ',
            encoding="utf-8",
        )
        raise OSError("Simulated write failure")

    monkeypatch.setattr(
        "synthetic_data.storage.dataset_store.write_jsonl",
        failing_write,
    )

    with pytest.raises(OSError, match="Simulated write failure"):
        DatasetStore.save(
            [create_event("evt-new")],
            dataset_type="generated",
            filename="new_dataset.jsonl",
        )

    assert not (tmp_path / "new_dataset.jsonl").exists()
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []


def test_duplicate_event_id_with_identical_content_is_rejected(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        DatasetStore,
        "DATASET_TYPES",
        {"generated": tmp_path},
    )

    event = create_event("evt-duplicate")

    with pytest.raises(ValueError, match="Duplicate event_id"):
        DatasetStore.save(
            [event, create_event("evt-duplicate")],
            dataset_type="generated",
            filename="duplicates.jsonl",
        )

    assert not (tmp_path / "duplicates.jsonl").exists()


def test_duplicate_event_id_with_different_content_is_rejected(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        DatasetStore,
        "DATASET_TYPES",
        {"generated": tmp_path},
    )

    first_event = create_event("evt-conflict")
    conflicting_event = create_event("evt-conflict")
    conflicting_event.host_id = "host-002"

    with pytest.raises(ValueError, match="Conflicting event_id"):
        DatasetStore.save(
            [first_event, conflicting_event],
            dataset_type="generated",
            filename="conflicts.jsonl",
        )

    assert not (tmp_path / "conflicts.jsonl").exists()


def test_duplicate_event_id_does_not_overwrite_existing_dataset(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        DatasetStore,
        "DATASET_TYPES",
        {"generated": tmp_path},
    )

    filename = "existing.jsonl"
    original_event = create_event("evt-original")

    path = DatasetStore.save(
        [original_event],
        dataset_type="generated",
        filename=filename,
    )

    original_content = path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate event_id"):
        DatasetStore.save(
            [
                create_event("evt-duplicate"),
                create_event("evt-duplicate"),
            ],
            dataset_type="generated",
            filename=filename,
        )

    assert path.read_text(encoding="utf-8") == original_content