
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
