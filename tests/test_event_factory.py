
import pytest

from synthetic_data.factory.event_factory import EventFactory


def test_factory_creates_valid_event():
    event = EventFactory.create_event(
        event_source="windows_process_creation",
        event_type="process_create",
        timestamp="2026-10-29T10:30:00Z",
        host_id="host-001",
        origin="synthetic",
        run_id="run-001",
    )

    event.validate()

    assert event.event_id.startswith("evt-")
    assert event.schema_version == "1.0.0"
    assert event.event_source == "windows_process_creation"


def test_factory_uses_supplied_event_id():
    event = EventFactory.create_event(
        event_id="custom-event-001",
        event_source="other",
        event_type="test_event",
        timestamp="2026-10-29T10:30:00Z",
        host_id="host-001",
        origin="reference",
        run_id="run-001",
    )

    assert event.event_id == "custom-event-001"


def test_factory_rejects_invalid_event():
    with pytest.raises(ValueError):
        EventFactory.create_event(
            event_source="invalid_source",
            event_type="test_event",
            timestamp="not-a-timestamp",
            host_id="host-001",
            origin="synthetic",
            run_id="run-001",
        )
