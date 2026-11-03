
import json

from synthetic_data.factory.event_factory import EventFactory
from synthetic_data.serialization.event_serializer import (
    serialize_event,
    write_jsonl,
    read_jsonl,
)


def create_sample_event():
    return EventFactory.create_event(
        event_id="evt-serializer-001",
        event_source="windows_process_creation",
        event_type="process_create",
        timestamp="2026-10-29T10:30:00Z",
        host_id="host-001",
        origin="synthetic",
        run_id="run-001",
    )


def test_serialize_event_returns_json():
    event = create_sample_event()

    result = serialize_event(event)
    parsed = json.loads(result)

    assert parsed["event_id"] == "evt-serializer-001"
    assert parsed["schema_version"] == "1.0.0"


def test_jsonl_write_and_read_round_trip(tmp_path):
    event = create_sample_event()
    output_path = tmp_path / "events.jsonl"

    count = write_jsonl([event], output_path)
    loaded_events = read_jsonl(output_path)

    assert count == 1
    assert len(loaded_events) == 1
    assert loaded_events[0].event_id == event.event_id
    assert loaded_events[0].to_dict() == event.to_dict()


def test_jsonl_writes_multiple_events(tmp_path):
    events = [
        create_sample_event(),
        EventFactory.create_event(
            event_id="evt-serializer-002",
            event_source="other",
            event_type="test_event",
            timestamp="2026-10-29T10:31:00Z",
            host_id="host-001",
            origin="reference",
            run_id="run-001",
        ),
    ]

    output_path = tmp_path / "events.jsonl"

    count = write_jsonl(events, output_path)
    loaded_events = read_jsonl(output_path)

    assert count == 2
    assert len(loaded_events) == 2
    assert loaded_events[1].event_id == "evt-serializer-002"
