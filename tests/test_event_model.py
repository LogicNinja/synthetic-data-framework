
from synthetic_data.models.event import (
    CanonicalEvent,
    ProcessInfo,
    SourceInfo,
    ProvenanceInfo,
)


def test_canonical_event_validates():
    event = CanonicalEvent(
        event_id="evt-001",
        event_source="windows_process_creation",
        event_type="process_create",
        timestamp="2026-10-29T10:30:00Z",
        host_id="host-001",
        origin="synthetic",
        run_id="run-001",
        process=ProcessInfo(
            process_id=1234,
            image="C:\\Windows\\System32\\notepad.exe",
            parent_process_id=1000,
            parent_image="C:\\Windows\\explorer.exe",
        ),
        source=SourceInfo(
            channel="Microsoft-Windows-Sysmon/Operational",
            event_code=1,
        ),
        provenance=ProvenanceInfo(
            origin="synthetic",
            scenario_id="scenario-001",
            action_id="action-001",
            generator_version="0.1.0",
        ),
        ground_truth_labels=["benign"],
    )

    event.validate()


def test_canonical_event_converts_to_dict():
    event = CanonicalEvent(
        event_id="evt-002",
        event_source="other",
        event_type="test_event",
        timestamp="2026-10-29T10:30:00Z",
        host_id="host-001",
        origin="reference",
        run_id="run-001",
    )

    result = event.to_dict()

    assert result["event_id"] == "evt-002"
    assert result["schema_version"] == "1.0.0"
    assert "process" not in result


def test_invalid_canonical_event_is_rejected():
    event = CanonicalEvent(
        event_id="evt-003",
        event_source="invalid_source",
        event_type="test_event",
        timestamp="not-a-timestamp",
        host_id="host-001",
        origin="synthetic",
        run_id="run-001",
    )

    try:
        event.validate()
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid event should have failed validation")
