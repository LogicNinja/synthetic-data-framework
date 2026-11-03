
from synthetic_data.schemas.event_validator import validate_event


def test_valid_event():
    event = {
        "event_id": "evt-001",
        "schema_version": "1.0.0",
        "event_source": "windows_process_creation",
        "event_type": "process_start",
        "timestamp": "2026-11-03T08:30:00+05:30",
        "host_id": "host-test-01",
        "origin": "synthetic",
        "run_id": "run-test-01",
        "process": {
            "process_id": 1234,
            "image": "C:\\Windows\\System32\\example.exe",
            "parent_process_id": 1000,
            "parent_image": "C:\\Windows\\explorer.exe",
        },
    }

    assert validate_event(event) == []


def test_missing_required_field():
    event = {
        "event_id": "evt-002",
        "schema_version": "1.0.0",
        "event_source": "windows_process_creation",
        "event_type": "process_start",
        "timestamp": "2026-11-03T08:30:00+05:30",
        "host_id": "host-test-01",
        "origin": "synthetic",
    }

    errors = validate_event(event)

    assert errors
    assert any("run_id" in error for error in errors)


def test_invalid_timestamp():
    event = {
        "event_id": "evt-003",
        "schema_version": "1.0.0",
        "event_source": "windows_process_creation",
        "event_type": "process_start",
        "timestamp": "not-a-timestamp",
        "host_id": "host-test-01",
        "origin": "synthetic",
        "run_id": "run-test-01",
    }

    errors = validate_event(event)

    assert errors
    assert any("timestamp" in error for error in errors)
