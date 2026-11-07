
import pytest

from synthetic_data.normalization.windows_event_normalizer import (
    WindowsEventNormalizer,
)


def test_normalize_sysmon_process_creation():
    raw_event = {
        "System": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventRecordID": 100,
            "TimeCreated": {
                "SystemTime": "2026-10-29T10:30:00Z"
            },
        },
        "EventData": {
            "ProcessId": "1234",
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "CommandLine": "notepad.exe",
            "ParentProcessId": "1000",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "User": "TEST\\User",
        },
    }

    event = WindowsEventNormalizer.normalize(
        raw_event,
        host_id="host-001",
        run_id="run-001",
    )

    assert event.event_source == "windows_process_creation"
    assert event.event_type == "process_creation"
    assert event.process.process_id == "1234"
    assert event.process.parent_image.endswith("explorer.exe")
    event.validate()


def test_normalize_powershell_classic_event():
    raw_event = {
        "System": {
            "EventID": 400,
            "Channel": "Windows PowerShell",
            "TimeCreated": {
                "SystemTime": "2026-10-29T10:30:00Z"
            },
        },
        "EventData": {
            "HostApplication": "powershell.exe",
            "User": "TEST\\User",
        },
    }

    event = WindowsEventNormalizer.normalize(
        raw_event,
        host_id="host-001",
        run_id="run-001",
    )

    assert event.event_source == "powershell_classic"
    assert event.event_type == "powershell_engine_start"
    assert event.process.image == "powershell.exe"
    event.validate()


def test_normalize_unknown_event():
    raw_event = {
        "System": {
            "EventID": 999,
            "Channel": "Example",
            "TimeCreated": {
                "SystemTime": "2026-10-29T10:30:00Z"
            },
        },
        "EventData": {},
    }

    event = WindowsEventNormalizer.normalize(
        raw_event,
        host_id="host-001",
        run_id="run-001",
    )

    assert event.event_source == "other"
    assert event.event_type == "windows_event_999"
    assert event.process is None


def test_missing_timestamp_rejected():
    raw_event = {
        "System": {"EventID": 1},
        "EventData": {},
    }

    with pytest.raises(ValueError):
        WindowsEventNormalizer.normalize(
            raw_event,
            host_id="host-001",
            run_id="run-001",
        )
