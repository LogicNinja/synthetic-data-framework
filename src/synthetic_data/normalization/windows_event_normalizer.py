from typing import Any

from synthetic_data.factory.event_factory import EventFactory
from synthetic_data.models.event import (
    ProcessInfo,
    ProvenanceInfo,
    SourceInfo,
)


class WindowsEventNormalizer:
    """Normalize raw Windows telemetry into canonical events."""

    @staticmethod
    def _get_value(data: dict[str, Any], *keys: str) -> Any:
        """Return the first matching field from a Windows event."""
        for key in keys:
            if key in data and data[key] is not None:
                return data[key]

        return None

    @classmethod
    def normalize(
        cls,
        raw_event: dict[str, Any],
        *,
        host_id: str,
        run_id: str,
        origin: str = "reference",
        scenario_id: str | None = None,
    ):
        """Convert a raw Windows event dictionary into a canonical event."""

        system = raw_event.get("System", {})
        event_data = raw_event.get("EventData", {})

        event_id = cls._get_value(
            system,
            "EventID",
            "event_id",
        )

        channel = cls._get_value(
            system,
            "Channel",
            "channel",
        )

        timestamp = cls._get_value(
            system,
            "TimeCreated",
            "timestamp",
        )

        if isinstance(timestamp, dict):
            timestamp = timestamp.get("SystemTime")

        if not timestamp:
            raise ValueError("Windows event is missing its timestamp.")

        if not event_id:
            raise ValueError("Windows event is missing its EventID.")

        if not isinstance(event_data, dict):
            raise ValueError("EventData must be a dictionary.")

        if str(event_id) == "1":
            event_source = "windows_process_creation"
            event_type = "process_creation"

            process = ProcessInfo(
                process_id=cls._get_value(
                    event_data,
                    "ProcessId",
                    "ProcessID",
                ),
                process_guid=cls._get_value(
                    event_data,
                    "ProcessGuid",
                    "ProcessGUID",
                ),
                image=cls._get_value(event_data, "Image"),
                original_file_name=cls._get_value(
                    event_data,
                    "OriginalFileName",
                ),
                command_line=cls._get_value(
                    event_data,
                    "CommandLine",
                ),
                parent_process_id=cls._get_value(
                    event_data,
                    "ParentProcessId",
                    "ParentProcessID",
                ),
                parent_process_guid=cls._get_value(
                    event_data,
                    "ParentProcessGuid",
                    "ParentProcessGUID",
                ),
                parent_image=cls._get_value(
                    event_data,
                    "ParentImage",
                ),
                parent_command_line=cls._get_value(
                    event_data,
                    "ParentCommandLine",
                ),
                user=cls._get_value(event_data, "User"),
            )

        elif str(event_id) == "400":
            event_source = "powershell_classic"
            event_type = "powershell_engine_start"

            process = ProcessInfo(
                image=cls._get_value(
                    event_data,
                    "HostApplication",
                    "Application",
                ),
                command_line=cls._get_value(
                    event_data,
                    "CommandLine",
                ),
                user=cls._get_value(
                    event_data,
                    "User",
                ),
            )

        else:
            event_source = "other"
            event_type = f"windows_event_{event_id}"
            process = None

        source = SourceInfo(
            source_event_id=cls._get_value(
                system,
                "EventRecordID",
                "RecordID",
            ),
            channel=channel,
            event_code=event_id,
            raw_event=raw_event,
            source_fields=event_data,
        )

        provenance = ProvenanceInfo(
            origin=origin,
            scenario_id=scenario_id,
        )

        return EventFactory.create_event(
            event_source=event_source,
            event_type=event_type,
            timestamp=timestamp,
            host_id=host_id,
            origin=origin,
            run_id=run_id,
            process=process,
            source=source,
            provenance=provenance,
        )