
"""L3 domain-aware consistency checks for synthetic Windows telemetry.

These are rule-based consistency checks. They do not establish statistical
realism against real Windows reference telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable


@dataclass
class DomainRealismReport:
    """Results of domain-aware event consistency checks."""

    event_count: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Return True when no domain consistency errors were found."""
        return not self.errors


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a timezone-aware ISO 8601 timestamp."""
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            return None

        return parsed

    except ValueError:
        return None


def _valid_identifier(value: Any) -> bool:
    """Return True for a non-empty string or integer, excluding booleans."""
    if isinstance(value, bool):
        return False

    if isinstance(value, int):
        return True

    return isinstance(value, str) and bool(value.strip())


def validate_domain_realism(
    events: Iterable[dict[str, Any]],
) -> DomainRealismReport:
    """Check basic Windows process and file-activity consistency.

    Hard errors indicate malformed or contradictory data. Warnings indicate
    conditions that may be valid, such as a parent process outside this batch.
    Statistical comparison against reference telemetry is not performed.
    """
    event_list = list(events)
    report = DomainRealismReport(event_count=len(event_list))

    process_events: list[dict[str, Any]] = []
    file_events: list[dict[str, Any]] = []

    timestamps_by_host: dict[str, list[tuple[datetime, str]]] = {}
    process_guids: dict[str, str] = {}

    # First pass: validate common fields and classify event types.
    for event in event_list:
        event_id = str(event.get("event_id", "<unknown>"))
        host_id = event.get("host_id")
        event_type = event.get("event_type")

        if not isinstance(host_id, str) or not host_id.strip():
            report.errors.append(
                f"{event_id}: host_id must be a non-empty string."
            )

        timestamp = _parse_timestamp(event.get("timestamp"))

        if timestamp is None:
            report.errors.append(
                f"{event_id}: timestamp must be a valid "
                "timezone-aware ISO 8601 value."
            )
        elif isinstance(host_id, str) and host_id.strip():
            timestamps_by_host.setdefault(host_id, []).append(
                (timestamp, event_id)
            )

        if event_type == "process_creation":
            process_events.append(event)

        elif event_type in {"file_creation", "file_modification"}:
            file_events.append(event)

    # Check timestamp ordering as events appear in the supplied stream.
    for host_id, entries in timestamps_by_host.items():
        for previous, current in zip(entries, entries[1:]):
            if current[0] < previous[0]:
                report.errors.append(
                    f"{host_id}: timestamp ordering is inconsistent "
                    f"between {previous[1]} and {current[1]}."
                )

    # Validate process creation fields and collect process GUIDs.
    for event in process_events:
        event_id = str(event.get("event_id", "<unknown>"))
        process = event.get("process")

        if not isinstance(process, dict):
            report.errors.append(
                f"{event_id}: process_creation requires a process object."
            )
            continue

        image = process.get("image")
        if not isinstance(image, str) or not image.strip():
            report.errors.append(
                f"{event_id}: process.image must be a non-empty string."
            )

        process_id = process.get("process_id")
        if not _valid_identifier(process_id):
            report.errors.append(
                f"{event_id}: process.process_id must be a "
                "non-empty string or integer."
            )

        process_guid = process.get("process_guid")
        if not isinstance(process_guid, str) or not process_guid.strip():
            report.errors.append(
                f"{event_id}: process.process_guid must be "
                "a non-empty string."
            )
        else:
            if process_guid in process_guids:
                report.errors.append(
                    f"{event_id}: duplicate process_guid "
                    f"{process_guid} also used by "
                    f"{process_guids[process_guid]}."
                )
            else:
                process_guids[process_guid] = event_id

    # Validate parent process references.
    for event in process_events:
        event_id = str(event.get("event_id", "<unknown>"))
        process = event.get("process")

        if not isinstance(process, dict):
            continue

        process_guid = process.get("process_guid")
        parent_guid = process.get("parent_process_guid")

        if (
            isinstance(process_guid, str)
            and process_guid.strip()
            and isinstance(parent_guid, str)
            and parent_guid.strip()
            and process_guid == parent_guid
        ):
            report.errors.append(
                f"{event_id}: process cannot be its own parent."
            )
            continue

        if (
            isinstance(parent_guid, str)
            and parent_guid.strip()
            and parent_guid not in process_guids
        ):
            report.warnings.append(
                f"{event_id}: parent_process_guid {parent_guid} "
                "does not refer to a process in this event batch."
            )

    # Validate file activity event fields.
    for event in file_events:
        event_id = str(event.get("event_id", "<unknown>"))
        extensions = event.get("extensions")

        if not isinstance(extensions, dict):
            report.errors.append(
                f"{event_id}: extensions must be an object."
            )
            continue

        file_activity = extensions.get("file_activity")

        if not isinstance(file_activity, dict):
            report.errors.append(
                f"{event_id}: missing extensions.file_activity object."
            )
            continue

        file_path = file_activity.get("file_path")
        file_size = file_activity.get("file_size")
        activity = file_activity.get("activity")

        if not isinstance(file_path, str) or not file_path.strip():
            report.errors.append(
                f"{event_id}: file_activity.file_path must be "
                "a non-empty string."
            )
        elif "\x00" in file_path:
            report.errors.append(
                f"{event_id}: file_activity.file_path must not "
                "contain a null byte."
            )

        if (
            not isinstance(file_size, int)
            or isinstance(file_size, bool)
            or file_size < 0
        ):
            report.errors.append(
                f"{event_id}: file_activity.file_size must be "
                "a non-negative integer."
            )

        expected_activity = {
            "file_creation": "creation",
            "file_modification": "modification",
        }.get(event.get("event_type"))

        if activity != expected_activity:
            report.errors.append(
                f"{event_id}: activity should be "
                f"{expected_activity!r} for event type "
                f"{event.get('event_type')!r}."
            )

    return report
