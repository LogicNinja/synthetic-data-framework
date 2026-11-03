
import json
from pathlib import Path
from typing import Any, Iterable

from synthetic_data.models.event import CanonicalEvent
from synthetic_data.schemas.event_validator import validate_event_or_raise


def serialize_event(event: CanonicalEvent) -> str:
    """Convert a canonical event to a JSON string."""
    event.validate()

    return json.dumps(
        event.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
    )


def write_jsonl(
    events: Iterable[CanonicalEvent],
    output_path: str | Path,
) -> int:
    """Write canonical events to a JSONL file. Return the number written."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    count = 0

    with path.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(serialize_event(event) + "\n")
            count += 1

    return count


def deserialize_event(data: dict[str, Any]) -> CanonicalEvent:
    """Reconstruct a canonical event from a dictionary."""
    validate_event_or_raise(data)

    # Import locally to keep reconstruction logic explicit.
    from synthetic_data.models.event import (
        DetectionResult,
        ProcessInfo,
        ProvenanceInfo,
        SourceInfo,
    )

    process = (
        ProcessInfo(**data["process"])
        if "process" in data
        else None
    )

    source = (
        SourceInfo(**data["source"])
        if "source" in data
        else None
    )

    provenance = (
        ProvenanceInfo(**data["provenance"])
        if "provenance" in data
        else None
    )

    detection_results = [
        DetectionResult(**result)
        for result in data.get("detection_results", [])
    ]

    return CanonicalEvent(
        event_id=data["event_id"],
        schema_version=data["schema_version"],
        event_source=data["event_source"],
        event_type=data["event_type"],
        timestamp=data["timestamp"],
        host_id=data["host_id"],
        origin=data["origin"],
        run_id=data["run_id"],
        process=process,
        source=source,
        provenance=provenance,
        ground_truth_labels=data.get("ground_truth_labels", []),
        detection_results=detection_results,
        extensions=data.get("extensions", {}),
    )


def read_jsonl(input_path: str | Path) -> list[CanonicalEvent]:
    """Read canonical events from a JSONL file."""
    path = Path(input_path)
    events = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                data = json.loads(line)
                events.append(deserialize_event(data))
            except (json.JSONDecodeError, ValueError, TypeError) as error:
                raise ValueError(
                    f"Invalid event on line {line_number}: {error}"
                ) from error

    return events
