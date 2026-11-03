
from uuid import uuid4
from typing import Any

from synthetic_data.config.settings import EVENT_SCHEMA_VERSION
from synthetic_data.models.event import (
    CanonicalEvent,
    DetectionResult,
    ProcessInfo,
    ProvenanceInfo,
    SourceInfo,
)


class EventFactory:
    """Create canonical events with consistent IDs and schema versioning."""

    @staticmethod
    def create_event(
        *,
        event_source: str,
        event_type: str,
        timestamp: str,
        host_id: str,
        origin: str,
        run_id: str,
        process: ProcessInfo | None = None,
        source: SourceInfo | None = None,
        provenance: ProvenanceInfo | None = None,
        ground_truth_labels: list[str] | None = None,
        detection_results: list[DetectionResult] | None = None,
        extensions: dict[str, Any] | None = None,
        event_id: str | None = None,
        validate: bool = True,
    ) -> CanonicalEvent:
        """Build a canonical event and optionally validate it."""

        event = CanonicalEvent(
            event_id=event_id or f"evt-{uuid4()}",
            schema_version=EVENT_SCHEMA_VERSION,
            event_source=event_source,
            event_type=event_type,
            timestamp=timestamp,
            host_id=host_id,
            origin=origin,
            run_id=run_id,
            process=process,
            source=source,
            provenance=provenance,
            ground_truth_labels=ground_truth_labels or [],
            detection_results=detection_results or [],
            extensions=extensions or {},
        )

        if validate:
            event.validate()

        return event
