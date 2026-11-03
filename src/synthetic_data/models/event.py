
from dataclasses import asdict, dataclass, field
from typing import Any

from synthetic_data.config.settings import EVENT_SCHEMA_VERSION
from synthetic_data.schemas.event_validator import validate_event_or_raise


def _remove_none_values(value: Any) -> Any:
    """Remove optional None values before schema validation."""
    if isinstance(value, dict):
        return {
            key: _remove_none_values(item)
            for key, item in value.items()
            if item is not None
        }

    if isinstance(value, list):
        return [_remove_none_values(item) for item in value]

    return value


@dataclass
class ProcessInfo:
    process_id: str | int | None = None
    process_guid: str | None = None
    image: str | None = None
    original_file_name: str | None = None
    command_line: str | None = None
    parent_process_id: str | int | None = None
    parent_process_guid: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    user: str | None = None


@dataclass
class SourceInfo:
    source_event_id: str | int | None = None
    channel: str | None = None
    event_code: str | int | None = None
    raw_event: dict | str | None = None
    source_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceInfo:
    origin: str | None = None
    scenario_id: str | None = None
    action_id: str | None = None
    generator_version: str | None = None
    parent_event_ids: list[str] = field(default_factory=list)


@dataclass
class DetectionResult:
    rule_id: str
    matched: bool
    evaluator_version: str
    reason: str | None = None


@dataclass
class CanonicalEvent:
    event_id: str
    event_source: str
    event_type: str
    timestamp: str
    host_id: str
    origin: str
    run_id: str

    schema_version: str = EVENT_SCHEMA_VERSION
    process: ProcessInfo | None = None
    source: SourceInfo | None = None
    provenance: ProvenanceInfo | None = None
    ground_truth_labels: list[str] = field(default_factory=list)
    detection_results: list[DetectionResult] = field(default_factory=list)
    extensions: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert the event into a JSON-ready dictionary."""
        return _remove_none_values(asdict(self))

    def validate(self) -> None:
        """Validate this event against the canonical JSON schema."""
        validate_event_or_raise(self.to_dict())
