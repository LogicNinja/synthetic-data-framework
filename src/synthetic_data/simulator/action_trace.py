"""Auditable records of successfully executed simulator actions."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ActionTraceEntry:
    """Record one simulator action and the events it produced."""

    action_id: str
    action_type: str
    parameters: dict[str, Any]
    event_ids: list[str] = field(default_factory=list)
    timestamp: str = ""
    technique_labels: list[str] = field(default_factory=list)