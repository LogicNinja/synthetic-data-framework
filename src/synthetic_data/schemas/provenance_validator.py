
"""Validate event provenance against the simulator action trace."""

from collections import Counter
from typing import Any, Iterable


def _get(value: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dictionary or an object."""
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def validate_provenance(
    events: Iterable[Any],
    trace: Iterable[Any],
) -> list[str]:
    """Return provenance errors found between events and action trace.

    The validator checks:
    - action IDs are present and unique in the trace
    - each event references a trace action
    - trace event IDs correspond to actual events
    - each trace action produces the event that references it
    - ground-truth labels match labels recorded in the trace
    """
    events = list(events)
    trace = list(trace)
    errors: list[str] = []

    trace_action_ids = [
        _get(entry, "action_id")
        for entry in trace
    ]
    event_ids = [
        _get(event, "event_id")
        for event in events
    ]

    duplicate_action_ids = [
        action_id
        for action_id, count in Counter(trace_action_ids).items()
        if action_id is not None and count > 1
    ]
    duplicate_event_ids = [
        event_id
        for event_id, count in Counter(event_ids).items()
        if event_id is not None and count > 1
    ]

    for action_id in duplicate_action_ids:
        errors.append(f"Duplicate action ID in trace: {action_id}")

    for event_id in duplicate_event_ids:
        errors.append(f"Duplicate event ID: {event_id}")

    trace_by_action_id = {
        _get(entry, "action_id"): entry
        for entry in trace
        if _get(entry, "action_id") is not None
    }

    event_id_set = set(event_ids)

    # Each trace entry must refer to an event that actually exists.
    for entry in trace:
        action_id = _get(entry, "action_id")
        recorded_event_ids = _get(entry, "event_ids", []) or []

        if not action_id:
            errors.append("Trace entry is missing an action ID.")

        if not recorded_event_ids:
            errors.append(
                f"Trace action {action_id} has no recorded event IDs."
            )

        for event_id in recorded_event_ids:
            if event_id not in event_id_set:
                errors.append(
                    f"Trace action {action_id} references missing event "
                    f"ID: {event_id}"
                )

    # Each event must be supported by its matching trace entry.
    for event in events:
        event_id = _get(event, "event_id")
        provenance = _get(event, "provenance")

        if provenance is None:
            errors.append(
                f"Event {event_id} is missing provenance."
            )
            continue

        action_id = _get(provenance, "action_id")

        if not action_id:
            errors.append(
                f"Event {event_id} is missing provenance action ID."
            )
            continue

        trace_entry = trace_by_action_id.get(action_id)

        if trace_entry is None:
            errors.append(
                f"Event {event_id} references action ID {action_id} "
                "which is missing from the trace."
            )
            continue

        recorded_event_ids = _get(trace_entry, "event_ids", []) or []

        if event_id not in recorded_event_ids:
            errors.append(
                f"Event {event_id} is not listed as an output of trace "
                f"action {action_id}."
            )

        event_labels = _get(event, "ground_truth_labels", []) or []
        trace_labels = _get(trace_entry, "technique_labels", []) or []

        if event_labels != trace_labels:
            errors.append(
                f"Ground-truth labels mismatch for event {event_id}: "
                f"event has {event_labels}, trace has {trace_labels}."
            )

    return errors
