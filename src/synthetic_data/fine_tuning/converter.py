"""Convert validated canonical telemetry into grounded chat fine-tuning rows."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
import random
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator


TASKS = (
    "event_classification",
    "log_interpretation",
    "attack_identification",
    "process_analysis",
    "threat_explanation",
)

SYSTEM_MESSAGE = (
    "You are a defensive Windows telemetry analyst. Base every conclusion only "
    "on the supplied simulated telemetry and its stated ground truth. Do not "
    "invent missing facts or claim that a single event proves malicious intent."
)

INSTRUCTIONS = {
    "event_classification": (
        "Classify this simulated Windows telemetry event as benign or malicious.",
        "Determine the ground-truth class of the following simulated event.",
    ),
    "log_interpretation": (
        "Interpret the observed fields in this simulated Windows event.",
        "Describe what the following telemetry record explicitly shows.",
    ),
    "attack_identification": (
        "Identify the ground-truth ATT&CK technique labels, if any, for this event.",
        "Report the configured technique IDs represented by this simulated event.",
    ),
    "process_analysis": (
        "Explain the recorded parent-child process relationship.",
        "What process relationship is explicitly recorded in this event?",
    ),
    "threat_explanation": (
        "Explain the event's ground-truth class and the telemetry evidence available.",
        "Explain what the simulator labels this event and what evidence it records.",
    ),
}


@dataclass(frozen=True)
class FineTuningExample:
    task: str
    scenario_group: str
    messages: list[dict[str, str]]
    source_event_ids: tuple[str, ...]
    label: str

    def to_chat_record(self) -> dict[str, Any]:
        # Fine-tuning files contain only the standard chat messages field.
        return {"messages": self.messages}


@dataclass(frozen=True)
class FineTuningDataset:
    splits: dict[str, list[FineTuningExample]]
    report: dict[str, Any]


def _as_dict(event: Any) -> dict[str, Any]:
    return event.to_dict() if hasattr(event, "to_dict") else dict(event)


def _ground_truth_label(event: dict[str, Any]) -> str:
    labels = event.get("ground_truth_labels") or []
    return "malicious" if labels else "benign"


def _scenario_group(event: dict[str, Any]) -> str:
    provenance = event.get("provenance") or {}
    return str(provenance.get("scenario_id") or event.get("run_id") or "unknown")


def _safe_event_view(event: dict[str, Any]) -> dict[str, Any]:
    """Keep relevant telemetry, excluding labels and identity/provenance leakage."""
    def scrub(value: Any) -> Any:
        excluded = {
            "ground_truth_labels", "label", "labels", "event_id", "source_event_id",
            "host_id", "run_id", "scenario_id", "action_id", "provenance",
            "detection_results",
        }
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items() if key not in excluded}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value

    fields = (
        "event_source", "event_type", "timestamp", "process", "source", "extensions",
    )
    process = scrub(dict(event.get("process") or {}))
    process.pop("user", None)
    process.pop("process_id", None)
    process.pop("process_guid", None)
    process.pop("parent_process_id", None)
    process.pop("parent_process_guid", None)
    view = scrub({key: event[key] for key in fields if key in event})
    if "process" in view:
        view["process"] = process
    source = view.get("source")
    if isinstance(source, dict):
        source = dict(source)
        source.pop("source_event_id", None)
        source.pop("raw_event", None)
        view["source"] = source
    return view


def _scenario_context(events: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(events, key=lambda event: (event.get("timestamp", ""), event.get("event_id", "")))
    return {
        "scenario_event_count": len(ordered),
        "event_sequence": [
            {
                "event_type": event.get("event_type"),
                "process_image": (event.get("process") or {}).get("image"),
                "parent_image": (event.get("process") or {}).get("parent_image"),
            }
            for event in ordered
        ],
    }


def _describe_event(event: dict[str, Any]) -> str:
    process = event.get("process") or {}
    process_name = process.get("image") or "an unspecified process"
    parent = process.get("parent_image")
    text = f"The record is a simulated {event.get('event_type', 'unknown')} event for {process_name}."
    if parent:
        text += f" Its recorded parent process is {parent}."
    source = event.get("source") or {}
    if source.get("channel"):
        text += f" The event channel is {source['channel']}."
    if source.get("event_code") is not None:
        text += f" The source event code is {source['event_code']}."
    return text


def _expected_response(task: str, event: dict[str, Any]) -> str | None:
    labels = sorted(str(value) for value in (event.get("ground_truth_labels") or []))
    label = _ground_truth_label(event)
    process = event.get("process") or {}
    process_name = process.get("image") or "an unspecified process"
    parent = process.get("parent_image")
    if task == "event_classification":
        return f"Ground-truth classification: {label}."
    if task == "log_interpretation":
        return _describe_event(event)
    if task == "attack_identification":
        return (
            "Ground-truth ATT&CK technique IDs: " + ", ".join(labels) + "."
            if labels else "No ground-truth ATT&CK technique label is attached to this event."
        )
    if task == "process_analysis":
        if not parent:
            return None
        return (
            f"The recorded process relationship is {parent} (parent) launching "
            f"{process_name} (child). This is the relationship represented in the simulated telemetry."
        )
    if task == "threat_explanation":
        explanation = f"The simulator's ground truth classifies this event as {label}. {_describe_event(event)}"
        if labels:
            explanation += " Configured technique labels: " + ", ".join(labels) + "."
        explanation += " A simulated event record alone does not establish real-world intent."
        return explanation
    raise ValueError(f"Unknown training task: {task}")


def _example(event: dict[str, Any], scenario_events: list[dict[str, Any]], task: str, index: int) -> FineTuningExample | None:
    response = _expected_response(task, event)
    if response is None:
        return None
    instruction = INSTRUCTIONS[task][index % len(INSTRUCTIONS[task])]
    payload: dict[str, Any] = {"task": task, "event": _safe_event_view(event)}
    if len(scenario_events) > 1:
        payload["scenario_context"] = _scenario_context(scenario_events)
    user_content = instruction + "\nTelemetry (JSON):\n" + json.dumps(
        payload, sort_keys=True, ensure_ascii=False
    )
    scenario_group = _scenario_group(event)
    return FineTuningExample(
        task=task,
        scenario_group=scenario_group,
        messages=[
            {"role": "system", "content": SYSTEM_MESSAGE},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": response},
        ],
        source_event_ids=(str(event.get("event_id", "")),),
        label=_ground_truth_label(event),
    )


def _split_group_ids(groups: list[str], ratios: tuple[float, float, float], seed: int) -> dict[str, set[str]]:
    if len(groups) < 3:
        raise ValueError(
            "At least three distinct scenario groups are required to create "
            "non-empty train, validation, and test splits without leakage."
        )
    if any(value <= 0 for value in ratios) or abs(sum(ratios) - 1.0) > 1e-8:
        raise ValueError("Split ratios must be positive and sum to 1.0.")
    shuffled = list(groups)
    random.Random(seed).shuffle(shuffled)
    raw = [len(groups) * ratio for ratio in ratios]
    counts = [int(value) for value in raw]
    for index in sorted(range(3), key=lambda item: raw[item] - counts[item], reverse=True)[: len(groups) - sum(counts)]:
        counts[index] += 1
    # Ensure all three splits remain represented for small but valid corpora.
    for empty in [index for index, count in enumerate(counts) if count == 0]:
        donor = max(range(3), key=lambda index: counts[index])
        counts[donor] -= 1
        counts[empty] = 1
    names = ("train", "validation", "test")
    split_groups: dict[str, set[str]] = {}
    start = 0
    for name, count in zip(names, counts):
        split_groups[name] = set(shuffled[start:start + count])
        start += count
    return split_groups


def convert_validated_telemetry(
    events: Iterable[Any],
    *,
    split_ratios: tuple[float, float, float] = (0.8, 0.1, 0.1),
    seed: int = 17,
    allowed_tasks: tuple[str, ...] = TASKS,
) -> FineTuningDataset:
    """Create deduplicated instruction-response rows, split by scenario group."""
    unknown_tasks = set(allowed_tasks) - set(TASKS)
    if unknown_tasks or not allowed_tasks:
        raise ValueError(f"Unknown or empty task list: {sorted(unknown_tasks)}")
    records = [_as_dict(event) for event in events]
    if not records:
        raise ValueError("Cannot convert an empty telemetry dataset.")
    by_group: dict[str, list[dict[str, Any]]] = {}
    for event in records:
        by_group.setdefault(_scenario_group(event), []).append(event)

    examples: list[FineTuningExample] = []
    for event_index, event in enumerate(records):
        group_events = by_group[_scenario_group(event)]
        for task_index, task in enumerate(allowed_tasks):
            row = _example(event, group_events, task, event_index + task_index)
            if row is not None:
                examples.append(row)

    seen: set[str] = set()
    unique_examples: list[FineTuningExample] = []
    duplicate_count = 0
    for example in examples:
        signature = hashlib.sha256(
            json.dumps(example.to_chat_record(), sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        if signature in seen:
            duplicate_count += 1
            continue
        seen.add(signature)
        unique_examples.append(example)

    split_groups = _split_group_ids(sorted(by_group), split_ratios, seed)
    splits = {
        name: [example for example in unique_examples if example.scenario_group in group_ids]
        for name, group_ids in split_groups.items()
    }
    if any(not split for split in splits.values()):
        raise ValueError("Each train/validation/test split must contain at least one example.")
    report = {
        "format": "chat_messages_jsonl",
        "event_count": len(records),
        "scenario_group_count": len(by_group),
        "example_count_before_deduplication": len(examples),
        "example_count": len(unique_examples),
        "duplicate_example_count": duplicate_count,
        "task_distribution": dict(sorted(Counter(example.task for example in unique_examples).items())),
        "label_distribution": dict(sorted(Counter(example.label for example in unique_examples).items())),
        "split_counts": {name: len(rows) for name, rows in splits.items()},
        "scenario_groups_per_split": {name: sorted(groups) for name, groups in split_groups.items()},
        "ground_truth_consistency": "Expected responses are deterministically derived from canonical event labels and fields.",
        "critique": "No separate LLM Critic review was run; conversion validation checks schema, labels, required content, and duplicates deterministically.",
    }
    dataset = FineTuningDataset(splits=splits, report=report)
    validate_fine_tuning_dataset(dataset, source_events=records)
    return dataset


def validate_fine_tuning_dataset(
    dataset: FineTuningDataset, *, source_events: Iterable[dict[str, Any]] | None = None
) -> None:
    """Validate row schema, content, labels, duplicates, and split isolation."""
    schema_path = Path(__file__).parents[1] / "schemas" / "fine_tuning_chat.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    seen: set[str] = set()
    groups: dict[str, set[str]] = {name: set() for name in dataset.splits}
    source_by_id = {
        str(event.get("event_id", "")): event
        for event in (source_events or [])
    }
    for split_name, examples in dataset.splits.items():
        for example in examples:
            record = example.to_chat_record()
            errors = list(validator.iter_errors(record))
            if errors:
                raise ValueError(
                    f"Invalid {split_name} fine-tuning example: "
                    + "; ".join(error.message for error in errors)
                )
            if any(not message["content"].strip() for message in example.messages):
                raise ValueError(f"Empty content in {split_name} fine-tuning example.")
            if example.task == "event_classification":
                expected = f"Ground-truth classification: {example.label}."
                if example.messages[-1]["content"] != expected:
                    raise ValueError("Classification response conflicts with source ground truth.")
            if source_by_id:
                source = source_by_id.get(example.source_event_ids[0])
                if source is None:
                    raise ValueError("Training example references an unknown source event.")
                if example.label != _ground_truth_label(source):
                    raise ValueError("Training example label conflicts with source ground truth.")
                expected_response = _expected_response(example.task, source)
                if expected_response != example.messages[-1]["content"]:
                    raise ValueError(
                        f"Expected response for task {example.task} conflicts with source telemetry."
                    )
            signature = hashlib.sha256(
                json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            if signature in seen:
                raise ValueError("Duplicate fine-tuning example remains after deduplication.")
            seen.add(signature)
            groups[split_name].add(example.scenario_group)
    split_names = list(groups)
    for index, name in enumerate(split_names):
        for other in split_names[index + 1:]:
            overlap = groups[name] & groups[other]
            if overlap:
                raise ValueError(f"Scenario leakage across {name}/{other}: {sorted(overlap)}")
