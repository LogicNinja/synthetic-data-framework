"""Declarative scenario specs.

A spec is plain data (a dict or JSON file) describing a host, a user and an
ordered list of simulator actions. ``spec_to_scenario`` turns it into a
``ScenarioFunction`` the existing ``ScenarioRunner`` can execute, so agents can
propose scenarios without writing Python, and ground-truth labels still come
only from the simulator.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from synthetic_data.simulator.scenario_runner import (
    ScenarioContext,
    ScenarioFunction,
)

SPEC_DIR = Path(__file__).resolve().parent / "specs"

LABELS = {"malicious", "benign"}
TOP_LEVEL_REQUIRED = {"scenario_id", "hostname", "username", "label", "steps"}
TOP_LEVEL_OPTIONAL = {"description"}

_PROCESS_FIELDS = {
    "process_id",
    "image",
    "command_line",
    "original_file_name",
    "timestamp",
}

STEP_REQUIRED = {
    "start_process": _PROCESS_FIELDS,
    "spawn_child": _PROCESS_FIELDS | {"parent_process_id"},
    "create_file": {"file_path", "timestamp"},
    "modify_file": {"file_path", "timestamp"},
}

STEP_OPTIONAL = {"technique_labels"}

STEP_OPTIONAL_BY_ACTION = {
    "start_process": set(),
    "spawn_child": set(),
    "create_file": {"size"},
    "modify_file": {"size"},
}


class ScenarioSpecError(ValueError):
    """Raised when a scenario spec is malformed or inconsistent."""


def _validate_file_size(step: dict[str, Any], where: str) -> None:
    """Validate an optional file size."""
    if "size" not in step:
        return

    size = step["size"]

    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ScenarioSpecError(
            f"{where}: size must be a non-negative integer."
        )


def validate_spec(spec: dict[str, Any]) -> None:
    """Raise ScenarioSpecError if a spec is malformed or inconsistent."""
    if not isinstance(spec, dict):
        raise ScenarioSpecError("Spec must be a mapping.")

    missing = TOP_LEVEL_REQUIRED - spec.keys()
    if missing:
        raise ScenarioSpecError(f"Spec is missing fields: {sorted(missing)}")

    unknown = spec.keys() - TOP_LEVEL_REQUIRED - TOP_LEVEL_OPTIONAL
    if unknown:
        raise ScenarioSpecError(f"Spec has unknown fields: {sorted(unknown)}")

    for name in ("scenario_id", "hostname", "username"):
        if not isinstance(spec[name], str) or not spec[name].strip():
            raise ScenarioSpecError(f"{name} must be a non-empty string.")

    if not isinstance(spec["label"], str) or spec["label"] not in LABELS:
        raise ScenarioSpecError(f"label must be one of {sorted(LABELS)}.")

    steps = spec["steps"]
    if not isinstance(steps, list) or not steps:
        raise ScenarioSpecError("steps must be a non-empty list.")

    process_times: dict[str, datetime] = {}
    created_files: set[str] = set()

    previous_time: datetime | None = None
    any_technique = False

    for index, step in enumerate(steps, start=1):
        where = f"step {index}"

        if not isinstance(step, dict):
            raise ScenarioSpecError(f"{where}: must be a mapping.")

        action = step.get("action")
        if action not in STEP_REQUIRED:
            raise ScenarioSpecError(
                f"{where}: unknown action {action!r}. "
                f"Allowed: {sorted(STEP_REQUIRED)}."
            )

        required = STEP_REQUIRED[action]
        action_optional = STEP_OPTIONAL_BY_ACTION[action]

        missing = required - step.keys()
        if missing:
            raise ScenarioSpecError(
                f"{where}: missing fields {sorted(missing)}."
            )

        unknown = (
            step.keys()
            - required
            - STEP_OPTIONAL
            - action_optional
            - {"action"}
        )
        if unknown:
            raise ScenarioSpecError(
                f"{where}: unknown fields {sorted(unknown)}."
            )

        # Validate required string fields, except file size which is numeric.
        for name in required:
            if not isinstance(step[name], str) or not step[name].strip():
                raise ScenarioSpecError(
                    f"{where}: {name} must be a non-empty string."
                )

        labels = step.get("technique_labels", [])
        if not isinstance(labels, list) or not all(
            isinstance(label, str) and label for label in labels
        ):
            raise ScenarioSpecError(
                f"{where}: technique_labels must be a list of strings."
            )

        any_technique = any_technique or bool(labels)

        try:
            timestamp = datetime.fromisoformat(step["timestamp"])
        except ValueError:
            raise ScenarioSpecError(
                f"{where}: timestamp is not ISO 8601: "
                f"{step['timestamp']!r}."
            ) from None

        try:
            if previous_time is not None and timestamp < previous_time:
                raise ScenarioSpecError(
                    f"{where}: timestamp goes backwards in time."
                )
        except TypeError:
            raise ScenarioSpecError(
                f"{where}: timestamps must all include, or all omit, "
                "a UTC offset."
            ) from None

        if action in {"start_process", "spawn_child"}:
            process_id = step["process_id"]

            if process_id in process_times:
                raise ScenarioSpecError(
                    f"{where}: duplicate process_id {process_id!r}."
                )

            if action == "spawn_child":
                parent = step["parent_process_id"]
                if parent not in process_times:
                    raise ScenarioSpecError(
                        f"{where}: parent_process_id {parent!r} was not "
                        "started by an earlier step."
                    )

            process_times[process_id] = timestamp

        elif action in {"create_file", "modify_file"}:
            file_path = step["file_path"]

            if action == "create_file":
                if file_path in created_files:
                    raise ScenarioSpecError(
                        f"{where}: file already created: {file_path!r}."
                    )
                created_files.add(file_path)

            elif file_path not in created_files:
                raise ScenarioSpecError(
                    f"{where}: file_path {file_path!r} was not created "
                    "by an earlier step."
                )

            _validate_file_size(step, where)

        previous_time = timestamp

    if spec["label"] == "benign" and any_technique:
        raise ScenarioSpecError(
            "A benign scenario must not carry technique labels."
        )

    if spec["label"] == "malicious" and not any_technique:
        raise ScenarioSpecError(
            "A malicious scenario needs at least one technique label."
        )


def spec_to_scenario(spec: dict[str, Any]) -> ScenarioFunction:
    """Validate a spec and return a function ScenarioRunner can execute."""
    validate_spec(spec)
    steps = [dict(step) for step in spec["steps"]]

    def scenario(context: ScenarioContext) -> None:
        for step in steps:
            kwargs = {
                key: value
                for key, value in step.items()
                if key != "action"
            }
            kwargs.setdefault("technique_labels", [])

            action = step["action"]

            if action == "start_process":
                context.actions.start_process(
                    host_id=context.host.host_id,
                    user_id=context.user.user_id,
                    **kwargs,
                )

            elif action == "spawn_child":
                context.actions.spawn_child(**kwargs)

            elif action == "create_file":
                context.actions.create_file(
                    host_id=context.host.host_id,
                    **kwargs,
                )

            elif action == "modify_file":
                context.actions.modify_file(
                    host_id=context.host.host_id,
                    **kwargs,
                )

    return scenario


def load_spec(path: str | Path) -> dict[str, Any]:
    """Load and validate a spec from a JSON file."""
    with Path(path).open("r", encoding="utf-8") as file:
        spec = json.load(file)

    validate_spec(spec)
    return spec


def load_builtin_spec(name: str) -> dict[str, Any]:
    """Load a spec shipped in scenarios/specs, e.g. 's2_wmi_powershell'."""
    return load_spec(SPEC_DIR / f"{name}.json")