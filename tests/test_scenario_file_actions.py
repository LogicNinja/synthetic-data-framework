
"""Tests for declarative file-activity scenario actions."""

import pytest

from synthetic_data.scenarios.spec import (
    ScenarioSpecError,
    spec_to_scenario,
    validate_spec,
)
from synthetic_data.simulator.scenario_runner import ScenarioRunner


def make_file_spec():
    """Return a valid benign scenario with file creation and modification."""
    return {
        "scenario_id": "S4",
        "hostname": "WIN-SYNTH-04",
        "username": "analyst",
        "label": "benign",
        "steps": [
            {
                "action": "create_file",
                "file_path": r"C:\Users\analyst\Documents\report.txt",
                "size": 128,
                "timestamp": "2026-01-01T10:00:00+00:00",
            },
            {
                "action": "modify_file",
                "file_path": r"C:\Users\analyst\Documents\report.txt",
                "size": 256,
                "timestamp": "2026-01-01T10:00:05+00:00",
            },
        ],
    }


def run_spec(spec):
    """Execute a declarative spec through the real scenario runner."""
    return ScenarioRunner().run(
        scenario_id=spec["scenario_id"],
        run_id="test-run-s4",
        hostname=spec["hostname"],
        username=spec["username"],
        scenario=spec_to_scenario(spec),
    )


def test_file_activity_spec_executes_and_emits_events():
    spec = make_file_spec()

    result = run_spec(spec)

    assert len(result.events) == 2
    assert [event.event_type for event in result.events] == [
        "file_creation",
        "file_modification",
    ]


def test_file_activity_spec_records_action_trace():
    spec = make_file_spec()

    result = run_spec(spec)

    assert [entry.action_type for entry in result.trace] == [
        "create_file",
        "modify_file",
    ]
    assert [entry.event_ids for entry in result.trace] == [
        [result.events[0].event_id],
        [result.events[1].event_id],
    ]


def test_file_modification_updates_simulated_file_size():
    spec = make_file_spec()

    result = run_spec(spec)

    file_activity = result.events[-1].extensions["file_activity"]

    assert file_activity["file_path"] == (
        r"C:\Users\analyst\Documents\report.txt"
    )
    assert file_activity["activity"] == "modification"
    assert file_activity["file_size"] == 256


def test_file_events_have_synthetic_provenance():
    spec = make_file_spec()

    result = run_spec(spec)

    for event in result.events:
        assert event.origin == "synthetic"
        assert event.provenance.scenario_id == "S4"
        assert event.provenance.action_id


def test_modify_file_before_creation_is_rejected():
    spec = make_file_spec()
    spec["steps"] = [spec["steps"][1]]

    with pytest.raises(
        ScenarioSpecError,
        match="was not created by an earlier step",
    ):
        validate_spec(spec)


@pytest.mark.parametrize("invalid_size", [-1, 1.5, True, "128"])
def test_invalid_file_size_is_rejected(invalid_size):
    spec = make_file_spec()
    spec["steps"][0]["size"] = invalid_size

    with pytest.raises(
        ScenarioSpecError,
        match="size must be a non-negative integer",
    ):
        validate_spec(spec)


def test_duplicate_file_creation_is_rejected():
    spec = make_file_spec()
    duplicate_step = dict(spec["steps"][0])
    duplicate_step["timestamp"] = "2026-01-01T10:00:03+00:00"
    spec["steps"].insert(1, duplicate_step)

    with pytest.raises(
        ScenarioSpecError,
        match="file already created",
    ):
        validate_spec(spec)


def test_file_actions_reject_unknown_fields():
    spec = make_file_spec()
    spec["steps"][0]["unexpected"] = "value"

    with pytest.raises(
        ScenarioSpecError,
        match="unknown fields",
    ):
        validate_spec(spec)


def test_builtin_process_scenarios_still_validate():
    from synthetic_data.scenarios.spec import load_builtin_spec

    validate_spec(load_builtin_spec("s2_wmi_powershell"))
    validate_spec(load_builtin_spec("s3_cmd_powershell"))
