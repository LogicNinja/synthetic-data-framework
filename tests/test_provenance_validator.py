
from dataclasses import replace

from synthetic_data.schemas.provenance_validator import validate_provenance
from synthetic_data.simulator.action_trace import ActionTraceEntry
from synthetic_data.simulator.scenario_runner import (
    ScenarioContext,
    ScenarioRunner,
)


def _run_simple_scenario():
    def scenario(context: ScenarioContext) -> None:
        context.actions.start_process(
            host_id=context.host.host_id,
            user_id=context.user.user_id,
            image="powershell.exe",
            command_line="powershell.exe",
            process_id="proc-1",
            timestamp="2026-01-01T10:00:00Z",
            technique_labels=["T1059.001"],
        )

    return ScenarioRunner().run(
        scenario_id="scenario-1",
        run_id="run-1",
        hostname="WIN-TEST",
        username="analyst",
        scenario=scenario,
    )


def test_valid_event_and_trace_have_no_provenance_errors():
    result = _run_simple_scenario()

    errors = validate_provenance(result.events, result.trace)

    assert errors == []


def test_event_with_missing_trace_action_is_reported():
    result = _run_simple_scenario()

    event = result.events[0]
    event.provenance.action_id = "action-missing"

    errors = validate_provenance(result.events, result.trace)

    assert any("missing from the trace" in error for error in errors)


def test_event_id_mismatch_is_reported():
    result = _run_simple_scenario()

    trace_entry = result.trace[0]
    trace_entry.event_ids = ["event-not-real"]

    errors = validate_provenance(result.events, result.trace)

    assert any("references missing event ID" in error for error in errors)
    assert any("not listed as an output" in error for error in errors)


def test_ground_truth_label_mismatch_is_reported():
    result = _run_simple_scenario()

    result.events[0].ground_truth_labels = ["T1000"]

    errors = validate_provenance(result.events, result.trace)

    assert any("Ground-truth labels mismatch" in error for error in errors)


def test_duplicate_action_id_is_reported():
    result = _run_simple_scenario()

    duplicate = replace(
        result.trace[0],
        event_ids=["another-event"],
    )
    result.trace.append(duplicate)

    errors = validate_provenance(result.events, result.trace)

    assert any("Duplicate action ID" in error for error in errors)


def test_trace_entry_with_missing_event_is_reported():
    result = _run_simple_scenario()

    result.trace[0].event_ids = ["missing-event"]

    errors = validate_provenance(result.events, result.trace)

    assert any("references missing event ID" in error for error in errors)


def test_trace_entry_missing_action_id_is_reported():
    result = _run_simple_scenario()

    result.trace[0].action_id = ""

    errors = validate_provenance(result.events, result.trace)

    assert any("missing an action ID" in error for error in errors)


def test_trace_entry_with_no_event_ids_is_reported():
    result = _run_simple_scenario()

    result.trace[0].event_ids = []

    errors = validate_provenance(result.events, result.trace)

    assert any("has no recorded event IDs" in error for error in errors)


def test_event_missing_provenance_is_reported():
    result = _run_simple_scenario()

    result.events[0].provenance = None

    errors = validate_provenance(result.events, result.trace)

    assert any("missing provenance" in error for error in errors)


def test_duplicate_event_id_is_reported():
    result = _run_simple_scenario()

    duplicate_event = replace(
        result.events[0],
        event_id=result.events[0].event_id,
    )
    result.events.append(duplicate_event)

    errors = validate_provenance(result.events, result.trace)

    assert any("Duplicate event ID" in error for error in errors)


def test_trace_entry_must_list_event_as_its_output():
    result = _run_simple_scenario()

    result.trace[0].event_ids = ["some-other-event"]

    errors = validate_provenance(result.events, result.trace)

    assert any("not listed as an output" in error for error in errors)
