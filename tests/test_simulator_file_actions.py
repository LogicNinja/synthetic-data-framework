import pytest

from synthetic_data.simulator.actions import (
    SimulatorActionError,
    SimulatorActions,
)
from synthetic_data.simulator.state import (
    SimulatorState,
    SimulatorStateError,
)


@pytest.fixture
def actions_and_host():
    state = SimulatorState()
    host = state.create_host("TEST-PC", host_id="host-1")

    actions = SimulatorActions(
        state,
        scenario_id="file-activity-test",
        run_id="run-1",
    )

    return actions, host


def test_create_file_emits_event_and_trace(actions_and_host):
    actions, host = actions_and_host

    event = actions.create_file(
        host_id=host.host_id,
        file_path=r"C:\Temp\sample.txt",
        size=100,
        timestamp="2026-01-01T10:00:00Z",
        technique_labels=["T1105"],
    )

    assert event.event_type == "file_creation"
    assert event.host_id == host.host_id
    assert event.origin == "synthetic"
    assert event.run_id == "run-1"
    assert event.extensions["file_activity"] == {
        "activity": "creation",
        "file_path": r"C:\Temp\sample.txt",
        "file_size": 100,
    }

    assert len(actions.events) == 1
    assert len(actions.trace) == 1

    trace = actions.trace[0]
    assert trace.action_type == "create_file"
    assert trace.action_id == event.provenance.action_id
    assert trace.event_ids == [event.event_id]
    assert trace.technique_labels == ["T1105"]


def test_modify_file_emits_event_and_updates_state(actions_and_host):
    actions, host = actions_and_host
    file_path = r"C:\Temp\sample.txt"

    actions.create_file(
        host_id=host.host_id,
        file_path=file_path,
        size=100,
    )

    event = actions.modify_file(
        host_id=host.host_id,
        file_path=file_path,
        size=250,
        timestamp="2026-01-01T10:01:00Z",
        technique_labels=["T1059.001"],
    )

    assert event.event_type == "file_modification"
    assert event.extensions["file_activity"] == {
        "activity": "modification",
        "file_path": file_path,
        "file_size": 250,
    }

    assert actions.state.get_file(host.host_id, file_path).size == 250
    assert len(actions.events) == 2
    assert len(actions.trace) == 2

    trace = actions.trace[1]
    assert trace.action_type == "modify_file"
    assert trace.action_id == event.provenance.action_id
    assert trace.event_ids == [event.event_id]
    assert trace.technique_labels == ["T1059.001"]


def test_create_file_uses_unique_action_ids(actions_and_host):
    actions, host = actions_and_host

    first_event = actions.create_file(
        host_id=host.host_id,
        file_path=r"C:\Temp\first.txt",
    )

    second_event = actions.create_file(
        host_id=host.host_id,
        file_path=r"C:\Temp\second.txt",
    )

    assert first_event.provenance.action_id == "action-0001"
    assert second_event.provenance.action_id == "action-0002"


def test_create_duplicate_file_does_not_emit_event_or_trace(actions_and_host):
    actions, host = actions_and_host
    file_path = r"C:\Temp\sample.txt"

    actions.create_file(
        host_id=host.host_id,
        file_path=file_path,
    )

    with pytest.raises(SimulatorStateError, match="already exists"):
        actions.create_file(
            host_id=host.host_id,
            file_path=file_path,
        )

    assert len(actions.events) == 1
    assert len(actions.trace) == 1


def test_modify_missing_file_does_not_emit_event_or_trace(actions_and_host):
    actions, host = actions_and_host

    with pytest.raises(SimulatorStateError, match="Unknown file"):
        actions.modify_file(
            host_id=host.host_id,
            file_path=r"C:\Temp\missing.txt",
            size=50,
        )

    assert actions.events == []
    assert actions.trace == []


def test_file_action_rejects_unknown_host():
    state = SimulatorState()

    actions = SimulatorActions(
        state,
        scenario_id="file-activity-test",
        run_id="run-1",
    )

    with pytest.raises(SimulatorStateError, match="Unknown host"):
        actions.create_file(
            host_id="missing-host",
            file_path=r"C:\Temp\sample.txt",
        )

    assert actions.events == []
    assert actions.trace == []
