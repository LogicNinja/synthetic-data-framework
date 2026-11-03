import pytest

from synthetic_data.simulator.actions import (
    SimulatorActions,
    SimulatorActionError,
)
from synthetic_data.simulator.state import SimulatorState


@pytest.fixture
def action_environment():
    state = SimulatorState()

    host = state.create_host(
        "WIN-TEST",
        host_id="host-1",
    )

    user = state.create_user(
        host_id=host.host_id,
        username="analyst",
        user_id="user-1",
    )

    actions = SimulatorActions(
        state,
        scenario_id="scenario-1",
        run_id="run-1",
    )

    return state, host, user, actions


def test_start_process_updates_state_and_emits_event(action_environment):
    state, host, user, actions = action_environment

    event = actions.start_process(
        host_id=host.host_id,
        user_id=user.user_id,
        image=r"C:\Windows\System32\notepad.exe",
        command_line="notepad.exe",
        process_id="proc-1",
        timestamp="2026-01-01T10:00:00Z",
    )

    process = state.get_process("proc-1")

    assert process.is_running
    assert event.event_type == "process_creation"
    assert event.event_source == "windows_process_creation"
    assert event.host_id == host.host_id
    assert event.run_id == "run-1"
    assert event.origin == "synthetic"
    assert event.process.process_id == "proc-1"
    assert event.process.image.endswith("notepad.exe")
    assert len(actions.events) == 1


def test_event_contains_scenario_and_action_provenance(action_environment):
    _, host, user, actions = action_environment

    event = actions.start_process(
        host_id=host.host_id,
        user_id=user.user_id,
        image="powershell.exe",
        command_line="powershell.exe",
        process_id="proc-1",
        timestamp="2026-01-01T10:00:00Z",
        technique_labels=["T1059.001"],
    )

    assert event.provenance.scenario_id == "scenario-1"
    assert event.provenance.action_id == "action-0001"
    assert event.provenance.origin == "synthetic"
    assert event.ground_truth_labels == ["T1059.001"]


def test_spawn_child_emits_parent_relationship(action_environment):
    state, host, user, actions = action_environment

    parent_event = actions.start_process(
        host_id=host.host_id,
        user_id=user.user_id,
        image="WmiPrvSE.exe",
        command_line="WmiPrvSE.exe",
        process_id="parent-1",
        timestamp="2026-01-01T10:00:00Z",
    )

    child_event = actions.spawn_child(
        parent_process_id="parent-1",
        image="powershell.exe",
        command_line="powershell.exe",
        process_id="child-1",
        timestamp="2026-01-01T10:00:01Z",
        technique_labels=["T1059.001"],
    )

    child = state.get_process("child-1")

    assert child.parent_process_id == "parent-1"
    assert child_event.process.parent_process_id == "parent-1"
    assert child_event.process.parent_process_guid == (
        state.get_process("parent-1").process_guid
    )
    assert child_event.provenance.parent_event_ids == [
        parent_event.event_id
    ]
    assert child_event.provenance.action_id == "action-0002"
    assert len(actions.events) == 2


def test_spawn_child_requires_parent_creation_event(action_environment):
    _, _, _, actions = action_environment

    # A process created directly through state has no emitted event.
    host = actions.state.get_host("host-1")
    user = actions.state.get_user("user-1")

    actions.state.add_process(
        host_id=host.host_id,
        user_id=user.user_id,
        image="parent.exe",
        command_line="parent.exe",
        process_id="parent-1",
    )

    with pytest.raises(SimulatorActionError):
        actions.spawn_child(
            parent_process_id="parent-1",
            image="child.exe",
            command_line="child.exe",
            process_id="child-1",
            timestamp="2026-01-01T10:00:01Z",
        )


def test_action_ids_increase(action_environment):
    _, host, user, actions = action_environment

    first = actions.start_process(
        host_id=host.host_id,
        user_id=user.user_id,
        image="one.exe",
        command_line="one.exe",
        process_id="proc-1",
        timestamp="2026-01-01T10:00:00Z",
    )

    second = actions.start_process(
        host_id=host.host_id,
        user_id=user.user_id,
        image="two.exe",
        command_line="two.exe",
        process_id="proc-2",
        timestamp="2026-01-01T10:00:01Z",
    )

    assert first.provenance.action_id == "action-0001"
    assert second.provenance.action_id == "action-0002"


def test_invalid_process_action_does_not_emit_event(action_environment):
    _, _, user, actions = action_environment

    with pytest.raises(ValueError):
        actions.start_process(
            host_id="missing-host",
            user_id=user.user_id,
            image="bad.exe",
            command_line="bad.exe",
        )

    assert actions.events == []