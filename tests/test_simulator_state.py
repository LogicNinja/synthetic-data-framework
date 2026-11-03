import pytest

from synthetic_data.simulator.state import (
    SimulatorState,
    SimulatorStateError,
)


@pytest.fixture
def state_with_host_and_user():
    state = SimulatorState()
    host = state.create_host("WIN-TEST", host_id="host-1")
    user = state.create_user(
        host_id=host.host_id,
        username="analyst",
        user_id="user-1",
    )
    return state, host, user


def test_create_host_and_user(state_with_host_and_user):
    state, host, user = state_with_host_and_user

    assert state.get_host(host.host_id) is host
    assert state.get_user(user.user_id) is user
    assert user.user_id in host.users


def test_add_process(state_with_host_and_user):
    state, host, user = state_with_host_and_user

    process = state.add_process(
        host_id=host.host_id,
        user_id=user.user_id,
        image=r"C:\Windows\System32\notepad.exe",
        command_line="notepad.exe",
        process_id="proc-1",
    )

    assert state.get_process("proc-1") is process
    assert process.is_running
    assert process.parent_process_id is None


def test_child_requires_existing_parent(state_with_host_and_user):
    state, host, user = state_with_host_and_user

    with pytest.raises(SimulatorStateError):
        state.add_process(
            host_id=host.host_id,
            user_id=user.user_id,
            image="child.exe",
            command_line="child.exe",
            parent_process_id="missing-parent",
        )


def test_child_process_relationship(state_with_host_and_user):
    state, host, user = state_with_host_and_user

    parent = state.add_process(
        host_id=host.host_id,
        user_id=user.user_id,
        image="parent.exe",
        command_line="parent.exe",
        process_id="parent-1",
    )

    child = state.add_process(
        host_id=host.host_id,
        user_id=user.user_id,
        image="child.exe",
        command_line="child.exe",
        parent_process_id=parent.process_id,
        process_id="child-1",
    )

    assert child.parent_process_id == parent.process_id
    assert child.parent_process_guid == parent.process_guid
    assert state.get_children(parent.process_id) == [child]


def test_process_cannot_use_parent_from_another_host():
    state = SimulatorState()

    host1 = state.create_host("WIN-1", host_id="host-1")
    user1 = state.create_user(host1.host_id, "user1", user_id="user-1")

    host2 = state.create_host("WIN-2", host_id="host-2")
    user2 = state.create_user(host2.host_id, "user2", user_id="user-2")

    parent = state.add_process(
        host_id=host1.host_id,
        user_id=user1.user_id,
        image="parent.exe",
        command_line="parent.exe",
        process_id="parent-1",
    )

    with pytest.raises(SimulatorStateError):
        state.add_process(
            host_id=host2.host_id,
            user_id=user2.user_id,
            image="child.exe",
            command_line="child.exe",
            parent_process_id=parent.process_id,
        )


def test_terminated_process_cannot_spawn_child(state_with_host_and_user):
    state, host, user = state_with_host_and_user

    parent = state.add_process(
        host_id=host.host_id,
        user_id=user.user_id,
        image="parent.exe",
        command_line="parent.exe",
        process_id="parent-1",
    )

    state.terminate_process(parent.process_id)

    with pytest.raises(SimulatorStateError):
        state.add_process(
            host_id=host.host_id,
            user_id=user.user_id,
            image="child.exe",
            command_line="child.exe",
            parent_process_id=parent.process_id,
        )


def test_get_running_processes_filters_by_host():
    state = SimulatorState()

    host1 = state.create_host("WIN-1", host_id="host-1")
    user1 = state.create_user(host1.host_id, "user1", user_id="user-1")

    host2 = state.create_host("WIN-2", host_id="host-2")
    user2 = state.create_user(host2.host_id, "user2", user_id="user-2")

    state.add_process(
        host1.host_id, user1.user_id, "one.exe", "one.exe",
        process_id="proc-1",
    )
    state.add_process(
        host2.host_id, user2.user_id, "two.exe", "two.exe",
        process_id="proc-2",
    )

    assert len(state.get_running_processes()) == 2
    assert len(state.get_running_processes("host-1")) == 1


def test_duplicate_ids_are_rejected(state_with_host_and_user):
    state, host, user = state_with_host_and_user

    state.add_process(
        host.host_id, user.user_id, "one.exe", "one.exe",
        process_id="proc-1",
    )

    with pytest.raises(SimulatorStateError):
        state.add_process(
            host.host_id, user.user_id, "two.exe", "two.exe",
            process_id="proc-1",
        )
