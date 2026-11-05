import pytest

from synthetic_data.simulator.state import (
    SimulatorState,
    SimulatorStateError,
)


@pytest.fixture
def state_with_host():
    state = SimulatorState()
    host = state.create_host("TEST-PC", host_id="host-1")
    return state, host


def test_create_file(state_with_host):
    state, host = state_with_host

    simulated_file = state.create_file(
        host_id=host.host_id,
        file_path=r"C:\Temp\sample.txt",
        size=100,
    )

    assert simulated_file.file_path == r"C:\Temp\sample.txt"
    assert simulated_file.host_id == host.host_id
    assert simulated_file.size == 100
    assert state.get_file(host.host_id, r"C:\Temp\sample.txt") is simulated_file


def test_create_file_rejects_duplicate(state_with_host):
    state, host = state_with_host
    file_path = r"C:\Temp\sample.txt"

    state.create_file(host.host_id, file_path)

    with pytest.raises(SimulatorStateError, match="already exists"):
        state.create_file(host.host_id, file_path)


def test_create_file_rejects_empty_path(state_with_host):
    state, host = state_with_host

    with pytest.raises(SimulatorStateError, match="File path cannot be empty"):
        state.create_file(host.host_id, "   ")


def test_create_file_rejects_negative_size(state_with_host):
    state, host = state_with_host

    with pytest.raises(SimulatorStateError, match="non-negative integer"):
        state.create_file(host.host_id, r"C:\Temp\sample.txt", size=-1)


def test_modify_file_updates_size(state_with_host):
    state, host = state_with_host
    file_path = r"C:\Temp\sample.txt"

    state.create_file(host.host_id, file_path, size=100)

    modified_file = state.modify_file(
        host.host_id,
        file_path,
        size=250,
    )

    assert modified_file.size == 250
    assert state.get_file(host.host_id, file_path).size == 250


def test_modify_file_rejects_missing_file(state_with_host):
    state, host = state_with_host

    with pytest.raises(SimulatorStateError, match="Unknown file"):
        state.modify_file(host.host_id, r"C:\Temp\missing.txt", size=50)


def test_same_file_path_can_exist_on_different_hosts():
    state = SimulatorState()
    host_1 = state.create_host("TEST-PC-1", host_id="host-1")
    host_2 = state.create_host("TEST-PC-2", host_id="host-2")
    file_path = r"C:\Temp\sample.txt"

    file_1 = state.create_file(host_1.host_id, file_path, size=100)
    file_2 = state.create_file(host_2.host_id, file_path, size=200)

    assert file_1.size == 100
    assert file_2.size == 200
    assert state.get_file(host_1.host_id, file_path) is file_1
    assert state.get_file(host_2.host_id, file_path) is file_2
