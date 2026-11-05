"""In-memory state for the synthetic Windows environment."""

from dataclasses import dataclass, field
from typing import Optional
from uuid import uuid4


class SimulatorStateError(ValueError):
    """Raised when a simulator state operation is invalid."""


@dataclass
class SimulatedUser:
    user_id: str
    username: str
    domain: str = "WORKGROUP"


@dataclass
class SimulatedHost:
    host_id: str
    hostname: str
    operating_system: str = "Windows"
    users: dict[str, SimulatedUser] = field(default_factory=dict)
    process_ids: set[str] = field(default_factory=set)


@dataclass
class SimulatedProcess:
    process_id: str
    host_id: str
    image: str
    command_line: str
    user_id: str
    parent_process_id: Optional[str] = None
    original_file_name: Optional[str] = None
    process_guid: str = field(default_factory=lambda: str(uuid4()))
    parent_process_guid: Optional[str] = None
    is_running: bool = True


@dataclass
class SimulatedFile:
    """A file that exists in the simulated Windows environment."""

    file_path: str
    host_id: str
    size: int = 0


class SimulatorState:
    """Tracks hosts, users, processes, and files in a simulated environment."""

    def __init__(self) -> None:
        self.hosts: dict[str, SimulatedHost] = {}
        self.users: dict[str, SimulatedUser] = {}
        self.processes: dict[str, SimulatedProcess] = {}
        self.files: dict[tuple[str, str], SimulatedFile] = {}

    def create_host(
        self,
        hostname: str,
        host_id: Optional[str] = None,
        operating_system: str = "Windows",
    ) -> SimulatedHost:
        """Create a host with a unique identifier."""
        if not hostname or not hostname.strip():
            raise SimulatorStateError("Hostname cannot be empty.")

        resolved_host_id = host_id or f"host-{uuid4()}"

        if resolved_host_id in self.hosts:
            raise SimulatorStateError(
                f"Host already exists: {resolved_host_id}"
            )

        host = SimulatedHost(
            host_id=resolved_host_id,
            hostname=hostname,
            operating_system=operating_system,
        )

        self.hosts[resolved_host_id] = host
        return host

    def create_user(
        self,
        host_id: str,
        username: str,
        user_id: Optional[str] = None,
        domain: str = "WORKGROUP",
    ) -> SimulatedUser:
        """Create a user associated with an existing host."""
        host = self.get_host(host_id)

        if not username or not username.strip():
            raise SimulatorStateError("Username cannot be empty.")

        resolved_user_id = user_id or f"user-{uuid4()}"

        if resolved_user_id in self.users:
            raise SimulatorStateError(
                f"User already exists: {resolved_user_id}"
            )

        user = SimulatedUser(
            user_id=resolved_user_id,
            username=username,
            domain=domain,
        )

        self.users[resolved_user_id] = user
        host.users[resolved_user_id] = user

        return user

    def get_host(self, host_id: str) -> SimulatedHost:
        """Return a host or raise an error if it does not exist."""
        try:
            return self.hosts[host_id]
        except KeyError as exc:
            raise SimulatorStateError(
                f"Unknown host: {host_id}"
            ) from exc

    def get_user(self, user_id: str) -> SimulatedUser:
        """Return a user or raise an error if it does not exist."""
        try:
            return self.users[user_id]
        except KeyError as exc:
            raise SimulatorStateError(
                f"Unknown user: {user_id}"
            ) from exc

    def get_process(self, process_id: str) -> SimulatedProcess:
        """Return a process or raise an error if it does not exist."""
        try:
            return self.processes[process_id]
        except KeyError as exc:
            raise SimulatorStateError(
                f"Unknown process: {process_id}"
            ) from exc

    def add_process(
        self,
        host_id: str,
        user_id: str,
        image: str,
        command_line: str,
        parent_process_id: Optional[str] = None,
        process_id: Optional[str] = None,
        original_file_name: Optional[str] = None,
    ) -> SimulatedProcess:
        """Add a process after validating its host, user, and parent."""
        host = self.get_host(host_id)
        user = self.get_user(user_id)

        if user_id not in host.users:
            raise SimulatorStateError(
                f"User {user_id} does not belong to host {host_id}."
            )

        if not image or not image.strip():
            raise SimulatorStateError("Process image cannot be empty.")

        if not command_line or not command_line.strip():
            raise SimulatorStateError("Command line cannot be empty.")

        parent = None

        if parent_process_id is not None:
            parent = self.get_process(parent_process_id)

            if parent.host_id != host_id:
                raise SimulatorStateError(
                    "Parent process must belong to the same host."
                )

            if not parent.is_running:
                raise SimulatorStateError(
                    "Cannot spawn a child from a terminated process."
                )

        resolved_process_id = process_id or str(uuid4())

        if resolved_process_id in self.processes:
            raise SimulatorStateError(
                f"Process ID already exists: {resolved_process_id}"
            )

        process = SimulatedProcess(
            process_id=resolved_process_id,
            host_id=host_id,
            image=image,
            command_line=command_line,
            user_id=user_id,
            parent_process_id=parent_process_id,
            original_file_name=original_file_name,
            parent_process_guid=parent.process_guid if parent else None,
        )

        self.processes[resolved_process_id] = process
        host.process_ids.add(resolved_process_id)

        return process

    def terminate_process(self, process_id: str) -> SimulatedProcess:
        """Mark a running process as terminated."""
        process = self.get_process(process_id)

        if not process.is_running:
            raise SimulatorStateError(
                f"Process is already terminated: {process_id}"
            )

        process.is_running = False
        return process

    def get_running_processes(
        self,
        host_id: Optional[str] = None,
    ) -> list[SimulatedProcess]:
        """Return running processes, optionally filtered by host."""
        if host_id is not None:
            self.get_host(host_id)

        return [
            process
            for process in self.processes.values()
            if process.is_running
            and (host_id is None or process.host_id == host_id)
        ]

    def get_children(
        self,
        process_id: str,
    ) -> list[SimulatedProcess]:
        """Return direct child processes of a given process."""
        self.get_process(process_id)

        return [
            process
            for process in self.processes.values()
            if process.parent_process_id == process_id
        ]

    def get_file(
        self,
        host_id: str,
        file_path: str,
    ) -> SimulatedFile:
        """Return a file or raise an error if it does not exist."""
        self.get_host(host_id)

        key = (host_id, file_path)

        try:
            return self.files[key]
        except KeyError as exc:
            raise SimulatorStateError(
                f"Unknown file on host {host_id}: {file_path}"
            ) from exc

    def create_file(
        self,
        host_id: str,
        file_path: str,
        size: int = 0,
    ) -> SimulatedFile:
        """Create a file on an existing host."""
        self.get_host(host_id)

        if not file_path or not file_path.strip():
            raise SimulatorStateError("File path cannot be empty.")

        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise SimulatorStateError(
                "File size must be a non-negative integer."
            )

        key = (host_id, file_path)

        if key in self.files:
            raise SimulatorStateError(
                f"File already exists on host {host_id}: {file_path}"
            )

        simulated_file = SimulatedFile(
            file_path=file_path,
            host_id=host_id,
            size=size,
        )

        self.files[key] = simulated_file
        return simulated_file

    def modify_file(
        self,
        host_id: str,
        file_path: str,
        size: Optional[int] = None,
    ) -> SimulatedFile:
        """Modify an existing file's size."""
        simulated_file = self.get_file(host_id, file_path)

        if size is not None:
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
            ):
                raise SimulatorStateError(
                    "File size must be a non-negative integer."
                )

            simulated_file.size = size

        return simulated_file
