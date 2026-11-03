"""Simulator actions that update state and emit canonical telemetry."""

from datetime import datetime, timezone
from typing import Optional

from synthetic_data.factory.event_factory import EventFactory
from synthetic_data.models.event import ProcessInfo, ProvenanceInfo
from synthetic_data.simulator.state import SimulatorState, SimulatedProcess


GENERATOR_VERSION = "0.1.0"


class SimulatorActionError(ValueError):
    """Raised when a simulator action cannot be completed."""


class SimulatorActions:
    """Execute simulator actions and collect their generated events."""

    def __init__(
        self,
        state: SimulatorState,
        *,
        scenario_id: str,
        run_id: str,
    ) -> None:
        if not scenario_id or not scenario_id.strip():
            raise SimulatorActionError("Scenario ID cannot be empty.")
        if not run_id or not run_id.strip():
            raise SimulatorActionError("Run ID cannot be empty.")

        self.state = state
        self.scenario_id = scenario_id
        self.run_id = run_id
        self.events = []
        self._action_counter = 0
        self._process_event_ids: dict[str, str] = {}

    def _next_action_id(self) -> str:
        """Generate a unique action ID within this scenario run."""
        self._action_counter += 1
        return f"action-{self._action_counter:04d}"

    @staticmethod
    def _timestamp(timestamp: Optional[str] = None) -> str:
        """Return a supplied timestamp or the current UTC timestamp."""
        if timestamp is not None:
            return timestamp
        return datetime.now(timezone.utc).isoformat()

    def _emit_process_event(
        self,
        process: SimulatedProcess,
        *,
        action_id: str,
        timestamp: str,
        technique_labels: Optional[list[str]] = None,
    ):
        """Create and store a canonical process-creation event."""
        parent_event_ids = []

        if process.parent_process_id is not None:
            parent_event_id = self._process_event_ids.get(
                process.parent_process_id
            )
            if parent_event_id is None:
                raise SimulatorActionError(
                    "Parent process has no corresponding creation event."
                )
            parent_event_ids.append(parent_event_id)

        user = self.state.get_user(process.user_id)

        process_info = ProcessInfo(
            process_id=process.process_id,
            process_guid=process.process_guid,
            image=process.image,
            original_file_name=process.original_file_name,
            command_line=process.command_line,
            parent_process_id=process.parent_process_id,
            parent_process_guid=process.parent_process_guid,
            user=user.username,
        )

        provenance = ProvenanceInfo(
            origin="synthetic",
            scenario_id=self.scenario_id,
            action_id=action_id,
            generator_version=GENERATOR_VERSION,
            parent_event_ids=parent_event_ids,
        )

        event = EventFactory.create_event(
            event_source="windows_process_creation",
            event_type="process_creation",
            timestamp=timestamp,
            host_id=process.host_id,
            origin="synthetic",
            run_id=self.run_id,
            process=process_info,
            provenance=provenance,
            ground_truth_labels=technique_labels or [],
        )

        self.events.append(event)
        self._process_event_ids[process.process_id] = event.event_id
        return event

    def start_process(
        self,
        *,
        host_id: str,
        user_id: str,
        image: str,
        command_line: str,
        parent_process_id: Optional[str] = None,
        process_id: Optional[str] = None,
        original_file_name: Optional[str] = None,
        timestamp: Optional[str] = None,
        technique_labels: Optional[list[str]] = None,
    ):
        """Start a process and emit its process-creation event."""
        # Validate parent event linkage before changing simulator state.
        if (
            parent_process_id is not None
            and parent_process_id not in self._process_event_ids
        ):
            raise SimulatorActionError(
                "Parent process has no corresponding creation event."
            )

        action_id = self._next_action_id()

        process = self.state.add_process(
            host_id=host_id,
            user_id=user_id,
            image=image,
            command_line=command_line,
            parent_process_id=parent_process_id,
            process_id=process_id,
            original_file_name=original_file_name,
        )

        return self._emit_process_event(
            process,
            action_id=action_id,
            timestamp=self._timestamp(timestamp),
            technique_labels=technique_labels,
        )

    def spawn_child(
        self,
        *,
        parent_process_id: str,
        image: str,
        command_line: str,
        process_id: Optional[str] = None,
        original_file_name: Optional[str] = None,
        timestamp: Optional[str] = None,
        technique_labels: Optional[list[str]] = None,
    ):
        """Spawn a child process and emit its process-creation event."""
        parent = self.state.get_process(parent_process_id)

        if parent_process_id not in self._process_event_ids:
            raise SimulatorActionError(
                "Parent process has no corresponding creation event."
            )

        return self.start_process(
            host_id=parent.host_id,
            user_id=parent.user_id,
            image=image,
            command_line=command_line,
            parent_process_id=parent_process_id,
            process_id=process_id,
            original_file_name=original_file_name,
            timestamp=timestamp,
            technique_labels=technique_labels,
        )