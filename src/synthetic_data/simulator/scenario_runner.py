"""Reusable runner for synthetic attack scenarios."""

from dataclasses import dataclass
from typing import Callable

from synthetic_data.simulator.actions import SimulatorActions
from synthetic_data.simulator.state import (
    SimulatorState,
    SimulatedHost,
    SimulatedUser,
)


@dataclass
class ScenarioResult:
    """Result produced after executing a scenario."""

    scenario_id: str
    run_id: str
    host: SimulatedHost
    user: SimulatedUser
    events: list


@dataclass
class ScenarioContext:
    """Context made available to a scenario implementation."""

    state: SimulatorState
    actions: SimulatorActions
    host: SimulatedHost
    user: SimulatedUser


ScenarioFunction = Callable[[ScenarioContext], None]


class ScenarioRunner:
    """Create an environment and execute a scenario."""

    def run(
        self,
        *,
        scenario_id: str,
        run_id: str,
        hostname: str,
        username: str,
        scenario: ScenarioFunction,
    ) -> ScenarioResult:
        """Execute a scenario and return its generated events."""

        state = SimulatorState()
        host = state.create_host(hostname=hostname)
        user = state.create_user(
            host_id=host.host_id,
            username=username,
        )

        actions = SimulatorActions(
            state,
            scenario_id=scenario_id,
            run_id=run_id,
        )

        context = ScenarioContext(
            state=state,
            actions=actions,
            host=host,
            user=user,
        )

        scenario(context)

        return ScenarioResult(
            scenario_id=scenario_id,
            run_id=run_id,
            host=host,
            user=user,
            events=actions.events.copy(),
        )
