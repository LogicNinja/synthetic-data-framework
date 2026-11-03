
from synthetic_data.simulator.scenario_runner import ScenarioRunner


def test_runner_executes_scenario_and_collects_events():
    runner = ScenarioRunner()

    def scenario(context):
        context.actions.start_process(
            host_id=context.host.host_id,
            user_id=context.user.user_id,
            image="powershell.exe",
            command_line="powershell.exe -NoProfile",
            technique_labels=["T1059.001"],
        )

    result = runner.run(
        scenario_id="S1",
        run_id="run-001",
        hostname="WIN-TEST",
        username="testuser",
        scenario=scenario,
    )

    assert result.scenario_id == "S1"
    assert result.run_id == "run-001"
    assert len(result.events) == 1

    event = result.events[0]
    assert event.event_type == "process_creation"
    assert event.ground_truth_labels == ["T1059.001"]


def test_runner_returns_empty_events_for_empty_scenario():
    runner = ScenarioRunner()

    result = runner.run(
        scenario_id="S1",
        run_id="run-002",
        hostname="WIN-TEST",
        username="testuser",
        scenario=lambda context: None,
    )

    assert result.events == []


def test_runner_collects_parent_and_child_events():
    runner = ScenarioRunner()

    def scenario(context):
        parent = context.actions.start_process(
            host_id=context.host.host_id,
            user_id=context.user.user_id,
            image="wscript.exe",
            command_line="wscript.exe script.js",
        )

        context.actions.spawn_child(
            parent_process_id=parent.process.process_id,
            image="cmd.exe",
            command_line="cmd.exe /c whoami",
        )

    result = runner.run(
        scenario_id="S5",
        run_id="run-003",
        hostname="WIN-TEST",
        username="testuser",
        scenario=scenario,
    )

    assert len(result.events) == 2
