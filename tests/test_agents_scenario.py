import copy

import pytest

from synthetic_data.agents.scenario_agent import ScenarioAgent
from synthetic_data.scenarios.spec import ScenarioSpecError, validate_spec
from synthetic_data.pipeline.runner import run_pipeline
from synthetic_data.storage.dataset_store import DatasetStore


class FakeStructuredClient:
    config = type("Config", (), {"model": "fake-grok-model"})()

    def __init__(self, response):
        self.response = response
        self.calls = []

    def generate_json(self, **kwargs):
        self.calls.append(kwargs)
        return copy.deepcopy(self.response)


VALID_MALICIOUS = {
    "scenario_id": "S_TEST_WMI_PS",
    "description": "WMI launches PowerShell.",
    "hostname": "WS-SYNTH-001",
    "username": "synthetic_user",
    "label": "malicious",
    "steps": [
        {
            "action": "start_process",
            "process_id": "1000",
            "image": "C:\\\\Windows\\\\System32\\\\WmiPrvSE.exe",
            "command_line": "WmiPrvSE.exe",
            "original_file_name": "WmiPrvSE.exe",
            "timestamp": "2026-01-01T10:00:00+00:00",
            "technique_labels": ["T1047"],
        },
        {
            "action": "spawn_child",
            "parent_process_id": "1000",
            "process_id": "1001",
            "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
            "command_line": "powershell.exe -NoProfile",
            "original_file_name": "PowerShell.EXE",
            "timestamp": "2026-01-01T10:00:01+00:00",
            "technique_labels": ["T1059.001"],
        },
    ],
}


def test_scenario_agent_returns_spec_accepted_by_existing_validator():
    client = FakeStructuredClient(VALID_MALICIOUS)
    result = ScenarioAgent(client).run(
        "Create a WMI process that launches PowerShell.",
        scenario_id="S_TEST_WMI_PS",
        hostname="WS-SYNTH-001",
        username="synthetic_user",
        label="malicious",
        technique_labels=["T1047", "T1059.001"],
    )

    validate_spec(result.spec)
    assert result.spec == VALID_MALICIOUS
    assert result.model == "fake-grok-model"
    assert client.calls[0]["schema_name"] == "windows_scenario_spec"


def test_scenario_agent_rejects_invalid_parent_reference():
    invalid = copy.deepcopy(VALID_MALICIOUS)
    invalid["steps"][1]["parent_process_id"] = "missing-parent"
    with pytest.raises(ScenarioSpecError, match="parent_process_id"):
        ScenarioAgent(FakeStructuredClient(invalid)).run("WMI to PowerShell")


def test_scenario_agent_enforces_caller_label_mismatch():
    response = copy.deepcopy(VALID_MALICIOUS)
    response["label"] = "benign"

    result = ScenarioAgent(FakeStructuredClient(response)).run(
        "WMI to PowerShell", label="malicious"
    )

    assert result.spec["label"] == "malicious"


def test_scenario_agent_supplies_planner_labels_when_malicious_output_omits_them():
    response = copy.deepcopy(VALID_MALICIOUS)
    for step in response["steps"]:
        step.pop("technique_labels", None)

    result = ScenarioAgent(FakeStructuredClient(response)).run(
        "WMI to PowerShell",
        label="malicious",
        plan={"technique_ids": ["T1047", "T1059.001"]},
    )

    labels = {
        label
        for step in result.spec["steps"]
        for label in step.get("technique_labels", [])
    }
    assert labels == {"T1047", "T1059.001"}


def test_scenario_agent_rejects_mismatched_caller_technique_labels():
    with pytest.raises(ScenarioSpecError, match="technique labels"):
        ScenarioAgent(FakeStructuredClient(VALID_MALICIOUS)).run(
            "WMI to PowerShell", technique_labels=["T1059.001"]
        )


def test_scenario_agent_requires_non_empty_request():
    with pytest.raises(ValueError, match="non-empty"):
        ScenarioAgent(FakeStructuredClient(VALID_MALICIOUS)).run("  ")


def test_generated_benign_spec_must_not_have_technique_labels():
    response = copy.deepcopy(VALID_MALICIOUS)
    response["label"] = "benign"
    with pytest.raises(ScenarioSpecError):
        ScenarioAgent(FakeStructuredClient(response)).run(
            "A benign process activity", label="benign"
        )


def test_generated_spec_runs_through_existing_pipeline(tmp_path, monkeypatch):
    monkeypatch.setitem(DatasetStore.DATASET_TYPES, "generated", tmp_path)
    result = ScenarioAgent(FakeStructuredClient(VALID_MALICIOUS)).run(
        "Create a WMI process that launches PowerShell."
    )
    report = run_pipeline(result.spec, [], run_id="agent-integration-test")
    assert report.ok
    assert report.event_count == 2
    assert report.saved_path is not None
    assert report.provenance_errors == []
    assert report.schema_errors == {}
