import json
from pathlib import Path

import pytest

from synthetic_data.agents.critic_agent import CriticAgent, CriticResult
from synthetic_data.agents.planner_agent import PlannerAgent
from synthetic_data.agents.scenario_agent import ScenarioGenerationResult
from synthetic_data.agents.workflow import GenerationWorkflow


PLAN = {
    "objective": "Cover WMI to PowerShell process ancestry.",
    "label": "malicious",
    "technique_ids": ["T1047", "T1059.001"],
    "coverage_gaps": ["WMI parent-child events"],
    "hard_cases": ["preserve parent image"],
    "generation_budget": 1,
    "scenario_request": "Simulate WMI starting PowerShell.",
    "rationale": "The request explicitly describes this simulated chain.",
}

VALID_SPEC = {
    "scenario_id": "S_TEST_WMI_PS",
    "hostname": "WS-SYNTH-001",
    "username": "synthetic_user",
    "label": "malicious",
    "steps": [
        {
            "action": "start_process",
            "process_id": "1000",
            "image": "C:\\Windows\\System32\\WmiPrvSE.exe",
            "command_line": "WmiPrvSE.exe",
            "original_file_name": "WmiPrvSE.exe",
            "timestamp": "2026-01-01T10:00:00+00:00",
            "technique_labels": ["T1047"],
        },
        {
            "action": "spawn_child",
            "parent_process_id": "1000",
            "process_id": "1001",
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -NoProfile",
            "original_file_name": "PowerShell.EXE",
            "timestamp": "2026-01-01T10:00:01+00:00",
            "technique_labels": ["T1059.001"],
        },
    ],
}

VALID_REVIEW = {
    "decision": "accept",
    "findings": [],
    "coverage_assessment": "Matches requested WMI child-process chain.",
    "realism_assessment": "Plausible simulated process ancestry.",
    "diversity_assessment": "Varies from supplied prior cases.",
    "accuracy_assessment": "Claims are supported by the scenario plan.",
    "consistency_assessment": "Actions and labels are internally consistent.",
    "completeness_assessment": "Required scenario fields are present.",
    "rubric_scores": {
        "accuracy": 4,
        "diversity": 4,
        "realism": 4,
        "consistency": 5,
        "completeness": 5,
    },
    "label_caveat": "ATT&CK labels require domain review.",
}


class FakeClient:
    config = type("Config", (), {"model": "fake"})()

    def __init__(self, result):
        self.result = result
        self.calls = []

    def generate_json(self, **kwargs):
        self.calls.append(kwargs)
        return self.result


def test_planner_schema_validates_plan_and_passes_requested_coverage():
    client = FakeClient(PLAN)
    result = PlannerAgent(client).run(
        "Simulate WMI starting PowerShell.",
        coverage_gaps=["WMI parent-child events"],
    )
    assert result.data == PLAN
    assert "WMI parent-child events" in client.calls[0]["user_prompt"]


def test_planner_rejects_malicious_plan_without_technique_ids():
    invalid = {**PLAN, "technique_ids": []}
    with pytest.raises(ValueError, match="invalid output"):
        PlannerAgent(FakeClient(invalid)).run("malicious behavior")


def test_planner_repairs_benign_label_when_techniques_are_present():
    inconsistent = {**PLAN, "label": "benign"}

    result = PlannerAgent(FakeClient(inconsistent)).run("Simulate WMI starting PowerShell.")

    assert result.data["label"] == "malicious"
    assert result.data["technique_ids"] == ["T1047", "T1059.001"]


def test_critic_runs_deterministic_checks_before_model_review():
    invalid = {**VALID_SPEC, "steps": []}
    client = FakeClient(VALID_REVIEW)
    result = CriticAgent(client).run(invalid, request="anything")
    assert result.decision == "reject"
    assert result.structural_errors
    assert client.calls == []


def test_critic_changes_accept_to_revise_for_high_severity_finding():
    review = {
        **VALID_REVIEW,
        "findings": [{
            "severity": "high",
            "issue": "The requested action is missing.",
            "recommendation": "Add the requested action.",
        }],
    }
    result = CriticAgent(FakeClient(review)).run(
        VALID_SPEC, request="Simulate the requested behavior"
    )
    assert result.decision == "revise"
    assert not result.accepted


def test_critic_ignores_generic_findings_contradicted_by_valid_draft():
    generic_review = {
        **VALID_REVIEW,
        "decision": "revise",
        "rubric_scores": {key: 1 for key in VALID_REVIEW["rubric_scores"]},
        "findings": [
            {"severity": "high", "issue": "Missing timestamp for the first step", "recommendation": "Add a timestamp."},
            {"severity": "medium", "issue": "Lack of diversity in the scenario", "recommendation": "Add variety."},
            {"severity": "high", "issue": "Missing parent-child relationship between the processes", "recommendation": "Add a parent."},
        ],
    }

    result = CriticAgent(FakeClient(generic_review)).run(
        VALID_SPEC,
        request="Create a WMI child process scenario.",
        plan=PLAN,
        existing_scenarios=[],
    )

    assert result.accepted
    assert result.findings == ()


def test_critic_flags_near_duplicate_against_existing_scenarios():
    result = CriticAgent(FakeClient(VALID_REVIEW)).run(
        VALID_SPEC,
        request="Simulate a WMI child process",
        existing_scenarios=[{**VALID_SPEC, "scenario_id": "OLDER"}],
    )
    assert result.decision == "revise"
    assert "near-duplicate" in result.diversity_assessment
    assert result.findings[-1]["severity"] == "high"


def test_workflow_retries_revisions_and_stops_after_acceptance():
    class Planner:
        def run(self, *args, **kwargs):
            conflicting_plan = {
                **PLAN,
                "label": "benign",
                "technique_ids": [],
                "scenario_request": "Create benign file activity.",
            }
            return type("Plan", (), {"data": conflicting_plan, "model": "planner"})()

    class Scenario:
        def __init__(self):
            self.feedback = []
            self.requests = []
            self.techniques = []

        def run(self, request, **kwargs):
            self.requests.append(request)
            self.feedback.append(kwargs.get("feedback"))
            self.techniques.append(kwargs.get("technique_labels"))
            return ScenarioGenerationResult(VALID_SPEC, "scenario")

    class Critic:
        def __init__(self):
            self.count = 0

        def run(self, spec, **kwargs):
            self.count += 1
            if self.count == 1:
                return CriticResult(
                    "reject",
                    ({"severity": "medium", "issue": "Clarify parent.", "recommendation": "Name parent."},),
                    "Partial.", "Plausible.", "Varied.", "Review labels.", "critic",
                )
            return CriticResult(
                "accept", (), "Covered.", "Plausible.", "Varied.", "Review labels.", "critic"
            )

    scenario, critic = Scenario(), Critic()
    result = GenerationWorkflow(Planner(), scenario, critic).run(
        "WMI to PowerShell",
        scenario_constraints={"label": "malicious", "technique_labels": ["T1059.001"]},
    )
    assert result.critic_accepted
    assert len(result.critic_history) == 2
    assert scenario.feedback[0] is None
    assert "Name parent" in scenario.feedback[1]
    assert scenario.requests == ["WMI to PowerShell", "WMI to PowerShell"]
    assert scenario.techniques[0] == ["T1059.001"]
    assert result.quality_report["samples_evaluated"] == 2
    assert result.quality_report["accepted"] == 1
    assert result.quality_report["rejected"] == 1
    assert result.quality_report["acceptance_rate"] == 0.5


def test_workflow_treats_planner_techniques_as_guidance_when_not_pinned():
    class Planner:
        def run(self, *args, **kwargs):
            return type("Plan", (), {"data": PLAN, "model": "planner"})()

    class Scenario:
        def run(self, request, **kwargs):
            assert kwargs["label"] == "malicious"
            assert kwargs["technique_labels"] is None
            return ScenarioGenerationResult(VALID_SPEC, "scenario")

    class Critic:
        def run(self, spec, **kwargs):
            return CriticResult("accept", (), "Covered.", "Plausible.", "Varied.", "Review labels.", "critic")

    result = GenerationWorkflow(Planner(), Scenario(), Critic()).run("WMI to PowerShell")

    assert result.critic_accepted

