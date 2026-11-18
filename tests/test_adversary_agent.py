import pytest

from synthetic_data.agents.adversary_agent import AdversaryAgent
from synthetic_data.scenarios.spec import ScenarioSpecError


FAILURE = {
    "event_id": "fn-1",
    "failure_type": "false_negative",
    "actual_label": "malicious",
    "malicious_probability": 0.12,
    "feature_summary": {
        "event_type": "process_start",
        "image_name": "WmiPrvSE.exe",
        "parent_image_name": "services.exe",
    },
}

PROPOSAL = {
    "weakness_summary": "Defender misses a WMI process chain.",
    "scenario_requests": [{
        "scenario_request": "Simulate a WMI provider launching a benignly named PowerShell process.",
        "label": "malicious",
        "target_failure_ids": ["fn-1"],
        "hard_case": "Variation in process metadata.",
        "technique_ids": ["T1047", "T1059.001"],
    }],
}


class FakeClient:
    config = type("Config", (), {"model": "fake"})()

    def __init__(self, response):
        self.response = response
        self.calls = []

    def generate_json(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def test_adversary_creates_bounded_failure_linked_requests():
    client = FakeClient(PROPOSAL)
    result = AdversaryAgent(client).run([FAILURE])
    assert result.data == PROPOSAL
    assert "fn-1" in result.data["scenario_requests"][0]["target_failure_ids"]
    prompt = client.calls[0]["user_prompt"]
    assert "WmiPrvSE.exe" in prompt
    assert "command_line" not in prompt


def test_adversary_rejects_unknown_failure_references():
    invalid = {
        **PROPOSAL,
        "scenario_requests": [{
            **PROPOSAL["scenario_requests"][0],
            "target_failure_ids": ["not-a-real-event"],
        }],
    }
    with pytest.raises(ScenarioSpecError, match="unknown failure"):
        AdversaryAgent(FakeClient(invalid)).run([FAILURE])


def test_adversary_rejects_label_conflicts():
    invalid = {
        **PROPOSAL,
        "scenario_requests": [{
            **PROPOSAL["scenario_requests"][0],
            "label": "benign",
            "technique_ids": [],
        }],
    }
    with pytest.raises(ScenarioSpecError, match="label does not match"):
        AdversaryAgent(FakeClient(invalid)).run([FAILURE])
