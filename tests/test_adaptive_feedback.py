import json
from types import SimpleNamespace

from synthetic_data.agents.adversary_agent import AdversarialProposal
from synthetic_data.agents.critic_agent import CriticResult
from synthetic_data.agents.scenario_agent import ScenarioGenerationResult
from synthetic_data.agents.workflow import GenerationWorkflowResult
from synthetic_data.evaluation.adaptive_feedback import AdaptiveFeedbackCycle
from synthetic_data.agents.planner_agent import ScenarioPlan
from synthetic_data.models.event import CanonicalEvent
from synthetic_data.storage.dataset_store import DatasetStore


def test_complete_failure_feedback_round_targets_then_retrains(tmp_path, monkeypatch):
    generated_dir = tmp_path
    final_dir = tmp_path / "final"
    monkeypatch.setitem(DatasetStore.DATASET_TYPES, "generated", generated_dir)
    monkeypatch.setitem(DatasetStore.DATASET_TYPES, "final", final_dir)
    failure = {
        "event_id": "fn-1",
        "failure_type": "false_negative",
        "actual_label": "malicious",
        "predicted_label": "benign",
        "malicious_probability": 0.1,
        "feature_summary": {"image_name": "WmiPrvSE.exe"},
    }
    proposal_data = {
        "weakness_summary": "WMI behavior is missed.",
        "scenario_requests": [{
            "scenario_request": "Simulate WMI launching a labeled child process.",
            "label": "malicious",
            "target_failure_ids": ["fn-1"],
            "hard_case": "WMI parent-child chain",
            "technique_ids": ["T1047"],
        }],
    }
    class Defender:
        def __init__(self):
            self.fit_count = 0

        def fit(self, events, labels=None):
            self.fit_count += 1
            self.events = list(events)
            return self

        def evaluate(self, events, labels=None):
            if self.fit_count == 1:
                return {
                    "macro_f1": 0.5,
                    "false_negatives": [failure],
                    "false_positives": [],
                }
            return {"macro_f1": 0.75, "false_negatives": [], "false_positives": []}

    class Adversary:
        def run(self, failures):
            assert failures == [failure]
            return AdversarialProposal(proposal_data, "fake")

    class Workflow:
        def run(self, request, **kwargs):
            assert "WMI" in request
            spec = {"scenario_id": "S_NEW"}
            return GenerationWorkflowResult(
                plan=ScenarioPlan({}, "fake"),
                generation=ScenarioGenerationResult(spec, "fake"),
                critic_history=(CriticResult("accept", (), "ok", "ok", "varied", "review labels", "fake"),),
                critic_accepted=True,
            )

    generated_events = [
        CanonicalEvent(
            event_id="generated-1",
            event_source="windows_process_creation",
            event_type="process_creation",
            timestamp="2026-01-01T10:00:00+00:00",
            host_id="WS-GENERATED",
            origin="synthetic",
            run_id="adaptive-test",
            ground_truth_labels=["T1047"],
        ),
        CanonicalEvent(
            event_id="generated-2",
            event_source="windows_process_creation",
            event_type="process_creation",
            timestamp="2026-01-01T10:00:01+00:00",
            host_id="WS-GENERATED",
            origin="synthetic",
            run_id="adaptive-test",
            ground_truth_labels=[],
        ),
    ]

    def fake_save(events, dataset_type, filename, metadata=None):
        folder = DatasetStore.DATASET_TYPES[dataset_type]
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / filename
        path.write_text(
            "\n".join(json.dumps(item.to_dict()) for item in events) + "\n",
            encoding="utf-8",
        )
        return path

    monkeypatch.setattr(DatasetStore, "save", fake_save)
    monkeypatch.setattr(DatasetStore, "update_metadata", lambda *args, **kwargs: {})

    def pipeline_runner(spec, rules, *, run_id, **kwargs):
        assert rules == []
        assert run_id.startswith("adaptive-")
        path = DatasetStore.save(
            generated_events,
            "generated",
            f"{run_id}.jsonl",
        )
        return SimpleNamespace(
            ok=True,
            saved_path=str(path),
            provenance_errors=[],
            schema_errors={},
            domain_realism_errors=[],
            domain_realism_warnings=[],
            roundtrip_ok=True,
            rules_failed_to_load=0,
            unsupported_evaluations=0,
            reference_realism_status="evaluated",
            reference_realism_errors=[],
            reference_event_count=30,
            reference_sample_adequacy="adequate",
            reference_similarity_score=0.9,
        )

    result = AdaptiveFeedbackCycle(
        Defender(),
        Adversary(),
        Workflow(),
        pipeline_runner=pipeline_runner,
        dataset_loader=lambda path: generated_events,
    ).run(
        training_events=[{"event_id": "train-1"}],
        heldout_events=[{"event_id": "heldout-1"}],
        training_labels=["benign"],
        heldout_labels=["malicious"],
    )

    assert result.adversarial_proposal == proposal_data
    assert result.generation_outcomes[0]["pipeline_ok"]
    assert result.augmented_event_count == 2
    assert result.macro_f1_delta == 0.25
    assert result.validation_report["validated"]
    assert result.final_dataset_path is not None
