import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from synthetic_data.models.event import CanonicalEvent, ProcessInfo, ProvenanceInfo
from synthetic_data.pipeline.end_to_end import run_end_to_end, validate_generation_request
from synthetic_data.serialization.event_serializer import read_jsonl
from synthetic_data.storage.dataset_store import DatasetStore
from synthetic_data.validation.four_layer import ValidationCriteria


def _request():
    return {
        "attack_type": "process execution",
        "scenario": "PowerShell launched by WMI and benign look-alikes",
        "difficulty": "medium",
        "scenario_count": 4,
        "labels": ["malicious", "benign", "malicious", "benign"],
        "constraints": {"scenario_id_prefix": "TEST", "required_event_types": ["process_creation"]},
    }


def _event(event_id, scenario_id, run_id, label):
    return CanonicalEvent(
        event_id=event_id,
        event_source="windows_process_creation",
        event_type="process_creation",
        timestamp=f"2026-01-01T00:00:{sum(ord(c) for c in scenario_id) % 60:02d}+00:00",
        host_id="WS-TEST",
        origin="synthetic",
        run_id=run_id,
        process=ProcessInfo(
            image="powershell.exe" if label == "malicious" else "notepad.exe",
            parent_image="WmiPrvSE.exe" if label == "malicious" else "explorer.exe",
            command_line="powershell.exe -NoProfile" if label == "malicious" else "notepad.exe",
        ),
        provenance=ProvenanceInfo(scenario_id=scenario_id, action_id=f"action-{event_id}"),
        ground_truth_labels=["T1059.001"] if label == "malicious" else [],
    )


def _eval_data(prefix):
    labels = ["benign", "malicious", "benign", "malicious"]
    return [
        _event(f"{prefix}-{index}", f"{prefix}-scenario-{index}", prefix, label)
        for index, label in enumerate(labels)
    ]


def test_structured_request_requires_labels_for_each_scenario_and_both_classes():
    request = _request()
    validate_generation_request(request)
    with pytest.raises(ValueError, match="Invalid generation request"):
        validate_generation_request({**request, "labels": ["benign"]})


def test_end_to_end_orchestrator_publishes_validated_telemetry_and_chat_splits(tmp_path, monkeypatch):
    class Workflow:
        def run(self, prompt, **kwargs):
            index = len(calls) + 1
            calls.append((prompt, kwargs))
            label = kwargs["scenario_constraints"]["label"]
            spec = {"scenario_id": kwargs["scenario_constraints"]["scenario_id"], "label": label}
            return SimpleNamespace(
                critic_accepted=True,
                generation=SimpleNamespace(spec=spec),
                quality_report={"samples_evaluated": 1, "accepted": 1, "rejected": 0, "rejection_reasons": []},
            )

    calls = []

    def fake_pipeline(spec, rules, *, run_id, **kwargs):
        event = _event(f"generated-{run_id}", spec["scenario_id"], run_id, spec["label"])
        path = DatasetStore.save([event], "generated", f"{spec['scenario_id']}.jsonl")
        return SimpleNamespace(
            ok=True,
            saved_path=str(path),
            provenance_errors=[],
            schema_errors={},
            domain_realism_errors=[],
            domain_realism_warnings=[],
            rules_failed_to_load=0,
            unsupported_evaluations=0,
            roundtrip_ok=True,
        )

    reference = [
        _event(f"ref-{i}", f"ref-scenario-{i}", "ref-run", label)
        for i, label in enumerate(["benign", "malicious", "benign", "malicious"])
    ]
    criteria = ValidationCriteria(
        minimum_reference_sample_size=1,
        minimum_reference_similarity=0.0,
        maximum_unsupported_sigma_evaluations=0,
        minimum_macro_f1=0.0,
        minimum_macro_f1_delta=-1.0,
    )
    result = run_end_to_end(
        _request(),
        workflow=Workflow(),
        reference_events=reference,
        training_events=_eval_data("train"),
        heldout_events=_eval_data("heldout"),
        output_root=tmp_path / "final",
        validation_criteria=criteria,
        pipeline_runner=fake_pipeline,
    )
    assert result.complete, json.dumps({"validation": result.report["validation_report"], "error": result.report["utility_error"], "fine": result.report["fine_tuning_report"]}, indent=2)
    assert len(calls) == 4
    assert Path(result.final_telemetry_path).is_file()
    assert set(result.fine_tuning_paths) == {"train", "validation", "test"}
    assert all(Path(path).is_file() for path in result.fine_tuning_paths.values())
    manifest = json.loads(Path(result.final_telemetry_path + ".meta.json").read_text(encoding="utf-8"))
    assert manifest["metadata"]["validated"] is True
    assert len(read_jsonl(result.final_telemetry_path)) == 4
    assert (tmp_path / "final" / "reports" / "quality_report.json").exists()


def test_end_to_end_does_not_publish_an_undersized_dataset_but_keeps_the_audit_record(tmp_path):
    class Workflow:
        def run(self, prompt, **kwargs):
            constraints = kwargs["scenario_constraints"]
            return SimpleNamespace(
                critic_accepted=True,
                generation=SimpleNamespace(spec={
                    "scenario_id": constraints["scenario_id"],
                    "label": constraints["label"],
                }),
                quality_report={"rejection_reasons": []},
            )

    def fake_pipeline(spec, rules, *, run_id, **kwargs):
        event = _event(f"generated-{run_id}", spec["scenario_id"], run_id, spec["label"])
        path = DatasetStore.save([event], "generated", f"{spec['scenario_id']}.jsonl")
        return SimpleNamespace(
            ok=True,
            saved_path=str(path),
            provenance_errors=[],
            schema_errors={},
            domain_realism_errors=[],
            domain_realism_warnings=[],
            rules_failed_to_load=0,
            unsupported_evaluations=0,
            roundtrip_ok=True,
        )

    criteria = ValidationCriteria(
        minimum_reference_sample_size=1,
        minimum_reference_similarity=0.0,
        maximum_unsupported_sigma_evaluations=0,
        minimum_macro_f1=0.0,
        minimum_macro_f1_delta=-1.0,
    )
    reference = _eval_data("reference")
    result = run_end_to_end(
        _request(),
        workflow=Workflow(),
        reference_events=reference,
        training_events=_eval_data("train"),
        heldout_events=_eval_data("heldout"),
        output_root=tmp_path / "final",
        validation_criteria=criteria,
        pipeline_runner=fake_pipeline,
        minimum_final_event_count=5,
    )

    assert not result.complete
    assert result.final_telemetry_path is None
    assert result.report["validated_event_count"] == 4
    assert not result.report["minimum_event_count_met"]
    outcomes = json.loads((tmp_path / "final" / "reports" / "all_scenario_outcomes.json").read_text(encoding="utf-8"))
    assert len(outcomes) == 4
    assert all("generated_spec" in outcome for outcome in outcomes)
