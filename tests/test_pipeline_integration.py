import copy

import pytest

from synthetic_data.pipeline.runner import (
    DEFAULT_RULE_DIR,
    load_rules,
    run_pipeline,
)
from synthetic_data.scenarios.spec import (
    ScenarioSpecError,
    load_builtin_spec,
    validate_spec,
)
from synthetic_data.storage.dataset_store import DatasetStore

WMI_POWERSHELL_RULE = {
    "title": "WMI Spawning PowerShell",
    "id": "test-wmi-powershell",
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {
        "selection": {
            "ParentImage|endswith": "\\WmiPrvSE.exe",
            "Image|endswith": "\\powershell.exe",
        },
        "condition": "selection",
    },
}

NON_MATCHING_RULE = {
    "title": "Cmd Execution",
    "id": "test-cmd",
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {
        "selection": {"Image|endswith": "\\cmd.exe"},
        "condition": "selection",
    },
}

# Two modifiers on one field: the evaluator rejects it, the pipeline must not crash.
UNSUPPORTED_RULE = {
    "title": "Unsupported Modifier",
    "id": "test-unsupported",
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {
        "selection": {"CommandLine|contains|all": ["a", "b"]},
        "condition": "selection",
    },
}

RULES = [WMI_POWERSHELL_RULE, NON_MATCHING_RULE, UNSUPPORTED_RULE]

BENIGN_SPEC = {
    "scenario_id": "B1_NOTEPAD",
    "hostname": "WS-002",
    "username": "bob",
    "label": "benign",
    "steps": [
        {
            "action": "start_process",
            "process_id": "2000",
            "image": "C:\\Windows\\System32\\notepad.exe",
            "command_line": "notepad.exe notes.txt",
            "original_file_name": "NOTEPAD.EXE",
            "timestamp": "2026-01-01T09:00:00+00:00",
        }
    ],
}


@pytest.fixture
def generated_dir(tmp_path, monkeypatch):
    monkeypatch.setitem(DatasetStore.DATASET_TYPES, "generated", tmp_path)
    return tmp_path


def test_s2_pipeline_end_to_end(generated_dir):
    report = run_pipeline(
        load_builtin_spec("s2_wmi_powershell"),
        RULES,
        run_id="test-run",
    )

    assert report.schema_errors == {}
    assert report.event_count == 2
    assert report.ok

    # Only the PowerShell event (child of WmiPrvSE) should match.
    assert len(report.detections) == 1
    assert list(report.detections.values())[0] == ["test-wmi-powershell"]

    # The unsupported rule is skipped once per event, not fatal.
    assert report.unsupported_evaluations == 2

    assert (generated_dir / "s2_wmi_powershell_test-run.jsonl").exists()


def test_reloaded_events_keep_detections(generated_dir):
    run_pipeline(
        load_builtin_spec("s2_wmi_powershell"),
        RULES,
        run_id="test-run",
    )

    reloaded = DatasetStore.load("generated", "s2_wmi_powershell_test-run.jsonl")

    assert len(reloaded) == 2
    assert sum(len(event.detection_results) for event in reloaded) == 1


def test_child_event_carries_parent_image_and_command_line(generated_dir):
    run_pipeline(
        load_builtin_spec("s2_wmi_powershell"),
        RULES,
        run_id="test-run",
    )

    child = DatasetStore.load("generated", "s2_wmi_powershell_test-run.jsonl")[1]

    assert child.process.parent_image.endswith("WmiPrvSE.exe")
    assert child.process.parent_command_line.endswith("WmiPrvSE.exe")


def test_benign_scenario_has_no_labels_or_detections(generated_dir):
    report = run_pipeline(BENIGN_SPEC, RULES, run_id="test-run")

    assert report.ok
    assert report.detections == {}

    reloaded = DatasetStore.load("generated", "b1_notepad_test-run.jsonl")
    assert all(event.ground_truth_labels == [] for event in reloaded)


def test_s2_spec_is_valid():
    validate_spec(load_builtin_spec("s2_wmi_powershell"))


def _spec_with(mutation):
    spec = copy.deepcopy(load_builtin_spec("s2_wmi_powershell"))
    mutation(spec)
    return spec


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s["steps"][0].update(action="delete_everything"),
        lambda s: s["steps"][1].pop("parent_process_id"),
        lambda s: s["steps"][1].update(parent_process_id="9999"),
        lambda s: s["steps"][1].update(process_id="1000"),
        lambda s: s["steps"][1].update(timestamp="2025-12-31T00:00:00+00:00"),
        lambda s: s["steps"][1].update(timestamp="not-a-date"),
        lambda s: s["steps"][0].update(unexpected="field"),
        lambda s: s.update(label="suspicious"),
        lambda s: s.update(steps=[]),
        lambda s: s.update(label="benign"),  # still carries technique labels
    ],
)
def test_invalid_specs_are_rejected(mutation):
    with pytest.raises(ScenarioSpecError):
        validate_spec(_spec_with(mutation))


def test_malicious_spec_without_technique_is_rejected():
    def strip_labels(spec):
        for step in spec["steps"]:
            step["technique_labels"] = []

    with pytest.raises(ScenarioSpecError):
        validate_spec(_spec_with(strip_labels))


@pytest.mark.skipif(
    not DEFAULT_RULE_DIR.exists(),
    reason="Sigma rules submodule not checked out at the default path",
)
def test_real_sigma_rules_do_not_break_the_pipeline(generated_dir):
    rules, _failed = load_rules(DEFAULT_RULE_DIR)
    assert rules

    report = run_pipeline(
        load_builtin_spec("s2_wmi_powershell"),
        rules,
        run_id="test-run",
    )

    assert report.ok


def test_failed_rule_load_makes_pipeline_not_ok(generated_dir):
    report = run_pipeline(
        load_builtin_spec("s2_wmi_powershell"),
        RULES,
        run_id="test-rule-load-failure",
        rules_failed_to_load=1,
    )
    assert report.rules_failed_to_load == 1
    assert report.roundtrip_ok
    assert not report.ok

def test_unhashable_label_is_rejected():
    with pytest.raises(ScenarioSpecError):
        validate_spec(_spec_with(lambda spec: spec.update(label=[])))


def test_pipeline_reports_valid_provenance(generated_dir):
    report = run_pipeline(
        load_builtin_spec("s2_wmi_powershell"),
        RULES,
        run_id="test-valid-provenance",
    )

    assert report.provenance_errors == []
    assert report.ok
    assert report.saved_path is not None


def test_pipeline_blocks_save_when_provenance_fails(
    generated_dir,
    monkeypatch,
):
    monkeypatch.setattr(
        "synthetic_data.pipeline.runner.validate_provenance",
        lambda events, trace: ["Simulated provenance failure."],
    )

    report = run_pipeline(
        load_builtin_spec("s2_wmi_powershell"),
        RULES,
        run_id="test-invalid-provenance",
    )

    assert report.provenance_errors == ["Simulated provenance failure."]
    assert report.saved_path is None
    assert not report.roundtrip_ok
    assert not report.ok

    expected_path = (
        generated_dir / "s2_wmi_powershell_test-invalid-provenance.jsonl"
    )
    assert not expected_path.exists()
