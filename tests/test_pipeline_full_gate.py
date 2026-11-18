import json

from synthetic_data.pipeline.runner import run_pipeline
from synthetic_data.scenarios.spec import load_builtin_spec
from synthetic_data.storage.dataset_store import DatasetStore
from synthetic_data.validation.four_layer import ValidationCriteria


def _reference_file(path):
    events = [
        {"event_type": "process_creation", "process": {"image": "WmiPrvSE.exe"}},
        {"event_type": "process_creation", "process": {"image": "powershell.exe"}},
    ]
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
    return path


def _criteria():
    return ValidationCriteria(
        minimum_reference_sample_size=2,
        minimum_reference_similarity=0.5,
        maximum_unsupported_sigma_evaluations=0,
        minimum_macro_f1=0.7,
        minimum_macro_f1_delta=0.0,
    )


def test_final_dataset_is_promoted_only_when_all_four_layers_pass(tmp_path, monkeypatch):
    generated = tmp_path / "generated"
    final = tmp_path / "final"
    generated.mkdir()
    monkeypatch.setitem(DatasetStore.DATASET_TYPES, "generated", generated)
    monkeypatch.setitem(DatasetStore.DATASET_TYPES, "final", final)
    reference = _reference_file(tmp_path / "reference.jsonl")

    report = run_pipeline(
        load_builtin_spec("s2_wmi_powershell"),
        [],
        run_id="full-gate-pass",
        dataset_type="final",
        reference_path=reference,
        critic_accepted=True,
        utility_report={"macro_f1": 0.8, "macro_f1_delta": 0.1},
        validation_criteria=_criteria(),
    )

    assert report.ok
    assert report.validated
    assert not report.final_promotion_blocked
    assert report.saved_path == str(final / "s2_wmi_powershell_full-gate-pass.jsonl")
    assert (generated / "s2_wmi_powershell_full-gate-pass.jsonl").exists()
    manifest = DatasetStore.load_metadata("final", "s2_wmi_powershell_full-gate-pass.jsonl")
    assert manifest["metadata"]["validated"] is True
    assert manifest["metadata"]["validation_report"]["decision"] == "validated"


def test_missing_critic_and_utility_keep_data_out_of_final(tmp_path, monkeypatch):
    generated = tmp_path
    final = tmp_path / "final"
    monkeypatch.setitem(DatasetStore.DATASET_TYPES, "generated", generated)
    monkeypatch.setitem(DatasetStore.DATASET_TYPES, "final", final)

    report = run_pipeline(
        load_builtin_spec("s2_wmi_powershell"),
        [],
        run_id="full-gate-incomplete",
        dataset_type="final",
    )

    assert report.ok
    assert not report.validated
    assert report.final_promotion_blocked
    assert report.validation_report["decision"] == "incomplete"
    assert not (final / "s2_wmi_powershell_full-gate-incomplete.jsonl").exists()
    assert (generated / "s2_wmi_powershell_full-gate-incomplete.jsonl").exists()
