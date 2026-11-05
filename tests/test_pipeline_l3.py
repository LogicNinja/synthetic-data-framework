"""Pipeline-level tests for Layer 3 (domain realism) validation."""

from synthetic_data.pipeline.runner import run_pipeline
from synthetic_data.scenarios.spec import load_builtin_spec
from synthetic_data.storage.dataset_store import DatasetStore
from synthetic_data.validation.domain_realism import DomainRealismReport


RULES = []


def _spec():
    return load_builtin_spec("s2_wmi_powershell")


def _patch_generated_dir(monkeypatch, tmp_path):
    monkeypatch.setitem(DatasetStore.DATASET_TYPES, "generated", tmp_path)
    return tmp_path


def test_pipeline_invokes_l3_validator(monkeypatch, tmp_path):
    output_dir = _patch_generated_dir(monkeypatch, tmp_path)
    calls = []

    def fake_l3(events):
        calls.append(events)
        return DomainRealismReport(event_count=len(events))

    monkeypatch.setattr(
        "synthetic_data.pipeline.runner.validate_domain_realism",
        fake_l3,
    )

    report = run_pipeline(_spec(), RULES, run_id="l3-invoked")

    assert len(calls) == 1
    assert len(calls[0]) == report.event_count
    assert report.ok
    assert (output_dir / "s2_wmi_powershell_l3-invoked.jsonl").exists()


def test_pipeline_includes_l3_errors_in_report(monkeypatch, tmp_path):
    _patch_generated_dir(monkeypatch, tmp_path)
    expected_errors = ["event-123: test L3 consistency error"]

    monkeypatch.setattr(
        "synthetic_data.pipeline.runner.validate_domain_realism",
        lambda events: DomainRealismReport(
            event_count=len(events),
            errors=expected_errors.copy(),
        ),
    )

    report = run_pipeline(_spec(), RULES, run_id="l3-error-report")

    assert report.domain_realism_errors == expected_errors
    assert not report.ok


def test_l3_error_prevents_dataset_saving(monkeypatch, tmp_path):
    output_dir = _patch_generated_dir(monkeypatch, tmp_path)
    filename = "l3-error-blocks-save.jsonl"

    monkeypatch.setattr(
        "synthetic_data.pipeline.runner.validate_domain_realism",
        lambda events: DomainRealismReport(
            event_count=len(events),
            errors=["Synthetic L3 failure."],
        ),
    )

    report = run_pipeline(
        _spec(),
        RULES,
        run_id="l3-error-blocks-save",
        filename=filename,
    )

    assert report.domain_realism_errors == ["Synthetic L3 failure."]
    assert report.saved_path is None
    assert report.roundtrip_ok is False
    assert not report.ok
    assert not (output_dir / filename).exists()


def test_l3_warnings_are_reported_but_do_not_fail_pipeline(
    monkeypatch,
    tmp_path,
):
    output_dir = _patch_generated_dir(monkeypatch, tmp_path)
    expected_warnings = ["event-456: parent process is outside this batch"]

    monkeypatch.setattr(
        "synthetic_data.pipeline.runner.validate_domain_realism",
        lambda events: DomainRealismReport(
            event_count=len(events),
            warnings=expected_warnings.copy(),
        ),
    )

    report = run_pipeline(_spec(), RULES, run_id="l3-warning")

    assert report.domain_realism_warnings == expected_warnings
    assert report.domain_realism_errors == []
    assert report.saved_path is not None
    assert report.roundtrip_ok
    assert report.ok
    assert (output_dir / "s2_wmi_powershell_l3-warning.jsonl").exists()


def test_clean_l3_report_allows_save_and_roundtrip(monkeypatch, tmp_path):
    output_dir = _patch_generated_dir(monkeypatch, tmp_path)

    monkeypatch.setattr(
        "synthetic_data.pipeline.runner.validate_domain_realism",
        lambda events: DomainRealismReport(event_count=len(events)),
    )

    report = run_pipeline(_spec(), RULES, run_id="l3-clean")

    assert report.domain_realism_errors == []
    assert report.domain_realism_warnings == []
    assert report.saved_path is not None
    assert report.roundtrip_ok
    assert report.ok

    saved_file = output_dir / "s2_wmi_powershell_l3-clean.jsonl"
    assert saved_file.exists()
    assert len(DatasetStore.load("generated", saved_file.name)) == report.event_count