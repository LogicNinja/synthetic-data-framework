from types import SimpleNamespace

import pytest

from synthetic_data.validation.four_layer import (
    ValidationCriteria,
    aggregate_validation_reports,
    build_four_layer_report,
    load_validation_criteria,
)


CRITERIA = ValidationCriteria(
    minimum_reference_sample_size=2,
    minimum_reference_similarity=0.6,
    minimum_macro_f1=0.7,
    minimum_macro_f1_delta=0.0,
)


def valid_reference():
    return SimpleNamespace(
        status="evaluated",
        similarity_score=0.8,
        reference_event_count=2,
        sample_adequacy="adequate",
        errors=[],
    )


def full_report(**overrides):
    values = {
        "criteria": CRITERIA,
        "provenance_errors": [],
        "schema_errors": {},
        "logic_errors": [],
        "logic_warnings": [],
        "roundtrip_ok": True,
        "rules_failed_to_load": 0,
        "unsupported_sigma_evaluations": 0,
        "domain_errors": [],
        "domain_warnings": [],
        "reference_report": valid_reference(),
        "critic_accepted": True,
        "utility_report": {"macro_f1": 0.8, "macro_f1_delta": 0.05},
    }
    values.update(overrides)
    return build_four_layer_report(**values)


def test_all_layers_must_pass_for_validated_status():
    report = full_report()
    assert report.validated
    assert report.decision == "validated"
    assert all(layer.status == "passed" for layer in report.layers.values())


@pytest.mark.parametrize(
    "override,layer",
    [
        ({"provenance_errors": ["unlinked event"]}, "L1"),
        ({"schema_errors": {"event-1": ["bad type"]}}, "L2"),
        ({"critic_accepted": False}, "L3"),
        ({"utility_report": {"macro_f1": 0.5, "macro_f1_delta": 0.05}}, "L4"),
        ({"utility_report": {"macro_f1": 0.8, "macro_f1_delta": -0.1}}, "L4"),
    ],
)
def test_rejection_criteria_are_reported_per_layer(override, layer):
    report = full_report(**override)
    assert not report.validated
    assert report.layers[layer].status == "failed"
    assert report.decision == "rejected"


def test_missing_critic_reference_or_utility_is_incomplete():
    report = full_report(reference_report=None, critic_accepted=None, utility_report=None)
    assert not report.validated
    assert report.decision == "incomplete"
    assert report.layers["L3"].status == "not_run"
    assert report.layers["L4"].status == "not_run"


def test_unsupported_sigma_rules_are_reported_without_invalidating_event_data():
    report = full_report(unsupported_sigma_evaluations=1)
    assert report.validated
    assert report.layers["L2"].status == "passed"
    assert any("detection coverage is incomplete" in item for item in report.layers["L2"].warnings)


def test_low_uncalibrated_reference_similarity_is_advisory():
    reference = SimpleNamespace(
        status="evaluated",
        similarity_score=0.04,
        reference_event_count=100,
        sample_adequacy="adequate",
        errors=[],
    )
    report = full_report(reference_report=reference)
    assert report.validated
    assert report.layers["L3"].status == "passed"
    assert any("not a hard gate" in item for item in report.layers["L3"].warnings)


def test_batch_requires_each_sample_to_pass():
    good = full_report()
    bad = full_report(critic_accepted=False)
    report = aggregate_validation_reports([good, bad], criteria=CRITERIA)
    assert not report.validated
    assert report.layers["L3"].status == "failed"
    assert report.layers["L3"].checks["sample_count"] == 2


def test_loads_project_acceptance_criteria():
    criteria = load_validation_criteria("configs/validation_criteria.json")
    assert criteria.minimum_reference_sample_size == 30
    assert criteria.maximum_unsupported_sigma_evaluations == 0

