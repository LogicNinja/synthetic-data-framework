
import pytest

from synthetic_data.detection.sigma_evaluator import (
    SigmaEvaluator,
    SigmaEvaluationError,
)


def sample_event():
    return {
        "event_id": "evt-001",
        "schema_version": "1.0.0",
        "event_source": "windows_process_creation",
        "event_type": "process_create",
        "timestamp": "2026-10-29T10:30:00Z",
        "host_id": "host-001",
        "origin": "synthetic",
        "run_id": "run-001",
        "process": {
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -NoProfile",
            "parent_image": "C:\\Windows\\System32\\wmiPrvSE.exe",
        },
    }


def sample_rule():
    return {
        "title": "PowerShell Process Rule",
        "id": "rule-001",
        "logsource": {
            "product": "windows",
            "category": "process_creation",
        },
        "detection": {
            "selection":
                {"Image|endswith": "\\powershell.exe"},
            "condition": "selection",
        },
    }


def test_sigma_rule_matches_event():
    result = SigmaEvaluator.evaluate(sample_rule(), sample_event())

    assert result["matched"] is True
    assert result["rule_id"] == "rule-001"


def test_sigma_rule_does_not_match_event():
    rule = sample_rule()
    rule["detection"]["selection"] = {
        "Image|endswith": "\\notepad.exe"
    }

    result = SigmaEvaluator.evaluate(rule, sample_event())

    assert result["matched"] is False


def test_condition_and():
    rule = sample_rule()
    rule["detection"]["filter"] = {
        "ParentImage|endswith": "\\wmiPrvSE.exe"
    }
    rule["detection"]["condition"] = "selection and filter"

    result = SigmaEvaluator.evaluate(rule, sample_event())

    assert result["matched"] is True


def test_condition_or():
    rule = sample_rule()
    rule["detection"]["filter"] = {
        "Image|endswith": "\\notepad.exe"
    }
    rule["detection"]["condition"] = "selection or filter"

    result = SigmaEvaluator.evaluate(rule, sample_event())

    assert result["matched"] is True


def test_unknown_selection_rejected():
    rule = sample_rule()
    rule["detection"]["condition"] = "unknown_selection"

    with pytest.raises(SigmaEvaluationError):
        SigmaEvaluator.evaluate(rule, sample_event())


def test_unsupported_modifier_rejected():
    rule = sample_rule()
    rule["detection"]["selection"] = {
        "Image|unsupported": "powershell.exe"
    }

    with pytest.raises(SigmaEvaluationError):
        SigmaEvaluator.evaluate(rule, sample_event())
def test_all_of_wildcard_selections():
    rule = sample_rule()
    rule["detection"]["selection_image"] = {
        "Image|endswith": "\\powershell.exe"
    }
    rule["detection"]["selection_parent"] = {
        "ParentImage|endswith": "\\wmiPrvSE.exe"
    }
    rule["detection"]["condition"] = "all of selection_*"

    result = SigmaEvaluator.evaluate(rule, sample_event())

    assert result["matched"] is True


def test_one_of_wildcard_selections():
    rule = sample_rule()
    rule["detection"]["selection_image"] = {
        "Image|endswith": "\\notepad.exe"
    }
    rule["detection"]["selection_parent"] = {
        "ParentImage|endswith": "\\wmiPrvSE.exe"
    }
    rule["detection"]["condition"] = "1 of selection_*"

    result = SigmaEvaluator.evaluate(rule, sample_event())

    assert result["matched"] is True


def test_not_one_of_wildcard_filters():
    rule = sample_rule()
    rule["detection"]["filter_main_image"] = {
        "Image|endswith": "\\notepad.exe"
    }
    rule["detection"]["condition"] = "selection and not 1 of filter_main_*"

    result = SigmaEvaluator.evaluate(rule, sample_event())

    assert result["matched"] is True


def test_wildcard_selection_requires_matching_names():
    rule = sample_rule()
    rule["detection"]["condition"] = "1 of missing_*"

    with pytest.raises(SigmaEvaluationError):
        SigmaEvaluator.evaluate(rule, sample_event())

