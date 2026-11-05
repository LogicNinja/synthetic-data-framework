import pytest

from synthetic_data.detection.sigma_evaluator import (
    SigmaEvaluationError,
    SigmaEvaluator,
)


def _event(command_line: str) -> dict:
    return {
        "process": {
            "image": "C:\\Windows\\System32\\cmd.exe",
            "command_line": command_line,
        }
    }


def _matches(selection: dict, command_line: str) -> bool:
    rule = {
        "id": "test-rule",
        "title": "Test rule",
        "logsource": {},
        "detection": {"selection": selection, "condition": "selection"},
    }
    return SigmaEvaluator.evaluate(rule, _event(command_line))["matched"]


# --- contains|all -----------------------------------------------------------


def test_contains_all_requires_every_value():
    selection = {"CommandLine|contains|all": ["-enc", "-nop"]}

    assert _matches(selection, "powershell -nop -enc AAAA")
    assert not _matches(selection, "powershell -enc AAAA")


def test_contains_without_all_matches_any_value():
    selection = {"CommandLine|contains": ["-enc", "-nop"]}

    assert _matches(selection, "powershell -enc AAAA")
    assert not _matches(selection, "powershell -noexit")


def test_contains_all_is_case_insensitive():
    assert _matches(
        {"CommandLine|contains|all": ["-ENC", "-NOP"]},
        "powershell -nop -enc AAAA",
    )


def test_all_modifier_order_does_not_matter():
    selection = {"CommandLine|all|contains": ["-enc", "-nop"]}

    assert _matches(selection, "powershell -nop -enc AAAA")
    assert not _matches(selection, "powershell -enc AAAA")


def test_startswith_all_and_endswith_all_work():
    assert _matches(
        {"CommandLine|startswith|all": ["power", "powershell"]},
        "powershell -nop",
    )
    assert not _matches(
        {"CommandLine|endswith|all": ["-nop", "-enc"]},
        "powershell -nop",
    )


# --- windash ----------------------------------------------------------------


@pytest.mark.parametrize(
    "command_line",
    [
        "powershell -enc AAAA",
        "powershell /enc AAAA",
        "powershell \u2013enc AAAA",  # en dash
        "powershell \u2014enc AAAA",  # em dash
        "powershell \u2015enc AAAA",  # horizontal bar
    ],
)
def test_contains_windash_accepts_every_dash_variant(command_line):
    assert _matches({"CommandLine|contains|windash": " -enc"}, command_line)


def test_windash_still_requires_the_rest_of_the_value():
    assert not _matches(
        {"CommandLine|contains|windash": " -enc"},
        "powershell /noexit",
    )


def test_windash_with_all_applies_per_value():
    selection = {"CommandLine|contains|windash|all": ["-nop", "-enc"]}

    assert _matches(selection, "powershell /nop \u2013enc AAAA")
    assert not _matches(selection, "powershell /nop")


def test_windash_before_contains_gives_same_result():
    selection = {"CommandLine|windash|contains": " -enc"}

    assert _matches(selection, "powershell /enc AAAA")


def test_windash_alone_compares_equal_values():
    assert _matches({"CommandLine|windash": "tool -x"}, "tool /x")
    assert not _matches({"CommandLine|windash": "tool -x"}, "tool /y")


# --- invalid chains are rejected, not silently accepted ----------------------


@pytest.mark.parametrize(
    "field",
    [
        "CommandLine|contains|startswith",
        "CommandLine|contains|contains",
        "CommandLine|re|windash",
        "CommandLine|exists|contains",
    ],
)
def test_contradictory_chains_raise(field):
    with pytest.raises(SigmaEvaluationError):
        _matches({field: "x"}, "anything")


@pytest.mark.parametrize("modifier", ["base64offset", "fieldref"])
def test_rare_modifiers_are_still_reported_as_unsupported(modifier):
    with pytest.raises(SigmaEvaluationError, match="Unsupported Sigma modifier"):
        _matches({f"CommandLine|{modifier}|contains": "x"}, "anything")


def test_windash_does_not_normalize_path_punctuation():
    selection = {"CommandLine|contains|windash": "C:-tools/my-app"}
    assert not _matches(selection, "C:/tools/my-app")
