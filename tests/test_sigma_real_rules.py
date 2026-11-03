from pathlib import Path

import pytest

from synthetic_data.detection.sigma_evaluator import SigmaEvaluator
from synthetic_data.detection.sigma_loader import SigmaRuleLoader


RULES_DIR = (
    Path(__file__).resolve().parents[1]
    / "knowledge"
    / "sigma_rules"
    / "sigma"
    / "rules"
    / "windows"
    / "process_creation"
)


def load_rule(filename):
    return SigmaRuleLoader.load_rule(RULES_DIR / filename)


def make_event(
    image,
    parent_image=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
    command_line="",
    original_file_name=None,
):
    return {
        "event_id": "evt-real-rule-test",
        "schema_version": "1.0.0",
        "event_source": "windows_process_creation",
        "event_type": "process_create",
        "timestamp": "2026-10-29T10:30:00Z",
        "host_id": "host-test",
        "origin": "synthetic",
        "run_id": "run-test",
        "process": {
            "image": image,
            "command_line": command_line,
            "parent_image": parent_image,
            "original_file_name": original_file_name,
        },
    }


def evaluate_rule(filename, event):
    rule = load_rule(filename)
    return SigmaEvaluator.evaluate(rule, event)["matched"]


# Rule 1: WmiPrvSE spawning PowerShell


RULE_1 = "proc_creation_win_wmiprvse_spawns_powershell.yml"


def test_wmiprvse_spawns_powershell_matches():
    event = make_event(
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -NoProfile",
    )

    assert evaluate_rule(RULE_1, event) is True


def test_wmiprvse_spawns_non_powershell_does_not_match():
    event = make_event(
        image=r"C:\Windows\System32\notepad.exe",
    )

    assert evaluate_rule(RULE_1, event) is False


def test_powershell_with_wrong_parent_does_not_match():
    event = make_event(
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        parent_image=r"C:\Windows\explorer.exe",
    )

    assert evaluate_rule(RULE_1, event) is False


# Rule 2: Potential PowerShell execution via DLL


RULE_2 = "proc_creation_win_susp_powershell_execution_via_dll.yml"


def test_powershell_via_dll_matches():
    event = make_event(
        image=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe",
        command_line="InstallUtil.exe DownloadString http://example.test",
    )

    assert evaluate_rule(RULE_2, event) is True


def test_utility_without_suspicious_command_does_not_match():
    event = make_event(
        image=r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe",
        command_line="InstallUtil.exe normal-assembly.dll",
    )

    assert evaluate_rule(RULE_2, event) is False


def test_suspicious_command_with_non_utility_does_not_match():
    event = make_event(
        image=r"C:\Windows\System32\notepad.exe",
        command_line="notepad.exe FromBase64String",
    )

    assert evaluate_rule(RULE_2, event) is False


# Rule 3: Suspicious WmiPrvSE child process


RULE_3 = "proc_creation_win_wmiprvse_susp_child_processes.yml"


def test_wmiprvse_spawns_suspicious_utility_matches():
    event = make_event(
        image=r"C:\Windows\System32\certutil.exe",
    )

    assert evaluate_rule(RULE_3, event) is True


def test_wmiprvse_spawns_suspicious_cmd_matches():
    event = make_event(
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c powershell -enc ABC",
    )

    assert evaluate_rule(RULE_3, event) is True


def test_suspicious_child_with_wrong_parent_does_not_match():
    event = make_event(
        image=r"C:\Windows\System32\certutil.exe",
        parent_image=r"C:\Windows\explorer.exe",
    )

    assert evaluate_rule(RULE_3, event) is False


@pytest.mark.parametrize(
    "image,command_line",
    [
        (
            r"C:\Windows\System32\WerFault.exe",
            "WerFault.exe",
        ),
        (
            r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            "WmiPrvSE.exe",
        ),
        (
            r"C:\Windows\System32\msiexec.exe",
            "msiexec.exe /i package.msi",
        ),
    ],
)
def test_wmiprvse_rule_exclusions_do_not_match(image, command_line):
    event = make_event(
        image=image,
        command_line=command_line,
    )

    assert evaluate_rule(RULE_3, event) is False