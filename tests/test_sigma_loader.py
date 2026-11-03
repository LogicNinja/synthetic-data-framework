
import pytest

from synthetic_data.detection.sigma_loader import SigmaRuleLoader


def test_load_valid_sigma_rule(tmp_path):
    rule_path = tmp_path / "sample.yml"

    rule_path.write_text(
        """
title: Example Process Detection
id: sample-rule-001
status: test
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
  condition: selection
tags:
  - attack.execution
""",
        encoding="utf-8",
    )

    rule = SigmaRuleLoader.load_rule(rule_path)

    assert rule["title"] == "Example Process Detection"
    assert rule["detection"]["condition"] == "selection"


def test_missing_required_fields_rejected(tmp_path):
    rule_path = tmp_path / "invalid.yml"

    rule_path.write_text(
        "title: Incomplete Rule\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        SigmaRuleLoader.load_rule(rule_path)


def test_invalid_yaml_rejected(tmp_path):
    rule_path = tmp_path / "broken.yml"

    rule_path.write_text(
        "title: [broken YAML",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        SigmaRuleLoader.load_rule(rule_path)


def test_metadata_extraction():
    rule = {
        "title": "Example",
        "id": "rule-001",
        "status": "test",
        "level": "high",
        "description": "Example description",
        "tags": ["attack.execution"],
        "logsource": {"product": "windows"},
        "detection": {"condition": "selection"},
    }

    metadata = SigmaRuleLoader.get_metadata(rule)

    assert metadata["title"] == "Example"
    assert metadata["level"] == "high"
    assert metadata["tags"] == ["attack.execution"]


def test_missing_rule_file_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        SigmaRuleLoader.load_rule(tmp_path / "missing.yml")
