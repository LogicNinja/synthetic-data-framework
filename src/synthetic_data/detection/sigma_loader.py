

from pathlib import Path
from typing import Any

import yaml


class SigmaRuleLoader:
    """Load and perform basic structural checks on Sigma rules."""

    REQUIRED_FIELDS = {"title", "logsource", "detection"}

    @staticmethod
    def load_rule(rule_path: str | Path) -> dict[str, Any]:
        """Load one Sigma rule from a YAML file."""
        path = Path(rule_path)

        if not path.is_file():
            raise FileNotFoundError(f"Sigma rule not found: {path}")

        try:
            with path.open("r", encoding="utf-8") as file:
                rule = yaml.safe_load(file)
        except yaml.YAMLError as error:
            raise ValueError(f"Invalid Sigma YAML: {error}") from error

        if not isinstance(rule, dict):
            raise ValueError("Sigma rule must be a YAML mapping.")

        missing_fields = SigmaRuleLoader.REQUIRED_FIELDS - rule.keys()

        if missing_fields:
            raise ValueError(
                f"Sigma rule is missing required fields: "
                f"{', '.join(sorted(missing_fields))}"
            )

        if not isinstance(rule["detection"], dict):
            raise ValueError("Sigma detection section must be a mapping.")

        if "condition" not in rule["detection"]:
            raise ValueError("Sigma detection section must contain condition.")

        return rule

    @staticmethod
    def load_rules_from_directory(
        directory: str | Path,
        recursive: bool = True,
    ) -> list[dict[str, Any]]:
        """Load Sigma YAML rules from a directory."""
        root = Path(directory)

        if not root.is_dir():
            raise NotADirectoryError(f"Rule directory not found: {root}")

        pattern = "**/*" if recursive else "*"

        rule_paths = sorted(
            path
            for path in root.glob(pattern)
            if path.is_file()
            and path.suffix.lower() in {".yml", ".yaml"}
        )

        return [
            SigmaRuleLoader.load_rule(path)
            for path in rule_paths
        ]

    @staticmethod
    def get_metadata(rule: dict[str, Any]) -> dict[str, Any]:
        """Extract useful rule metadata."""
        return {
            "title": rule.get("title"),
            "id": rule.get("id"),
            "status": rule.get("status"),
            "level": rule.get("level"),
            "description": rule.get("description"),
            "tags": rule.get("tags", []),
            "logsource": rule.get("logsource", {}),
            "detection": rule.get("detection", {}),
        }
