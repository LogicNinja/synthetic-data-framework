
import re
from typing import Any

EVALUATOR_VERSION = "0.2.0"

SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "re",
    "all",
    "exists",
    "windash",
}

# At most one of these may appear on a field.
MATCH_MODIFIERS = {"contains", "startswith", "endswith", "re"}

# Characters that Windows command lines treat as interchangeable flag prefixes.
_DASH_CHARACTERS = re.compile(r"(?<!\S)[-/\u2013\u2014\u2015](?=[A-Za-z])")

class SigmaEvaluationError(ValueError):
    """Raised when a Sigma rule uses unsupported or invalid syntax."""


class SigmaEvaluator:
    @staticmethod
    def _normalize_field_name(name: str) -> str:
        """Normalize Sigma and canonical event field names."""
        return re.sub(r"[^a-z0-9]", "", name.casefold())

    @staticmethod
    def _normalize_dashes(text: str) -> str:
        """Map every Windows dash variant (- / en/em dash, bar) to '-'.

        Applying this to both the event value and the rule value is
        equivalent to expanding the rule value into all its dash variants.
        It can match slightly more than a variant-by-variant expansion
        when a dash inside a word differs, which is rare in practice.
        """
        return _DASH_CHARACTERS.sub("-", text)

    @staticmethod
    def _validate_modifiers(modifiers: list[str]) -> None:
        """Reject unsupported or contradictory modifier chains."""
        unsupported = [
            modifier
            for modifier in modifiers
            if modifier not in SUPPORTED_MODIFIERS
        ]
        if unsupported:
            raise SigmaEvaluationError(
                f"Unsupported Sigma modifier: {unsupported[0]}"
            )

        duplicates = sorted(
            {modifier for modifier in modifiers if modifiers.count(modifier) > 1}
        )
        if duplicates:
            raise SigmaEvaluationError(
                f"Duplicate Sigma modifier: {duplicates[0]}"
            )

        if "exists" in modifiers and len(modifiers) > 1:
            raise SigmaEvaluationError(
                "The 'exists' modifier cannot be combined with other modifiers."
            )

        match_types = [m for m in modifiers if m in MATCH_MODIFIERS]
        if len(match_types) > 1:
            raise SigmaEvaluationError(
                f"Conflicting match modifiers: {', '.join(match_types)}"
            )

        if "re" in modifiers and "windash" in modifiers:
            raise SigmaEvaluationError(
                "The 'windash' modifier cannot be combined with 're'."
            )

    @classmethod
    def _flatten_event(cls, event: Any) -> dict[str, Any]:
        """Flatten nested event data with case- and format-insensitive keys."""
        if hasattr(event, "to_dict"):
            event = event.to_dict()

        if not isinstance(event, dict):
            raise SigmaEvaluationError(
                "Event must be a dictionary or canonical event."
            )

        flattened: dict[str, Any] = {}

        def visit(value: Any, prefix: str = "") -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    field_name = f"{prefix}.{key}" if prefix else str(key)
                    visit(child, field_name)
                return

            if not prefix:
                return

            flattened[prefix.casefold()] = value
            flattened[cls._normalize_field_name(prefix)] = value

            leaf_name = prefix.rsplit(".", 1)[-1]
            flattened.setdefault(leaf_name.casefold(), value)
            flattened.setdefault(cls._normalize_field_name(leaf_name), value)

        visit(event)
        return flattened

    @classmethod
    def _match_value(
        cls,
        actual: Any,
        expected: Any,
        modifiers: list[str],
    ) -> bool:
        """Compare an actual event value with a Sigma expected value."""
        if "exists" in modifiers:
            expected_exists = (
                expected is True
                or str(expected).casefold() == "true"
            )
            actual_exists = actual is not None
            return actual_exists == expected_exists

        if actual is None:
            return expected is None

        if expected is None:
            return False

        remaining_modifiers = [
            modifier for modifier in modifiers if modifier != "all"
        ]

        if isinstance(expected, list):
            if "all" in modifiers:
                return all(
                    cls._match_value(actual, item, remaining_modifiers)
                    for item in expected
                )

            return any(
                cls._match_value(actual, item, remaining_modifiers)
                for item in expected
            )

        actual_text = str(actual)
        expected_text = str(expected)

        if "windash" in modifiers:
            actual_text = cls._normalize_dashes(actual_text)
            expected_text = cls._normalize_dashes(expected_text)

        if "contains" in modifiers:
            return expected_text.casefold() in actual_text.casefold()

        if "startswith" in modifiers:
            return actual_text.casefold().startswith(expected_text.casefold())

        if "endswith" in modifiers:
            return actual_text.casefold().endswith(expected_text.casefold())

        if "re" in modifiers:
            try:
                return re.search(expected_text, actual_text) is not None
            except re.error as exc:
                raise SigmaEvaluationError(
                    f"Invalid regular expression: {expected_text}"
                ) from exc

        return actual_text.casefold() == expected_text.casefold()

    @classmethod
    def _match_selection(
        cls,
        selection: Any,
        event_fields: dict[str, Any],
    ) -> bool:
        """Match a Sigma selection; mappings use AND, lists use OR."""
        if isinstance(selection, list):
            return any(
                cls._match_selection(item, event_fields)
                for item in selection
            )

        if not isinstance(selection, dict):
            raise SigmaEvaluationError(
                "A Sigma selection must be a mapping or list of mappings."
            )

        for field_expression, expected in selection.items():
            parts = str(field_expression).split("|")
            field_name = parts[0]
            modifiers = [part.casefold() for part in parts[1:]]

            cls._validate_modifiers(modifiers)

            normalized_field = cls._normalize_field_name(field_name)
            actual = event_fields.get(normalized_field)

            if not cls._match_value(actual, expected, modifiers):
                return False

        return True

    @classmethod
    def _evaluate_condition(
        cls,
        condition: str,
        selections: dict[str, Any],
        event_fields: dict[str, Any],
    ) -> bool:
        """Evaluate Sigma conditions including wildcard and numeric 'of' syntax."""
        token_pattern = re.compile(
            r"\(|\)|\d+|[A-Za-z_][A-Za-z0-9_-]*(?:\*)?"
        )
        tokens = token_pattern.findall(condition)

        if not tokens:
            raise SigmaEvaluationError("Sigma condition is empty or invalid.")

        normalized_condition = re.sub(r"\s+", "", condition)
        reconstructed = "".join(tokens)

        if normalized_condition.casefold() != reconstructed.casefold():
            raise SigmaEvaluationError(
                f"Unsupported Sigma condition syntax: {condition}"
            )

        position = 0

        def resolve_selection_group(pattern: str) -> list[str]:
            if "*" not in pattern:
                if pattern not in selections:
                    raise SigmaEvaluationError(
                        f"Unknown Sigma selection reference: {pattern}"
                    )
                return [pattern]

            if pattern.count("*") != 1 or not pattern.endswith("*"):
                raise SigmaEvaluationError(
                    f"Unsupported Sigma selection pattern: {pattern}"
                )

            prefix = pattern[:-1]
            matching_names = [
                name for name in selections
                if name.startswith(prefix)
            ]

            if not matching_names:
                raise SigmaEvaluationError(
                    f"No Sigma selections match pattern: {pattern}"
                )

            return matching_names

        def parse_primary() -> bool:
            nonlocal position

            if position >= len(tokens):
                raise SigmaEvaluationError(
                    "Unexpected end of Sigma condition."
                )

            token = tokens[position]

            if token == "(":
                position += 1
                result = parse_or()

                if position >= len(tokens) or tokens[position] != ")":
                    raise SigmaEvaluationError(
                        "Unmatched parenthesis in condition."
                    )

                position += 1
                return result

            if token == ")" or token.casefold() in {"and", "or", "not"}:
                raise SigmaEvaluationError(
                    f"Unexpected token in Sigma condition: {token}"
                )

            if token.casefold() == "all" or token.isdigit():
                quantifier = token.casefold()
                position += 1

                if (
                    position >= len(tokens)
                    or tokens[position].casefold() != "of"
                ):
                    raise SigmaEvaluationError(
                        f"Expected 'of' after {token}."
                    )

                position += 1

                if position >= len(tokens):
                    raise SigmaEvaluationError(
                        "Expected a selection pattern after 'of'."
                    )

                pattern = tokens[position]
                position += 1

                matching_names = resolve_selection_group(pattern)

                match_count = sum(
                    cls._match_selection(selections[name], event_fields)
                    for name in matching_names
                )

                if quantifier == "all":
                    return match_count == len(matching_names)

                required_count = int(quantifier)

                if required_count < 1:
                    raise SigmaEvaluationError(
                        "Sigma 'of' count must be at least 1."
                    )

                return match_count >= required_count

            position += 1

            matching_names = resolve_selection_group(token)

            return cls._match_selection(
                selections[matching_names[0]],
                event_fields,
            )

        def parse_not() -> bool:
            nonlocal position

            if (
                position < len(tokens)
                and tokens[position].casefold() == "not"
            ):
                position += 1
                return not parse_not()

            return parse_primary()

        def parse_and() -> bool:
            nonlocal position
            result = parse_not()

            while (
                position < len(tokens)
                and tokens[position].casefold() == "and"
            ):
                position += 1
                right = parse_not()
                result = result and right

            return result

        def parse_or() -> bool:
            nonlocal position
            result = parse_and()

            while (
                position < len(tokens)
                and tokens[position].casefold() == "or"
            ):
                position += 1
                right = parse_and()
                result = result or right

            return result

        result = parse_or()

        if position != len(tokens):
            raise SigmaEvaluationError(
                f"Unexpected token in Sigma condition: {tokens[position]}"
            )

        return result

    @classmethod
    def evaluate(
        cls,
        rule: dict[str, Any],
        event: Any,
    ) -> dict[str, Any]:
        """Evaluate a Sigma rule against one event."""
        try:
            detection = rule.get("detection")

            if not isinstance(detection, dict):
                raise SigmaEvaluationError(
                    "Sigma rule must contain a detection mapping."
                )

            condition = detection.get("condition")

            if not isinstance(condition, str) or not condition.strip():
                raise SigmaEvaluationError(
                    "Sigma detection must contain a condition string."
                )

            selections = {
                name: value
                for name, value in detection.items()
                if name != "condition"
            }

            event_fields = cls._flatten_event(event)
            matched = cls._evaluate_condition(
                condition,
                selections,
                event_fields,
            )

            return {
                "rule_id": rule.get("id") or rule.get("rule_id"),
                "matched": matched,
                "evaluator_version": EVALUATOR_VERSION,
                "reason": (
                    "Rule matched event."
                    if matched
                    else "Rule did not match event."
                ),
            }

        except SigmaEvaluationError:
            raise
        except Exception as exc:
            raise SigmaEvaluationError(
                f"Failed to evaluate Sigma rule: {exc}"
            ) from exc
