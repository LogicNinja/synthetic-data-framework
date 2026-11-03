
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_PATH = Path(__file__).with_name("event.schema.json")


def load_schema() -> dict:
    """Load the canonical event schema."""
    with SCHEMA_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def validate_event(event: dict) -> list[str]:
    """Return validation errors for a canonical event."""
    schema = load_schema()

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    errors = sorted(
        validator.iter_errors(event),
        key=lambda error: list(error.absolute_path),
    )

    return [
        f"{'/'.join(map(str, error.absolute_path)) or '<root>'}: "
        f"{error.message}"
        for error in errors
    ]


def validate_event_or_raise(event: dict) -> None:
    """Raise ValueError if the event does not satisfy the schema."""
    errors = validate_event(event)

    if errors:
        raise ValueError("Event validation failed:\n" + "\n".join(errors))
