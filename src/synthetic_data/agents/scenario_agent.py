"""Scenario Planner/Generator Agent aligned with the repository's declarative specs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass
from typing import Any

from synthetic_data.agents.base import BaseAgent
from synthetic_data.agents.client import GrokResponsesClient
from synthetic_data.scenarios.spec import ScenarioSpecError, validate_spec


SYSTEM_PROMPT = """You are the Scenario Planner and Generator for a Windows endpoint
security telemetry simulator. Return exactly one declarative scenario object
matching the supplied JSON schema. Do not return markdown or commentary.

Repository constraints:
- Top-level fields are scenario_id, optional description, hostname, username,
  label, and ordered steps only.
- Allowed actions are start_process, spawn_child, create_file, modify_file.
- start_process requires process_id, image, command_line, original_file_name, timestamp.
- spawn_child requires those same fields plus parent_process_id. Its parent
  must have been started in an earlier step.
- create_file and modify_file require file_path and timestamp; modify_file
  requires the file to have been created earlier. Optional size is a
  non-negative integer.
- Every timestamp must be ISO-8601, use a consistent UTC-offset convention,
  and be non-decreasing.
- Every process_id must be unique. Use realistic Windows paths and process
  names. Keep command lines plausible and avoid destructive or live actions:
  this is a declarative simulation, not an instruction to execute commands.
- A malicious scenario must have at least one technique_labels entry across
  its steps. A benign scenario must have no technique labels.
- Technique labels must be MITRE ATT&CK technique IDs (for example T1059.001)
  only when the mapping is reasonably well-supported by the described action.
  Do not invent IDs merely to satisfy the schema.

Important epistemic constraint: the simulator records the labels supplied in
this spec as configured ground-truth labels and the provenance validator
checks that they survive execution. That does NOT independently prove that
an LLM-suggested ATT&CK mapping is correct. Be conservative; describe the
scenario accurately and do not claim external verification."""


@dataclass(frozen=True)
class ScenarioGenerationResult:
    """Generated spec plus traceable generation metadata."""

    spec: dict[str, Any]
    model: str
    agent_name: str = "scenario_agent"


class ScenarioAgent(BaseAgent):
    """Generate specs accepted by the existing ``scenarios.spec`` module.

    The returned spec is validated with the repository's existing validator.
    This agent deliberately does not run the pipeline automatically: generated
    labels should be reviewed before being treated as trusted ground truth.
    """

    def __init__(self, client: Any | None = None) -> None:
        super().__init__(client or GrokResponsesClient())

    def run(
        self,
        request: str,
        *,
        scenario_id: str | None = None,
        hostname: str = "WS-SYNTH-001",
        username: str = "synthetic_user",
        label: str | None = None,
        technique_labels: list[str] | None = None,
        start_timestamp: str | None = None,
    ) -> ScenarioGenerationResult:
        """Generate and validate one scenario specification.

        ``technique_labels`` can pin labels supplied by a trusted caller. When
        omitted, Grok may propose conservative labels for malicious scenarios;
        those proposals still require human/domain review.
        """
        if not isinstance(request, str) or not request.strip():
            raise ValueError("request must be a non-empty string.")
        if label is not None and label not in {"malicious", "benign"}:
            raise ValueError("label must be 'malicious' or 'benign'.")
        if label == "benign" and technique_labels:
            raise ValueError("A benign scenario cannot have technique labels.")
        if technique_labels is not None and not all(
            isinstance(item, str) and item.strip() for item in technique_labels
        ):
            raise ValueError("technique_labels must contain non-empty strings.")

        constraints = {
            "scenario_id": scenario_id,
            "hostname": hostname,
            "username": username,
            "label": label,
            "technique_labels": technique_labels,
            "start_timestamp": start_timestamp,
        }
        user_prompt = (
            "Create one scenario for this request.\n"
            f"Request: {request.strip()}\n"
            "Caller constraints (use supplied non-null values exactly):\n"
            f"{json.dumps(constraints, ensure_ascii=False, indent=2)}\n"
            "Use only the actions and fields supported by the schema. For a "
            "process chain, start the parent before spawning its child. "
            "Generate a concise, unique scenario_id if none was supplied. "
            "Use the supplied start_timestamp for the first step and advance "
            "timestamps monotonically. If label is unspecified, infer whether "
            "the described activity is malicious or benign."
        )
        schema_path = (
            Path(__file__).with_name("schemas") / "scenario_spec.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        generated = self.client.generate_json(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            schema_name="windows_scenario_spec",
            schema=schema,
        )

        # Caller-supplied values are authoritative, not suggestions to the LLM.
        for key in ("scenario_id", "hostname", "username", "label"):
            if constraints[key] is not None and generated.get(key) != constraints[key]:
                raise ScenarioSpecError(
                    f"Generated {key!r} does not match the caller-supplied value."
                )
        if technique_labels is not None:
            generated_labels = sorted({
                label for step in generated.get("steps", [])
                for label in step.get("technique_labels", [])
            })
            if generated_labels != sorted(set(technique_labels)):
                raise ScenarioSpecError(
                    "Generated technique labels do not match caller-supplied labels."
                )

        validate_spec(generated)
        return ScenarioGenerationResult(
            spec=generated,
            model=getattr(
                getattr(self.client, "config", None),
                "model",
                "injected-client",
            ),
        )

    def generate(self, request: str, **kwargs: Any) -> ScenarioGenerationResult:
        """Readable alias for ``run``."""
        return self.run(request, **kwargs)
