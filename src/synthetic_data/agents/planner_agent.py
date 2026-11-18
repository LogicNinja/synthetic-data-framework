"""Plan scenario generation around requested scope and known coverage gaps."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from synthetic_data.agents.base import BaseAgent
from synthetic_data.agents.client import GrokResponsesClient
from synthetic_data.scenarios.spec import ScenarioSpecError


PLANNER_SYSTEM_PROMPT = """You are the Planner Agent for a controlled Windows telemetry simulator.
Produce one concise structured plan for the user's request. Choose attack or
benign label, identify relevant techniques only when reasonably supported,
and prioritize explicit coverage gaps and hard cases. The budget is a limit
on scenario count, not a request to exceed the user's scope. All output is a
plan for simulated events; never recommend executing actions on a real host.
Technique IDs in your plan are hypotheses for scenario design, not verified
ground truth. Do not claim that they were externally checked."""


@dataclass(frozen=True)
class ScenarioPlan:
    """Schema-validated planner output."""

    data: dict[str, Any]
    model: str


class PlannerAgent(BaseAgent):
    """Create a machine-readable generation plan using the shared client API."""

    def __init__(self, client: Any | None = None) -> None:
        super().__init__(client or GrokResponsesClient())
        self.schema_path = Path(__file__).with_name("schemas") / "planner_output.schema.json"

    def run(
        self,
        request: str,
        *,
        coverage_gaps: list[str] | None = None,
        hard_cases: list[str] | None = None,
        generation_budget: int = 1,
        image_paths: list[str | Path] | None = None,
    ) -> ScenarioPlan:
        if not isinstance(request, str) or not request.strip():
            raise ValueError("request must be a non-empty string.")
        if not 1 <= generation_budget <= 20:
            raise ValueError("generation_budget must be between 1 and 20.")

        schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        user_prompt = (
            f"User request:\n{request.strip()}\n\n"
            "Known coverage gaps:\n"
            f"{json.dumps(coverage_gaps or [], ensure_ascii=False)}\n\n"
            "Required hard cases:\n"
            f"{json.dumps(hard_cases or [], ensure_ascii=False)}\n\n"
            f"Maximum scenario budget: {generation_budget}.\n"
            "Return a plan for one scenario within that budget. Preserve the "
            "user's intent and avoid adding unsupported attack behavior."
        )
        kwargs = {
            "system_prompt": PLANNER_SYSTEM_PROMPT,
            "user_prompt": user_prompt,
            "schema_name": "windows_scenario_plan",
            "schema": schema,
        }
        if image_paths:
            kwargs["image_paths"] = image_paths
        plan = self.client.generate_json(**kwargs)
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(plan),
            key=lambda error: list(map(str, error.absolute_path)),
        )
        if errors:
            raise ScenarioSpecError(
                "Planner returned invalid output: "
                + "; ".join(error.message for error in errors)
            )
        return ScenarioPlan(
            data=plan,
            model=getattr(getattr(self.client, "config", None), "model", "injected-client"),
        )
