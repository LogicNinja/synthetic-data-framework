"""Critique scenario drafts after deterministic structural validation."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from synthetic_data.agents.base import BaseAgent
from synthetic_data.agents.client import GrokResponsesClient
from synthetic_data.scenarios.spec import ScenarioSpecError, validate_spec


CRITIC_SYSTEM_PROMPT = """You are a cautious quality critic for simulated Windows telemetry scenarios.
Review accuracy, diversity, realism, consistency, and completeness. Check
that claims and labels are supported by the supplied plan and scenario,
actions are plausible and internally consistent, variation is meaningful,
and required fields are present. Do not claim to prove ATT&CK labels correct:
labels in a scenario are configured ground truth and need independent domain
review. Raw event records do not need a toxicity score; flag harmful or toxic
natural-language content only when evaluating text intended for model
training. Return exactly
the supplied JSON shape. Give specific, repairable recommendations. Do not
claim to prove ATT&CK labels correct: labels in a scenario are configured
ground truth and need independent domain review. Do not ask for real attack
execution or destructive host actions. Structural validity is checked
separately by code; focus on coverage and domain plausibility. Score each
rubric dimension from 1 to 5: 1 means materially incorrect or absent, 3 means
mixed or uncertain, and 5 means strong and well supported. Use 2 and 4 for
intermediate cases. Keep scores consistent with findings and decision. Do not
invent required fields, actions, event types, timestamps, or process names.
Before claiming something is missing, verify it is absent from the draft. The
application checks schema and explicit caller requirements separately. If the
prior scenario list is empty, do not ask for prior summaries or reject for lack
of a cross-scenario comparison; assess only whether this draft offers a
meaningful scenario on its own. For every finding, cite the specific action
or field that supports it."""


class CriticError(ValueError):
    """Raised when critic output is malformed or unusable."""


@dataclass(frozen=True)
class CriticResult:
    """Structured critic decision and its audit context."""

    decision: str
    findings: tuple[dict[str, str], ...]
    coverage_assessment: str
    realism_assessment: str
    diversity_assessment: str
    label_caveat: str
    model: str
    accuracy_assessment: str = "Not assessed."
    consistency_assessment: str = "Not assessed."
    completeness_assessment: str = "Not assessed."
    rubric_scores: dict[str, int] = field(default_factory=dict)
    structural_errors: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        return self.decision == "accept" and not self.structural_errors

    def feedback_text(self) -> str:
        if self.structural_errors:
            return "Fix these deterministic specification errors, preserving all caller constraints:\n" + "\n".join(
                f"- {error}" for error in self.structural_errors
            )
        actionable = [
            finding for finding in self.findings
            if finding.get("recommendation", "").strip()
        ]
        if not actionable:
            return (
                "Regenerate a meaningfully different scenario that still meets "
                "the original request and all caller constraints."
            )
        return "Address only these specific findings; preserve all caller constraints:\n" + "\n".join(
            f"- Finding: {finding['issue']} Repair: {finding['recommendation']}"
            for finding in actionable
        )


class CriticAgent(BaseAgent):
    """Reject invalid specs in code, then use an LLM for qualitative review."""

    def __init__(self, client: Any | None = None) -> None:
        super().__init__(client or GrokResponsesClient())
        self.schema_path = Path(__file__).with_name("schemas") / "critic_output.schema.json"

    def run(
        self,
        spec: dict[str, Any],
        *,
        request: str,
        plan: dict[str, Any] | None = None,
        existing_scenarios: list[dict[str, Any]] | None = None,
        image_paths: list[str | Path] | None = None,
    ) -> CriticResult:
        structural_errors: list[str] = []
        try:
            validate_spec(spec)
        except Exception as error:
            structural_errors.append(str(error))
        if structural_errors:
            return CriticResult(
                decision="reject",
                findings=(),
                coverage_assessment="Not assessed because structural validation failed.",
                realism_assessment="Not assessed because structural validation failed.",
                diversity_assessment="Not assessed because structural validation failed.",
                accuracy_assessment="Not assessed because structural validation failed.",
                consistency_assessment="Not assessed because structural validation failed.",
                completeness_assessment="Not assessed because structural validation failed.",
                label_caveat="Configured technique labels are not independently verified.",
                model="deterministic-validator",
                structural_errors=tuple(structural_errors),
            )

        schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        existing = existing_scenarios or []
        duplicate_of, duplicate_score = self._nearest_duplicate(spec, existing)
        user_prompt = (
            f"Request:\n{request}\n\n"
            f"Planner output:\n{json.dumps(plan or {}, ensure_ascii=False, indent=2)}\n\n"
            f"Scenario draft:\n{json.dumps(spec, ensure_ascii=False, indent=2)}\n\n"
            "Prior scenario summaries for diversity comparison:\n"
            f"{json.dumps([self._scenario_summary(item) for item in existing[:20]], ensure_ascii=False, indent=2)}\n\n"
            "Accept only if the draft is coherent and meaningfully addresses "
            "the request. Use revise for specific repairable gaps; reject for "
            "fundamental mismatch. State uncertainty explicitly. Verify each "
            "claimed gap against the supplied draft and request."
        )
        client_kwargs = {
            "system_prompt": CRITIC_SYSTEM_PROMPT,
            "user_prompt": user_prompt,
            "schema_name": "scenario_critic_review",
            "schema": schema,
        }
        if image_paths:
            client_kwargs["image_paths"] = image_paths
        review = self.client.generate_json(**client_kwargs)
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(review),
            key=lambda error: list(map(str, error.absolute_path)),
        )
        if errors:
            raise CriticError(
                "Critic returned invalid output: "
                + "; ".join(error.message for error in errors)
            )

        findings = [
            finding
            for finding in review["findings"]
            if self._finding_is_grounded(
                finding,
                spec=spec,
                plan=plan or {},
                request=request,
                existing=existing,
            )
        ]
        decision = review["decision"]
        # A small local critic can emit a generic checklist that contradicts
        # the already validated draft (for example, claiming a timestamp is
        # absent). A revision decision with no grounded finding is not
        # actionable, so admit the draft to the remaining validation gates.
        ungrounded_revision = decision == "revise" and not findings
        if ungrounded_revision:
            decision = "accept"
        low_scores = [
            dimension for dimension, score in review["rubric_scores"].items()
            if score <= 2
        ]
        if decision == "accept" and low_scores and not ungrounded_revision:
            decision = "revise"
            findings.append({
                "severity": "high",
                "issue": "Low rubric score for: " + ", ".join(sorted(low_scores)) + ".",
                "recommendation": "Address the low-scoring quality dimensions before acceptance.",
            })
        if duplicate_of is not None:
            diversity_assessment = (
                f"Deterministic comparison found a near-duplicate of "
                f"{duplicate_of} (behavior similarity {duplicate_score:.2f})."
            )
            findings.append({
                "severity": "high",
                "issue": (
                    f"Scenario is a near-duplicate of {duplicate_of} "
                    f"(behavior similarity {duplicate_score:.2f})."
                ),
                "recommendation": (
                    "Change the action sequence or executable/process "
                    "relationship to add meaningful behavioral variety."
                ),
            })
            if decision == "accept":
                decision = "revise"
        else:
            diversity_assessment = review["diversity_assessment"]
        # Do not allow a confident accept while the same review contains a
        # high-severity issue. Require another generation pass to address it.
        if decision == "accept" and any(
            finding["severity"] == "high" for finding in findings
        ):
            decision = "revise"
        return CriticResult(
            decision=decision,
            findings=tuple(findings),
            coverage_assessment=review["coverage_assessment"],
            realism_assessment=review["realism_assessment"],
            diversity_assessment=diversity_assessment,
            accuracy_assessment=review["accuracy_assessment"],
            consistency_assessment=review["consistency_assessment"],
            completeness_assessment=review["completeness_assessment"],
            rubric_scores=review["rubric_scores"],
            label_caveat=review["label_caveat"],
            model=getattr(getattr(self.client, "config", None), "model", "injected-client"),
        )

    @staticmethod
    def _finding_is_grounded(
        finding: dict[str, str],
        *,
        spec: dict[str, Any],
        plan: dict[str, Any],
        request: str,
        existing: list[dict[str, Any]],
    ) -> bool:
        """Reject generic claims contradicted by deterministic input evidence."""
        issue = str(finding.get("issue", "")).casefold()
        steps = [step for step in spec.get("steps", []) if isinstance(step, dict)]
        has_timestamps = bool(steps) and all(step.get("timestamp") for step in steps)
        has_parent_child = any(
            step.get("action") == "spawn_child" and step.get("parent_process_id")
            for step in steps
        )
        has_file_actions = any(step.get("action") in {"create_file", "modify_file"} for step in steps)

        if "timestamp" in issue and has_timestamps:
            return False
        if "parent-child" in issue and has_parent_child:
            return False
        if "creation of the file" in issue and not has_file_actions:
            return False
        if "coverage gap" in issue and plan.get("coverage_gaps"):
            return False
        if "hard case" in issue and plan.get("hard_cases"):
            return False
        if "generation budget" in issue and plan.get("generation_budget"):
            return False
        if "scenario request" in issue and request.strip():
            return False
        if "diversity" in issue and not existing:
            return False
        if "inconsistent label" in issue:
            return False
        return True

    @staticmethod
    def _scenario_summary(spec: dict[str, Any]) -> dict[str, Any]:
        steps = spec.get("steps", [])
        process_relationships = []
        command_shapes = []
        technique_labels = set()
        for step in steps:
            if not isinstance(step, dict):
                continue
            child = Path(str(step.get("image", ""))).name.casefold()
            parent = Path(str(step.get("parent_image", ""))).name.casefold()
            if parent or child:
                process_relationships.append(f"{parent or '<root>'}->{child or '<unknown>'}")
            command = " ".join(str(step.get("command_line", "")).casefold().split())
            if command:
                command_shapes.append(command)
            technique_labels.update(step.get("technique_labels", []))
        return {
            "scenario_id": spec.get("scenario_id", "unknown"),
            "label": spec.get("label", "unknown"),
            "actions": [step.get("action", "") for step in steps if isinstance(step, dict)],
            "process_images": [
                Path(str(step.get("image", ""))).name.casefold()
                for step in steps
                if isinstance(step, dict) and step.get("image")
            ],
            "process_relationships": process_relationships,
            "command_shapes": command_shapes,
            "technique_labels": sorted(technique_labels),
        }

    @classmethod
    def _nearest_duplicate(
        cls,
        spec: dict[str, Any],
        existing: list[dict[str, Any]],
        *,
        threshold: float = 0.9,
    ) -> tuple[str | None, float]:
        candidate = cls._scenario_summary(spec)
        candidate_actions = set(candidate["actions"])
        candidate_images = set(candidate["process_images"])
        candidate_features = (
            {f"action:{value}" for value in candidate_actions}
            | {f"image:{value}" for value in candidate_images}
            | {f"relationship:{value}" for value in candidate["process_relationships"]}
            | {f"command:{value}" for value in candidate["command_shapes"]}
            | {f"technique:{value}" for value in candidate["technique_labels"]}
        )
        best_id: str | None = None
        best_score = 0.0
        for index, prior in enumerate(existing):
            summary = cls._scenario_summary(prior)
            prior_features = (
                {f"action:{value}" for value in set(summary["actions"])}
                | {f"image:{value}" for value in set(summary["process_images"])}
                | {f"relationship:{value}" for value in summary["process_relationships"]}
                | {f"command:{value}" for value in summary["command_shapes"]}
                | {f"technique:{value}" for value in summary["technique_labels"]}
            )
            union = candidate_features | prior_features
            score = len(candidate_features & prior_features) / len(union) if union else 1.0
            if score > best_score:
                best_id = str(summary["scenario_id"] or f"prior-{index + 1}")
                best_score = score
        return (best_id, best_score) if best_score >= threshold else (None, best_score)
