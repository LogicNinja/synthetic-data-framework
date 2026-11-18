"""Plan, generate, and critique one scenario with bounded revision attempts."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
import time
from typing import Any, Callable

from synthetic_data.agents.critic_agent import CriticAgent, CriticResult
from synthetic_data.agents.planner_agent import PlannerAgent, ScenarioPlan
from synthetic_data.agents.scenario_agent import ScenarioAgent, ScenarioGenerationResult
from synthetic_data.scenarios.spec import ScenarioSpecError


@dataclass(frozen=True)
class GenerationWorkflowResult:
    """Generated artifact and review trail; this is not a validated dataset."""

    plan: ScenarioPlan
    generation: ScenarioGenerationResult
    critic_history: tuple[CriticResult, ...]
    critic_accepted: bool
    quality_report: dict[str, Any] = field(default_factory=dict)


class GenerationWorkflow:
    """Run planner → scenario agent → critic and retry actionable revisions."""

    def __init__(
        self,
        planner: PlannerAgent,
        scenario_agent: ScenarioAgent,
        critic: CriticAgent,
        *,
        max_attempts: int = 3,
        progress_callback: Callable[[str], None] | None = None,
    ) -> None:
        if max_attempts < 1 or max_attempts > 5:
            raise ValueError("max_attempts must be between 1 and 5.")
        self.planner = planner
        self.scenario_agent = scenario_agent
        self.critic = critic
        self.max_attempts = max_attempts
        self.progress_callback = progress_callback

    def run(
        self,
        request: str,
        *,
        coverage_gaps: list[str] | None = None,
        hard_cases: list[str] | None = None,
        existing_scenarios: list[dict[str, Any]] | None = None,
        image_paths: list[str | Path] | None = None,
        scenario_constraints: dict[str, Any] | None = None,
        scenario_requirements: dict[str, Any] | None = None,
    ) -> GenerationWorkflowResult:
        workflow_started = time.perf_counter()
        plan = self.planner.run(
            request,
            coverage_gaps=coverage_gaps,
            hard_cases=hard_cases,
            generation_budget=1,
            image_paths=image_paths,
        )
        plan_data = dict(plan.data)
        for key in ("label", "technique_ids"):
            if scenario_constraints and key in scenario_constraints:
                plan_data[key] = scenario_constraints[key]
        if scenario_constraints and "technique_labels" in scenario_constraints:
            plan_data["technique_ids"] = scenario_constraints["technique_labels"]
        if scenario_requirements:
            plan_data["caller_requirements"] = scenario_requirements
        plan = ScenarioPlan(data=plan_data, model=plan.model)
        history: list[CriticResult] = []
        generation_latencies: list[float] = []
        critic_latencies: list[float] = []
        feedback: str | None = None
        generation: ScenarioGenerationResult | None = None

        for attempt in range(1, self.max_attempts + 1):
            if self.progress_callback is not None:
                self.progress_callback(f"  Attempt {attempt}/{self.max_attempts}: generate candidate")
            generation_started = time.perf_counter()
            scenario_kwargs = dict(scenario_constraints or {})
            scenario_kwargs.update({
                "label": plan.data["label"],
                "technique_labels": (
                    (scenario_constraints or {}).get("technique_labels")
                    if (scenario_constraints or {}).get("technique_labels") is not None
                    else plan.data.get("technique_ids", [])
                    if plan.data.get("label") == "malicious"
                    else []
                ),
                "plan": plan.data,
                "feedback": feedback,
                "image_paths": image_paths,
                "requirements": scenario_requirements,
            })
            try:
                generation = self.scenario_agent.run(
                    request, **scenario_kwargs
                )
            except (ScenarioSpecError, ValueError) as error:
                generation_latencies.append(time.perf_counter() - generation_started)
                generation = ScenarioGenerationResult({}, "deterministic-validator")
                review = CriticResult(
                    decision="revise",
                    findings=(),
                    coverage_assessment="Scenario did not pass deterministic specification checks.",
                    realism_assessment="Not assessed.",
                    diversity_assessment="Not assessed.",
                    label_caveat="Configured labels require domain review.",
                    model="deterministic-validator",
                    structural_errors=(str(error),),
                )
                history.append(review)
                feedback = review.feedback_text()
                if self.progress_callback is not None:
                    self.progress_callback(f"  Attempt {attempt}: specification issue; feeding repair note into retry: {feedback}")
                continue
            generation_latencies.append(time.perf_counter() - generation_started)
            critic_started = time.perf_counter()
            review = self.critic.run(
                generation.spec,
                request=request,
                plan=plan.data,
                existing_scenarios=existing_scenarios,
                image_paths=image_paths,
            )
            critic_latencies.append(time.perf_counter() - critic_started)
            history.append(review)
            if review.accepted:
                if self.progress_callback is not None:
                    self.progress_callback(f"  Attempt {attempt}: Critic accepted candidate")
                break
            feedback = review.feedback_text()
            if self.progress_callback is not None:
                self.progress_callback(f"  Attempt {attempt}: Critic requested revision; feedback sent to Scenario Agent: {feedback}")

        assert generation is not None
        accepted = bool(history and history[-1].accepted)
        rejection_reasons = [
            finding["issue"]
            for review in history
            if not review.accepted
            for finding in review.findings
        ] + [
            error
            for review in history
            if not review.accepted
            for error in review.structural_errors
        ]
        rejected_count = sum(not review.accepted for review in history)
        rubric_keys = ("accuracy", "diversity", "realism", "consistency", "completeness")
        mean_rubric_scores = {
            key: round(mean(review.rubric_scores[key] for review in history if key in review.rubric_scores), 3)
            for key in rubric_keys
            if any(key in review.rubric_scores for review in history)
        }
        quality_report = {
            "samples_evaluated": len(history),
            "accepted": int(accepted),
            "rejected": rejected_count,
            "acceptance_rate": int(accepted) / len(history) if history else 0.0,
            "generation_latency_seconds": round(sum(generation_latencies), 4),
            "critic_latency_seconds": round(sum(critic_latencies), 4),
            "workflow_latency_seconds": round(time.perf_counter() - workflow_started, 4),
            "critic_scores": mean_rubric_scores,
            "rejection_reasons": rejection_reasons,
            "discarded_after_retry_limit": not accepted,
            "four_layer_validation": {
                key: {"status": "not_run", "reason": "Scenario has not entered dataset validation."}
                for key in ("L1", "L2", "L3", "L4")
            },
            "rubric": [
                {
                    "accuracy": review.accuracy_assessment,
                    "diversity": review.diversity_assessment,
                    "realism": review.realism_assessment,
                    "consistency": review.consistency_assessment,
                    "completeness": review.completeness_assessment,
                    "scores": review.rubric_scores,
                }
                for review in history
            ],
        }
        return GenerationWorkflowResult(
            plan=plan,
            generation=generation,
            critic_history=tuple(history),
            critic_accepted=accepted,
            quality_report=quality_report,
        )
