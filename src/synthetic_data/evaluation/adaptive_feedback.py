"""One bounded Defender → Adversary → generation feedback cycle."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Sequence
from uuid import uuid4

from synthetic_data.agents.adversary_agent import AdversaryAgent
from synthetic_data.agents.workflow import GenerationWorkflow
from synthetic_data.defender.model import event_label_from_ground_truth
from synthetic_data.serialization.event_serializer import read_jsonl
from synthetic_data.storage.dataset_store import DatasetStore
from synthetic_data.validation.four_layer import (
    FourLayerValidationReport,
    ValidationCriteria,
    aggregate_validation_reports,
    build_four_layer_report,
)


@dataclass(frozen=True)
class AdaptiveCycleResult:
    initial_evaluation: dict[str, Any]
    adversarial_proposal: dict[str, Any] | None
    generation_outcomes: tuple[dict[str, Any], ...]
    augmented_event_count: int
    final_evaluation: dict[str, Any] | None
    macro_f1_delta: float | None
    validation_report: dict[str, Any] | None = None
    final_dataset_path: str | None = None


class AdaptiveFeedbackCycle:
    """Evaluate held-out failures and feed accepted, validated scenarios back.

    The caller supplies a scenario/environment-separated held-out set. New
    simulator events enter training only after critic acceptance and the
    existing L1-L3 pipeline gates succeed. The final held-out score measures
    utility for this one round; it does not guarantee future improvement.
    """

    def __init__(
        self,
        defender: Any,
        adversary: AdversaryAgent,
        generation_workflow: GenerationWorkflow,
        *,
        pipeline_runner: Callable[..., Any] | None = None,
        dataset_loader: Callable[[str | Path], list[Any]] = read_jsonl,
        rules: list[dict[str, Any]] | None = None,
        reference_path: str | Path | None = None,
        validation_criteria: ValidationCriteria | None = None,
    ) -> None:
        self.defender = defender
        self.adversary = adversary
        self.generation_workflow = generation_workflow
        if pipeline_runner is None:
            from synthetic_data.pipeline.runner import run_pipeline
            pipeline_runner = run_pipeline
        self.pipeline_runner = pipeline_runner
        self.dataset_loader = dataset_loader
        self.rules = rules or []
        self.reference_path = reference_path
        self.validation_criteria = validation_criteria or ValidationCriteria()

    def run(
        self,
        *,
        training_events: Sequence[Any],
        heldout_events: Sequence[Any],
        training_labels: Sequence[str] | None = None,
        heldout_labels: Sequence[str] | None = None,
    ) -> AdaptiveCycleResult:
        self.defender.fit(training_events, training_labels)
        initial = self.defender.evaluate(heldout_events, heldout_labels)
        failures = [
            *initial.get("false_negatives", []),
            *initial.get("false_positives", []),
        ]
        if not failures:
            return AdaptiveCycleResult(initial, None, (), 0, initial, 0.0)

        proposal = self.adversary.run(failures)
        generated_training: list[Any] = []
        outcomes: list[dict[str, Any]] = []
        candidate_reports: list[tuple[Any, Any]] = []
        pre_utility_reports: list[FourLayerValidationReport] = []
        accepted_scenarios: list[dict[str, Any]] = []
        for index, item in enumerate(proposal.data["scenario_requests"], start=1):
            generated = self.generation_workflow.run(
                item["scenario_request"],
                coverage_gaps=[proposal.data["weakness_summary"]],
                hard_cases=[item["hard_case"]],
                existing_scenarios=accepted_scenarios,
            )
            outcome: dict[str, Any] = {
                "target_failure_ids": item["target_failure_ids"],
                "scenario_request": item["scenario_request"],
                "critic_accepted": generated.critic_accepted,
                "quality_report": generated.quality_report,
                "pipeline_ok": False,
                "rejection_reasons": [],
                "saved_path": None,
            }
            if not generated.critic_accepted:
                outcome["rejection_reasons"].extend(
                    generated.quality_report.get("rejection_reasons", [])
                )
                if not outcome["rejection_reasons"]:
                    outcome["rejection_reasons"].append("critic did not accept scenario")
                outcome["discarded"] = True
                outcomes.append(outcome)
                continue

            pipeline_report = self.pipeline_runner(
                generated.generation.spec,
                self.rules,
                run_id=f"adaptive-{uuid4().hex}",
                reference_path=self.reference_path,
                critic_accepted=generated.critic_accepted,
                validation_criteria=self.validation_criteria,
            )
            candidate_reports.append((pipeline_report, generated))
            reference_report = SimpleNamespace(
                status=pipeline_report.reference_realism_status,
                similarity_score=pipeline_report.reference_similarity_score,
                reference_event_count=pipeline_report.reference_event_count,
                sample_adequacy=pipeline_report.reference_sample_adequacy,
                errors=pipeline_report.reference_realism_errors,
            )
            pre_validation = build_four_layer_report(
                criteria=self.validation_criteria,
                provenance_errors=pipeline_report.provenance_errors,
                schema_errors=pipeline_report.schema_errors,
                domain_errors=pipeline_report.domain_realism_errors,
                domain_warnings=pipeline_report.domain_realism_warnings,
                roundtrip_ok=pipeline_report.roundtrip_ok,
                rules_failed_to_load=pipeline_report.rules_failed_to_load,
                unsupported_sigma_evaluations=pipeline_report.unsupported_evaluations,
                reference_report=reference_report,
                critic_accepted=generated.critic_accepted,
                utility_report=None,
            )
            pre_utility_reports.append(pre_validation)
            outcome["pipeline_ok"] = bool(pipeline_report.ok)
            outcome["four_layer_validation"] = getattr(
                pipeline_report, "validation_report", pre_validation.to_dict()
            )
            outcome["l1_l3_pass"] = all(
                pre_validation.layers[key].status == "passed"
                for key in ("L1", "L2", "L3")
            )
            outcome["saved_path"] = pipeline_report.saved_path
            outcome["rejection_reasons"] = [
                *pipeline_report.provenance_errors,
                *[
                    f"{event_id}: {error}"
                    for event_id, errors in pipeline_report.schema_errors.items()
                    for error in errors
                ],
                *pipeline_report.domain_realism_errors,
            ]
            if (
                pipeline_report.ok
                and outcome["l1_l3_pass"]
                and pipeline_report.saved_path
            ):
                generated_training.extend(self.dataset_loader(pipeline_report.saved_path))
                accepted_scenarios.append(generated.generation.spec)
            outcomes.append(outcome)

        if not generated_training:
            incomplete_report = aggregate_validation_reports(
                pre_utility_reports,
                criteria=self.validation_criteria,
            )
            return AdaptiveCycleResult(
                initial,
                proposal.data,
                tuple(outcomes),
                0,
                None,
                None,
                validation_report=incomplete_report.to_dict(),
            )

        augmented_events = [*training_events, *generated_training]
        augmented_labels = (
            [*training_labels]
            if training_labels is not None
            else [event_label_from_ground_truth(event) for event in training_events]
        )
        augmented_labels.extend(
            event_label_from_ground_truth(event) for event in generated_training
        )
        self.defender.fit(augmented_events, augmented_labels)
        final = self.defender.evaluate(heldout_events, heldout_labels)
        delta = final["macro_f1"] - initial["macro_f1"]

        utility_report = {
            "macro_f1": final["macro_f1"],
            "macro_f1_delta": delta,
        }
        sample_validation_reports: list[FourLayerValidationReport] = []
        for pipeline_report, generated in candidate_reports:
            reference_report = SimpleNamespace(
                status=pipeline_report.reference_realism_status,
                similarity_score=pipeline_report.reference_similarity_score,
                reference_event_count=pipeline_report.reference_event_count,
                sample_adequacy=pipeline_report.reference_sample_adequacy,
                errors=pipeline_report.reference_realism_errors,
            )
            sample_report = build_four_layer_report(
                criteria=self.validation_criteria,
                provenance_errors=pipeline_report.provenance_errors,
                schema_errors=pipeline_report.schema_errors,
                domain_errors=pipeline_report.domain_realism_errors,
                domain_warnings=pipeline_report.domain_realism_warnings,
                roundtrip_ok=pipeline_report.roundtrip_ok,
                rules_failed_to_load=pipeline_report.rules_failed_to_load,
                unsupported_sigma_evaluations=pipeline_report.unsupported_evaluations,
                reference_report=reference_report,
                critic_accepted=generated.critic_accepted,
                utility_report=utility_report,
            )
            sample_validation_reports.append(sample_report)
            for outcome in outcomes:
                if outcome.get("saved_path") == pipeline_report.saved_path:
                    outcome["four_layer_validation"] = sample_report.to_dict()
                    outcome["rejection_reasons"].extend(
                        error for layer in sample_report.layers.values() for error in layer.errors
                    )
                    break
            if pipeline_report.saved_path:
                filename = Path(pipeline_report.saved_path).name
                DatasetStore.update_metadata(
                    "generated",
                    filename,
                    {
                        "validation_status": sample_report.decision,
                        "validated": sample_report.validated,
                        "validation_report": sample_report.to_dict(),
                    },
                )

        batch_validation = aggregate_validation_reports(
            sample_validation_reports,
            criteria=self.validation_criteria,
        )
        final_dataset_path = None
        if batch_validation.validated:
            final_filename = f"adaptive_{uuid4().hex}.jsonl"
            DatasetStore.DATASET_TYPES["final"].mkdir(parents=True, exist_ok=True)
            final_path = DatasetStore.save(
                generated_training,
                "final",
                final_filename,
                metadata={
                    "generation_method": "defender_adversary_feedback",
                    "validation_status": batch_validation.decision,
                    "validated": batch_validation.validated,
                    "validation_report": batch_validation.to_dict(),
                    "heldout_macro_f1": final["macro_f1"],
                    "macro_f1_delta": delta,
                },
            )
            final_dataset_path = str(final_path)
        return AdaptiveCycleResult(
            initial_evaluation=initial,
            adversarial_proposal=proposal.data,
            generation_outcomes=tuple(outcomes),
            augmented_event_count=len(generated_training),
            final_evaluation=final,
            macro_f1_delta=delta,
            validation_report=batch_validation.to_dict(),
            final_dataset_path=final_dataset_path,
        )
