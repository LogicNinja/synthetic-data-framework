"""Coordinate request → agents → simulator → validation → fine-tuning export."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any, Callable, Sequence
from uuid import uuid4

from jsonschema import Draft202012Validator, FormatChecker

from synthetic_data.agents.workflow import GenerationWorkflow
from synthetic_data.defender.model import DefenderModel
from synthetic_data.evaluation.diversity import benchmark_dataset_diversity
from synthetic_data.evaluation.quality_benchmark import benchmark_dataset_quality
from synthetic_data.fine_tuning import convert_validated_telemetry
from synthetic_data.serialization.event_serializer import read_jsonl
from synthetic_data.storage.dataset_store import DatasetStore
from synthetic_data.validation.four_layer import (
    FourLayerValidationReport,
    ValidationCriteria,
    aggregate_validation_reports,
    build_four_layer_report,
)
from synthetic_data.validation.reference_realism import compare_reference_realism


@dataclass(frozen=True)
class EndToEndResult:
    report: dict[str, Any]
    final_telemetry_path: str | None
    fine_tuning_paths: dict[str, str]
    complete: bool


def validate_generation_request(request: dict[str, Any]) -> None:
    schema_path = Path(__file__).parents[3] / "configs" / "end_to_end_request.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(request))
    if errors:
        raise ValueError("Invalid generation request: " + "; ".join(error.message for error in errors))
    if len(request["labels"]) != request["scenario_count"]:
        raise ValueError("labels must contain exactly one class for each requested scenario.")
    if not any(label == "benign" for label in request["labels"]):
        raise ValueError("At least one benign scenario is required for a balanced dataset.")
    if not any(label == "malicious" for label in request["labels"]):
        raise ValueError("At least one malicious scenario is required for a balanced dataset.")
    constraints = request["constraints"]
    for positive, negative in (
        ("required_processes", "forbidden_processes"),
        ("required_actions", "forbidden_actions"),
        ("must_include", "must_not_include"),
    ):
        conflict = set(constraints.get(positive, [])) & set(constraints.get(negative, []))
        if conflict:
            raise ValueError(f"Conflicting {positive}/{negative}: {sorted(conflict)}")


def _scenario_request_text(request: dict[str, Any], label: str) -> str:
    difficulty_guidance = {
        "easy": "Use a straightforward, common behavior with clear telemetry evidence.",
        "medium": "Use a multi-step behavior with realistic process or event relationships.",
        "hard": "Use a challenging edge case with plausible benign context and less obvious evidence; preserve the specified ground truth.",
    }[request["difficulty"]]
    constraints = request["constraints"]
    class_guidance = (
        "Required behavior: include a PowerShell process in the simulated child-process chain and use the configured ATT&CK label."
        if label == "malicious"
        else "Required behavior: model ordinary benign activity and do not attach ATT&CK technique labels."
    )
    return (
        f"Attack type: {request['attack_type']}\n"
        f"Scenario: {request['scenario']}\n"
        f"Difficulty: {request['difficulty']}\n"
        f"Required class: {label}\n"
        f"{class_guidance}\n"
        f"Difficulty guidance: {difficulty_guidance}\n"
        "Explicit constraints: " + json.dumps(constraints, ensure_ascii=False, sort_keys=True)
    )


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8", newline="\n")
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def run_end_to_end(
    request: dict[str, Any],
    *,
    workflow: GenerationWorkflow,
    adversary: Any | None = None,
    reference_events: Sequence[Any],
    training_events: Sequence[Any],
    heldout_events: Sequence[Any],
    output_root: str | Path,
    rules: list[dict[str, Any]] | None = None,
    validation_criteria: ValidationCriteria | None = None,
    pipeline_runner: Callable[..., Any] | None = None,
    random_seed: int = 17,
    progress_callback: Callable[[str], None] | None = None,
) -> EndToEndResult:
    """Run one complete offline-data workflow. Agent API calls use injected workflow clients."""
    validate_generation_request(request)
    if not reference_events or not training_events or not heldout_events:
        raise ValueError("Reference, training, and held-out telemetry must all be non-empty.")
    criteria = validation_criteria or ValidationCriteria()
    root = Path(output_root)
    staging_dir = root / "staging"
    telemetry_dir = root / "telemetry"
    report_dir = root / "reports"
    root.mkdir(parents=True, exist_ok=True)

    from synthetic_data.pipeline.runner import run_pipeline
    pipeline_runner = pipeline_runner or run_pipeline
    original_generated = DatasetStore.DATASET_TYPES["generated"]
    original_final = DatasetStore.DATASET_TYPES["final"]
    DatasetStore.DATASET_TYPES["generated"] = staging_dir
    DatasetStore.DATASET_TYPES["final"] = telemetry_dir

    outcomes: list[dict[str, Any]] = []
    candidates: list[tuple[list[Any], Any, bool, dict[str, Any]]] = []
    accepted_scenarios: list[dict[str, Any]] = []
    final_telemetry_path: str | None = None
    fine_tuning_paths: dict[str, str] = {}
    try:
        baseline_model = DefenderModel().fit(training_events)
        baseline_metrics = baseline_model.evaluate(heldout_events)
        failures = [
            *baseline_metrics.get("false_negatives", []),
            *baseline_metrics.get("false_positives", []),
        ]
        adversarial_proposal = None
        adversary_error: str | None = None
        if adversary is not None and failures:
            try:
                adversarial_proposal = adversary.run(failures).data
            except (ValueError, RuntimeError) as error:
                # The user-requested generation and validation pipeline can
                # still complete if an optional LLM feedback proposal fails
                # its schema or semantic checks. Never admit that proposal.
                adversary_error = str(error)

        constraints = request["constraints"]
        prefix = re.sub(r"[^A-Za-z0-9_-]", "_", constraints.get("scenario_id_prefix", "E2E"))
        base_timestamp = constraints.get("start_timestamp")
        if base_timestamp:
            normalized = base_timestamp.replace("Z", "+00:00")
            timestamp_origin = datetime.fromisoformat(normalized)
            if timestamp_origin.tzinfo is None:
                timestamp_origin = timestamp_origin.replace(tzinfo=timezone.utc)
        else:
            timestamp_origin = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        scenario_queue = [
            {
                "label": label,
                "scenario_id": f"{prefix}_{index:03d}",
                "prompt": _scenario_request_text(request, label),
                "hard_cases": [f"Difficulty: {request['difficulty']}"],
                "technique_labels": constraints.get("technique_labels") if label == "malicious" else [],
                    "start_timestamp": (timestamp_origin + timedelta(minutes=index - 1)).isoformat(),
                "source": "user_request",
                "target_failure_ids": [],
            }
            for index, label in enumerate(request["labels"], start=1)
        ]
        if adversarial_proposal:
            for index, proposal in enumerate(adversarial_proposal["scenario_requests"], start=1):
                scenario_queue.append({
                    "label": proposal["label"],
                    "scenario_id": f"{prefix}_ADV_{index:03d}",
                    "prompt": (
                        "Adversarial follow-up to a measured Defender weakness.\n"
                        f"Weakness: {adversarial_proposal['weakness_summary']}\n"
                        f"Scenario request: {proposal['scenario_request']}"
                    ),
                    "hard_cases": [proposal["hard_case"]],
                    "technique_labels": proposal["technique_ids"],
                    "start_timestamp": (timestamp_origin + timedelta(minutes=request["scenario_count"] + index - 1)).isoformat(),
                    "source": "adversary_feedback",
                    "target_failure_ids": proposal["target_failure_ids"],
                })

        for task_index, task in enumerate(scenario_queue, start=1):
            label = task["label"]
            scenario_id = task["scenario_id"]
            if progress_callback is not None:
                progress_callback(
                    f"[{task_index}/{len(scenario_queue)}] Generating and reviewing {scenario_id} ({label})"
                )
            common = {
                "scenario_id": scenario_id,
                "hostname": constraints.get("hostname", "WS-SYNTH-001"),
                "username": constraints.get("username", "synthetic_user"),
                "label": label,
            }
            if label == "benign":
                common["technique_labels"] = []
            elif task["technique_labels"] is not None:
                common["technique_labels"] = task["technique_labels"]
            common["start_timestamp"] = task["start_timestamp"]
            requirements = {
                key: constraints[key]
                for key in (
                    "required_processes", "forbidden_processes", "required_actions",
                    "forbidden_actions", "must_include", "must_not_include",
                )
                if key in constraints
            }
            hard_cases = list(task["hard_cases"])
            if request["difficulty"] == "hard":
                hard_cases.append("Include a challenging but simulator-supported edge case.")
            generated = workflow.run(
                task["prompt"],
                hard_cases=hard_cases,
                existing_scenarios=accepted_scenarios,
                scenario_constraints=common,
                scenario_requirements=requirements,
            )
            outcome: dict[str, Any] = {
                "scenario_id": scenario_id,
                "label": label,
                "source": task["source"],
                "target_failure_ids": task["target_failure_ids"],
                "critic_accepted": generated.critic_accepted,
                "quality_report": generated.quality_report,
                "pipeline_passed": False,
                "rejection_reasons": list(generated.quality_report.get("rejection_reasons", [])),
                "saved_path": None,
                "four_layer_validation": {
                    key: {"status": "not_run", "reason": "Critic did not accept a scenario for simulation."}
                    for key in ("L1", "L2", "L3", "L4")
                },
            }
            if not generated.critic_accepted:
                if not outcome["rejection_reasons"]:
                    outcome["rejection_reasons"].append("Critic rejected after retry limit.")
                outcome["discarded"] = True
                outcomes.append(outcome)
                if progress_callback is not None:
                    progress_callback(f"[{task_index}/{len(scenario_queue)}] Discarded {scenario_id} after Critic review")
                continue

            pipeline_report = pipeline_runner(
                generated.generation.spec,
                rules or [],
                run_id=f"e2e-{uuid4().hex}",
                reference_path=None,
                critic_accepted=True,
                validation_criteria=criteria,
            )
            outcome["pipeline_passed"] = bool(pipeline_report.ok)
            outcome["saved_path"] = pipeline_report.saved_path
            outcome["four_layer_validation"] = getattr(pipeline_report, "validation_report", None)
            if pipeline_report.saved_path:
                simulated_events = read_jsonl(pipeline_report.saved_path)
            else:
                simulated_events = []
            required_event_types = set(constraints.get("required_event_types", []))
            emitted_event_types = {event.event_type for event in simulated_events}
            missing_event_types = sorted(required_event_types - emitted_event_types)
            if missing_event_types:
                outcome["rejection_reasons"].append(
                    "Required event types were not emitted: " + ", ".join(missing_event_types)
                )
                outcome["pipeline_passed"] = False
            if not pipeline_report.ok:
                outcome["rejection_reasons"].extend(pipeline_report.provenance_errors)
                outcome["rejection_reasons"].extend(
                    error for errors in pipeline_report.schema_errors.values() for error in errors
                )
                outcome["rejection_reasons"].extend(pipeline_report.domain_realism_errors)
            outcome["l1_l2_pass"] = bool(pipeline_report.ok) and not missing_event_types
            if outcome["l1_l2_pass"]:
                candidates.append((simulated_events, pipeline_report, generated.critic_accepted, outcome))
                accepted_scenarios.append(generated.generation.spec)
            else:
                outcome["discarded"] = True
            outcomes.append(outcome)
            if progress_callback is not None:
                status = "passed L1/L2" if outcome["l1_l2_pass"] else "failed L1/L2"
                progress_callback(f"[{task_index}/{len(scenario_queue)}] {scenario_id}: Critic accepted; {status}")

        candidate_events = [event for events, _, _, _ in candidates for event in events]
        reference_dicts = [event.to_dict() for event in reference_events]
        diversity = benchmark_dataset_diversity(candidate_events).to_dict() if candidate_events else None
        quality = benchmark_dataset_quality(candidate_events, reference_events).to_dict() if candidate_events else None

        utility_report: dict[str, Any] | None = None
        utility_error: str | None = None
        try:
            augmented_model = DefenderModel().fit([*training_events, *candidate_events])
            augmented_metrics = augmented_model.evaluate(heldout_events)
            utility_report = {
                "macro_f1": augmented_metrics["macro_f1"],
            "macro_f1_delta": augmented_metrics["macro_f1"] - baseline_metrics["macro_f1"],
                "baseline": baseline_metrics,
                "augmented": augmented_metrics,
            }
        except (ValueError, RuntimeError) as error:
            utility_error = str(error)

        full_reports: list[FourLayerValidationReport] = []
        reference_report = None
        if candidate_events:
            # The configured LMD reference contains normal telemetry. Compare
            # it with requested benign scenarios only; mixing malicious
            # process images into this distribution score makes realism
            # similarity uninterpretable.
            benign_process_events = [
                event
                for events, _, _, outcome in candidates
                if outcome.get("label") == "benign"
                for event in events
                if event.event_type == "process_creation"
            ]
            reference_report = compare_reference_realism(
                [event.to_dict() for event in benign_process_events],
                reference_dicts,
                minimum_sample_size=criteria.minimum_reference_sample_size,
            )
            for events, pipeline_report, critic_accepted, outcome in candidates:
                sample_report = build_four_layer_report(
                    criteria=criteria,
                    provenance_errors=pipeline_report.provenance_errors,
                    schema_errors=pipeline_report.schema_errors,
                    logic_errors=pipeline_report.domain_realism_errors,
                    logic_warnings=pipeline_report.domain_realism_warnings,
                    roundtrip_ok=pipeline_report.roundtrip_ok,
                    rules_failed_to_load=pipeline_report.rules_failed_to_load,
                    unsupported_sigma_evaluations=pipeline_report.unsupported_evaluations,
                    reference_report=reference_report,
                    critic_accepted=critic_accepted,
                    utility_report=utility_report or ({"error": utility_error} if utility_error else None),
                )
                full_reports.append(sample_report)
                outcome["four_layer_validation"] = sample_report.to_dict()
                outcome["rejection_reasons"].extend(
                    error for layer in sample_report.layers.values() for error in layer.errors
                )
        validation = aggregate_validation_reports(full_reports, criteria=criteria)

        fine_tuning_report: dict[str, Any] | None = None
        if validation.validated:
            filename = "synthetic_events.jsonl"
            final_path = DatasetStore.save(
                candidate_events,
                "final",
                filename,
                metadata={
                    "generation_method": "planner_scenario_simulator_critic_pipeline",
                    "validated": True,
                    "validation_status": "validated",
                    "validation_report": validation.to_dict(),
                    "utility_report": utility_report,
                    "run_id": uuid4().hex,
                },
            )
            final_telemetry_path = str(final_path)
            try:
                converted = convert_validated_telemetry(
                    candidate_events, seed=random_seed
                )
                ft_dir = root / "fine_tuning"
                for split, examples in converted.splits.items():
                    fine_tuning_paths[split] = str(ft_dir / f"{split}.jsonl")
                    payload = "".join(
                        json.dumps(row.to_chat_record(), ensure_ascii=False, sort_keys=True) + "\n"
                        for row in examples
                    )
                    _atomic_write(Path(fine_tuning_paths[split]), payload)
                fine_tuning_report = converted.report
                DatasetStore.update_metadata(
                    "final",
                    filename,
                    {
                        "diversity_report": diversity,
                        "reference_quality_report": quality,
                        "fine_tuning_report": converted.report,
                    },
                )
                metadata = {
                    "source_dataset_filename": filename,
                    "source_sha256": DatasetStore.load_metadata("final", filename)["sha256"],
                    "validation_report": validation.to_dict(),
                    "fine_tuning_split_counts": converted.report["split_counts"],
                    "split_seed": random_seed,
                }
                _atomic_write(report_dir / "dataset_metadata.json", json.dumps(metadata, indent=2, ensure_ascii=False) + "\n")
            except ValueError as error:
                utility_error = utility_error or str(error)

        report = {
            "workflow_status": "complete" if validation.validated and fine_tuning_report else "incomplete",
            "request": request,
            "defender_baseline_metrics": baseline_metrics,
            "adversarial_proposal": adversarial_proposal,
            "adversary_error": adversary_error,
            "scenario_outcomes": outcomes,
            "scenario_count": request["scenario_count"],
            "total_scenario_attempts": len(scenario_queue),
            "critic_accepted_scenario_count": sum(item["critic_accepted"] for item in outcomes),
            "l1_l2_passed_scenario_count": len(candidates),
            "generation_latency_seconds": sum(
                item.get("quality_report", {}).get("generation_latency_seconds", 0.0)
                for item in outcomes
            ),
            "critic_latency_seconds": sum(
                item.get("quality_report", {}).get("critic_latency_seconds", 0.0)
                for item in outcomes
            ),
            "validation_report": validation.to_dict(),
            "utility_report": utility_report,
            "utility_error": utility_error,
            "diversity_report": diversity,
            "reference_quality_report": quality,
            "fine_tuning_report": fine_tuning_report,
            "final_telemetry_path": final_telemetry_path,
            "fine_tuning_paths": fine_tuning_paths,
            "human_review": "not_run; review high-impact claims and ATT&CK labels before publication.",
        }
        quality_report = {
            "status": report["workflow_status"],
            "four_layer_validation": validation.to_dict(),
            "utility_report": utility_report,
            "diversity_report": diversity,
            "reference_quality_report": quality,
            "fine_tuning_quality": fine_tuning_report,
            "critic_accepted_scenarios": report["critic_accepted_scenario_count"],
            "accepted_scenarios_passing_l1_l2": report["l1_l2_passed_scenario_count"],
            "rejected_scenarios": [item for item in outcomes if item.get("discarded")],
        }
        _atomic_write(report_dir / "quality_report.json", json.dumps(quality_report, indent=2, ensure_ascii=False, default=str) + "\n")
        _atomic_write(report_dir / "end_to_end_report.json", json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n")
        return EndToEndResult(report, final_telemetry_path, fine_tuning_paths, report["workflow_status"] == "complete")
    finally:
        DatasetStore.DATASET_TYPES["generated"] = original_generated
        DatasetStore.DATASET_TYPES["final"] = original_final
