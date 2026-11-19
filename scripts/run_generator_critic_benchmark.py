"""Run matched raw, Critic-filtered, and feedback-assisted generation cohorts."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys
import time
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from synthetic_data.agents.client import GrokResponsesClient
from synthetic_data.agents.ollama_client import DEFAULT_OLLAMA_MODEL, OllamaClient
from synthetic_data.agents.critic_agent import CriticAgent
from synthetic_data.agents.planner_agent import PlannerAgent
from synthetic_data.agents.scenario_agent import ScenarioAgent
from synthetic_data.agents.workflow import GenerationWorkflow
from synthetic_data.evaluation.quality_benchmark import compare_experiment_cohorts
from synthetic_data.retrieval.local_bm25 import LocalBM25Retriever
from synthetic_data.serialization.event_serializer import read_jsonl, write_jsonl
from synthetic_data.pipeline.runner import run_pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True, help="JSON array of fixed request case objects")
    parser.add_argument("--reference", type=Path, required=True, help="Reference canonical JSONL dataset")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--feedback-attempts", type=int, default=3)
    parser.add_argument("--provider", choices=("ollama", "grok"), default="ollama")
    parser.add_argument("--model", help=f"Local Ollama model (default: {DEFAULT_OLLAMA_MODEL})")
    parser.add_argument("--ollama-host", help="Ollama URL")
    args = parser.parse_args()
    cases = json.loads(args.cases.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        parser.error("--cases must contain a non-empty JSON array")
    if not 1 <= args.feedback_attempts <= 5:
        parser.error("--feedback-attempts must be between 1 and 5")

    client = (
        OllamaClient(model=args.model, host=args.ollama_host)
        if args.provider == "ollama"
        else GrokResponsesClient()
    )
    planner = PlannerAgent(client)
    scenario_agent = ScenarioAgent(
        client,
        retriever=LocalBM25Retriever([
            PROJECT_ROOT / "docs",
            PROJECT_ROOT / "knowledge" / "windows_refs",
            PROJECT_ROOT / "knowledge" / "sigma_rules" / "sigma" / "rules" / "windows" / "process_creation",
        ]),
    )
    critic = CriticAgent(client)
    variants = ("generator", "critic", "feedback")
    cohort_events = {name: [] for name in variants}
    cohort_metadata = {}

    for variant in variants:
        report = {
            "attempts": 0,
            "accepted": 0,
            "rejected": 0,
            "generation_latency_seconds": 0.0,
            "critic_latency_seconds": 0.0,
            "critic_scores_by_dimension": defaultdict(list),
            "critic_first_scores_by_dimension": defaultdict(list),
            "critic_final_scores_by_dimension": defaultdict(list),
            "case_ids": [],
            "pipeline_passed": 0,
            "pipeline_rejected": 0,
            "cohort_samples_kept": 0,
        }
        workflow = GenerationWorkflow(
            planner,
            scenario_agent,
            critic,
            max_attempts=1 if variant == "critic" else args.feedback_attempts,
        )
        for index, case in enumerate(cases, start=1):
            case_id = str(case.get("case_id", f"case-{index}"))
            request = str(case["request"])
            report["case_ids"].append(case_id)
            if variant == "generator":
                plan = planner.run(
                    request,
                    coverage_gaps=case.get("coverage_gaps"),
                    hard_cases=case.get("hard_cases"),
                    generation_budget=1,
                )
                generation_started = time.perf_counter()
                generation = scenario_agent.run(
                    plan.data["scenario_request"],
                    label=plan.data["label"],
                    plan=plan.data,
                )
                report["generation_latency_seconds"] += time.perf_counter() - generation_started
                critic_started = time.perf_counter()
                review = critic.run(generation.spec, request=request, plan=plan.data)
                report["critic_latency_seconds"] += time.perf_counter() - critic_started
                reviews = [review]
                accepted_for_filter = True  # baseline is deliberately unfiltered
                spec = generation.spec
            else:
                result = workflow.run(
                    request,
                    coverage_gaps=case.get("coverage_gaps"),
                    hard_cases=case.get("hard_cases"),
                )
                reviews = list(result.critic_history)
                report["generation_latency_seconds"] += result.quality_report.get("generation_latency_seconds", 0.0)
                report["critic_latency_seconds"] += result.quality_report.get("critic_latency_seconds", 0.0)
                accepted_for_filter = result.critic_accepted
                spec = result.generation.spec

            report["attempts"] += len(reviews)
            report["accepted"] += sum(review.accepted for review in reviews)
            report["rejected"] += sum(not review.accepted for review in reviews)
            for review in reviews:
                for dimension, score in review.rubric_scores.items():
                    report["critic_scores_by_dimension"][dimension].append(score)
            if reviews:
                for dimension, score in reviews[0].rubric_scores.items():
                    report["critic_first_scores_by_dimension"][dimension].append(score)
                for dimension, score in reviews[-1].rubric_scores.items():
                    report["critic_final_scores_by_dimension"][dimension].append(score)

            if variant != "generator" and not accepted_for_filter:
                continue

            run_id = f"bench-{variant}-{uuid4().hex}"
            pipeline_report = run_pipeline(
                spec,
                [],
                run_id=run_id,
                dataset_type="generated",
                reference_path=args.reference,
                critic_accepted=all(review.accepted for review in reviews),
            )
            if not pipeline_report.saved_path:
                report["pipeline_rejected"] += 1
                continue
            if pipeline_report.ok:
                report["pipeline_passed"] += 1
            else:
                report["pipeline_rejected"] += 1
            if variant == "generator" or pipeline_report.ok:
                cohort_events[variant].extend(read_jsonl(pipeline_report.saved_path))
                report["cohort_samples_kept"] += 1

        first_scores = report.pop("critic_first_scores_by_dimension")
        final_scores = report.pop("critic_final_scores_by_dimension")
        all_attempt_scores = report.pop("critic_scores_by_dimension")
        report["critic_scores"] = {
            dimension: sum(scores) / len(scores)
            for dimension, scores in final_scores.items() if scores
        }
        report["critic_all_attempt_scores"] = {
            dimension: sum(scores) / len(scores)
            for dimension, scores in all_attempt_scores.items() if scores
        }
        report["critic_score_improvement_by_dimension"] = {
            dimension: sum(final_scores[dimension][index] - first_scores[dimension][index]
                           for index in range(min(len(first_scores[dimension]), len(final_scores[dimension]))))
            / min(len(first_scores[dimension]), len(final_scores[dimension]))
            for dimension in set(first_scores) & set(final_scores)
            if first_scores[dimension] and final_scores[dimension]
        }
        report["acceptance_rate"] = (
            report["accepted"] / report["attempts"] if report["attempts"] else 0.0
        )
        report["filter_applied"] = variant != "generator"
        cohort_metadata[variant] = report

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for variant, events in cohort_events.items():
        write_jsonl(events, args.output_dir / f"{variant}.jsonl")
        (args.output_dir / f"{variant}-metadata.json").write_text(
            json.dumps(cohort_metadata[variant], indent=2) + "\n", encoding="utf-8"
        )
    comparison = compare_experiment_cohorts(
        cohort_events,
        read_jsonl(args.reference),
        metadata=cohort_metadata,
    )
    comparison["experiment_design"] = {
        "cases": cohort_metadata["generator"]["case_ids"],
        "model": client.config.model,
        "feedback_attempt_limit": args.feedback_attempts,
        "critic_only_attempt_limit": 1,
        "llm_provider": args.provider,
        "llm_model": client.config.model,
    }
    (args.output_dir / "quality-benchmark.json").write_text(
        json.dumps(comparison, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"Matched cohort benchmark written to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
