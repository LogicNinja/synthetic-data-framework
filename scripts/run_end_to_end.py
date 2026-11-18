"""Run the complete no-UI generation, validation, benchmarking, and export flow."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from synthetic_data.agents.client import GrokResponsesClient
from synthetic_data.agents.adversary_agent import AdversaryAgent
from synthetic_data.agents.ollama_client import OllamaClient
from synthetic_data.agents.critic_agent import CriticAgent
from synthetic_data.agents.planner_agent import PlannerAgent
from synthetic_data.agents.scenario_agent import ScenarioAgent
from synthetic_data.agents.workflow import GenerationWorkflow
from synthetic_data.config.settings import CONFIG_DIR, KNOWLEDGE_DIR
from synthetic_data.evaluation.quality_benchmark import benchmark_dataset_quality
from synthetic_data.pipeline.end_to_end import run_end_to_end
from synthetic_data.pipeline.runner import load_rules
from synthetic_data.retrieval.local_bm25 import LocalBM25Retriever
from synthetic_data.serialization.event_serializer import read_jsonl
from synthetic_data.validation.four_layer import load_validation_criteria


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path, help="Structured request JSON; see configs/end_to_end_request.example.json")
    parser.add_argument("--reference", type=Path, required=True, help="Reference canonical telemetry JSONL")
    parser.add_argument("--training", type=Path, required=True, help="Defender training JSONL with both classes")
    parser.add_argument("--heldout", type=Path, required=True, help="Scenario-disjoint Defender held-out JSONL")
    parser.add_argument("--output-root", type=Path, default=PROJECT_ROOT / "data" / "final")
    parser.add_argument("--rules", type=Path, default=KNOWLEDGE_DIR / "sigma_rules" / "sigma" / "rules" / "windows" / "process_creation")
    parser.add_argument("--criteria", type=Path, default=CONFIG_DIR / "validation_criteria.json")
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--provider", choices=("ollama", "grok"), default="ollama")
    parser.add_argument("--model", help="Local Ollama model (default: qwen2.5:7b)")
    parser.add_argument("--planner-model", help="Ollama model for planning (defaults to --model)")
    parser.add_argument("--scenario-model", help="Ollama model for scenario generation (defaults to --model)")
    parser.add_argument("--critic-model", help="Ollama model for critique (defaults to --model)")
    parser.add_argument("--adversary-model", help="Ollama model for adversarial proposals (defaults to --model)")
    parser.add_argument("--ollama-host", help="Ollama URL (default: http://127.0.0.1:11434)")
    args = parser.parse_args()

    request = json.loads(args.request.read_text(encoding="utf-8"))
    if args.provider == "ollama":
        default_model = args.model or "qwen2.5:7b"
        role_models = {
            "planner": args.planner_model or default_model,
            "scenario": args.scenario_model or default_model,
            "critic": args.critic_model or default_model,
            "adversary": args.adversary_model or default_model,
        }
        clients = {
            role: OllamaClient(model=model, host=args.ollama_host)
            for role, model in role_models.items()
        }
    else:
        shared_client = GrokResponsesClient()
        clients = {role: shared_client for role in ("planner", "scenario", "critic", "adversary")}
        role_models = {role: "grok" for role in clients}
    retriever = LocalBM25Retriever([
        PROJECT_ROOT / "docs",
        KNOWLEDGE_DIR / "windows_refs",
        args.rules,
    ])
    workflow = GenerationWorkflow(
        PlannerAgent(clients["planner"]),
        ScenarioAgent(clients["scenario"], retriever=retriever),
        CriticAgent(clients["critic"]),
        max_attempts=args.max_attempts,
        progress_callback=lambda message: print(message, file=sys.stderr, flush=True),
    )
    rules, failed_rules = load_rules(args.rules)
    result = run_end_to_end(
        request,
        workflow=workflow,
        adversary=AdversaryAgent(clients["adversary"]),
        reference_events=read_jsonl(args.reference),
        training_events=read_jsonl(args.training),
        heldout_events=read_jsonl(args.heldout),
        output_root=args.output_root,
        rules=rules,
        validation_criteria=load_validation_criteria(args.criteria),
        random_seed=args.seed,
        progress_callback=lambda message: print(message, file=sys.stderr, flush=True),
    )
    report = result.report
    report["llm_provider"] = args.provider
    report["llm_model"] = args.model or "qwen2.5:7b"
    report["llm_models_by_role"] = role_models
    report["sigma_rules_loaded"] = len(rules)
    report["sigma_rules_failed_to_load"] = failed_rules
    report["training_reference_quality"] = benchmark_dataset_quality(
        read_jsonl(args.training), read_jsonl(args.reference)
    ).to_dict()
    report_path = args.output_root / "reports" / "end_to_end_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    print(json.dumps({
        "workflow_status": report["workflow_status"],
        "validated": report["validation_report"]["validated"],
        "final_telemetry": result.final_telemetry_path,
        "fine_tuning_files": result.fine_tuning_paths,
        "report": str(report_path),
    }, indent=2))
    return 0 if result.complete else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"End-to-end workflow failed: {error}")
