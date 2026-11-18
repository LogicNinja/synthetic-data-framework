"""Run one held-out Defender → Adversary → generation feedback cycle."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from synthetic_data.agents.adversary_agent import AdversaryAgent
from synthetic_data.agents.client import GrokResponsesClient
from synthetic_data.agents.ollama_client import OllamaClient
from synthetic_data.agents.critic_agent import CriticAgent
from synthetic_data.agents.planner_agent import PlannerAgent
from synthetic_data.agents.scenario_agent import ScenarioAgent
from synthetic_data.agents.workflow import GenerationWorkflow
from synthetic_data.config.settings import CONFIG_DIR, KNOWLEDGE_DIR
from synthetic_data.defender.model import DefenderModel
from synthetic_data.evaluation.adaptive_feedback import AdaptiveFeedbackCycle
from synthetic_data.retrieval.local_bm25 import LocalBM25Retriever
from synthetic_data.serialization.event_serializer import read_jsonl
from synthetic_data.pipeline.runner import load_rules
from synthetic_data.validation.four_layer import load_validation_criteria


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate defender failures and feed accepted scenarios back into generation."
    )
    parser.add_argument("training_jsonl", type=Path)
    parser.add_argument("heldout_jsonl", type=Path)
    parser.add_argument("--rules", type=Path, default=(
        KNOWLEDGE_DIR / "sigma_rules" / "sigma" / "rules" / "windows" / "process_creation"
    ))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--provider", choices=("ollama", "grok"), default="ollama")
    parser.add_argument("--model", help="Local Ollama model (default: qwen2.5:7b)")
    parser.add_argument("--ollama-host", help="Ollama URL")
    parser.add_argument("--reference", type=Path)
    parser.add_argument(
        "--criteria",
        type=Path,
        default=CONFIG_DIR / "validation_criteria.json",
    )
    args = parser.parse_args()

    client = (
        OllamaClient(model=args.model, host=args.ollama_host)
        if args.provider == "ollama"
        else GrokResponsesClient()
    )
    retriever = LocalBM25Retriever([
        PROJECT_ROOT / "docs",
        PROJECT_ROOT / "knowledge" / "windows_refs",
        args.rules,
    ])
    workflow = GenerationWorkflow(
        PlannerAgent(client),
        ScenarioAgent(client, retriever=retriever),
        CriticAgent(client),
        max_attempts=args.max_attempts,
    )
    rules, failed = load_rules(args.rules)
    result = AdaptiveFeedbackCycle(
        DefenderModel(),
        AdversaryAgent(client),
        workflow,
        rules=rules,
        reference_path=args.reference,
        validation_criteria=load_validation_criteria(args.criteria),
    ).run(
        training_events=read_jsonl(args.training_jsonl),
        heldout_events=read_jsonl(args.heldout_jsonl),
    )
    report = asdict(result)
    report["sigma_rules_loaded"] = len(rules)
    report["sigma_rules_failed_to_load"] = failed
    output = args.output or (
        PROJECT_ROOT / "data" / "reports"
        / f"adaptive_feedback_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "initial_macro_f1": result.initial_evaluation["macro_f1"],
        "generated_events": result.augmented_event_count,
        "final_macro_f1": (
            result.final_evaluation["macro_f1"] if result.final_evaluation else None
        ),
        "macro_f1_delta": result.macro_f1_delta,
        "report": str(output),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
