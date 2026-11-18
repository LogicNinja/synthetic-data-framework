"""Run planner → RAG-grounded scenario generation → critic review."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from synthetic_data.agents.client import GrokResponsesClient
from synthetic_data.agents.ollama_client import OllamaClient
from synthetic_data.agents.critic_agent import CriticAgent
from synthetic_data.agents.planner_agent import PlannerAgent
from synthetic_data.agents.scenario_agent import ScenarioAgent
from synthetic_data.agents.workflow import GenerationWorkflow
from synthetic_data.retrieval.local_bm25 import LocalBM25Retriever


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate and critique one simulated Windows scenario."
    )
    parser.add_argument("request", help="What simulated scenario to generate")
    parser.add_argument("--coverage-gap", action="append", default=[])
    parser.add_argument("--hard-case", action="append", default=[])
    parser.add_argument("--image", action="append", type=Path, default=[])
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--provider", choices=("ollama", "grok"), default="ollama")
    parser.add_argument("--model", help="Local Ollama model (default: qwen2.5:7b)")
    parser.add_argument("--ollama-host", help="Ollama URL")
    args = parser.parse_args()

    client = (
        OllamaClient(model=args.model, host=args.ollama_host)
        if args.provider == "ollama"
        else GrokResponsesClient()
    )
    retriever = LocalBM25Retriever(
        [
            PROJECT_ROOT / "docs",
            PROJECT_ROOT / "knowledge" / "windows_refs",
            PROJECT_ROOT / "knowledge" / "sigma_rules" / "sigma" / "rules" / "windows" / "process_creation",
        ]
    )
    workflow = GenerationWorkflow(
        PlannerAgent(client),
        ScenarioAgent(client, retriever=retriever),
        CriticAgent(client),
        max_attempts=args.max_attempts,
    )
    result = workflow.run(
        args.request,
        coverage_gaps=args.coverage_gap,
        hard_cases=args.hard_case,
        image_paths=args.image,
    )
    report = {
        "critic_accepted": result.critic_accepted,
        "plan": asdict(result.plan),
        "scenario": asdict(result.generation),
        "critic_history": [asdict(item) for item in result.critic_history],
        "quality_report": result.quality_report,
        "dataset_validation_status": "not_run",
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Workflow report saved to {args.output}")
    else:
        print(rendered)
    return 0 if result.critic_accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
