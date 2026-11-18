"""Compare direct and few-shot scenario prompts on a fixed case set."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from synthetic_data.agents.client import GrokResponsesClient
from synthetic_data.agents.config import GrokConfig
from synthetic_data.evaluation.baseline_prompts import (
    evaluate_prompt_baselines,
    load_prompt_files,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare versioned scenario-generation prompt baselines."
    )
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument(
        "--cases", type=Path, default=PROJECT_ROOT / "configs" / "baseline_cases.json"
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    case_data = json.loads(args.cases.read_text(encoding="utf-8"))
    prompts = load_prompt_files({
        "b0_direct": PROJECT_ROOT / "prompts" / "baselines" / "b0_direct.txt",
        "b1_few_shot": PROJECT_ROOT / "prompts" / "baselines" / "b1_few_shot.txt",
    })
    schema_path = (
        PROJECT_ROOT / "src" / "synthetic_data" / "agents" / "schemas"
        / "scenario_spec.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    config = GrokConfig.from_env()
    client = GrokResponsesClient(config)

    report = evaluate_prompt_baselines(
        cases=case_data,
        prompts=prompts,
        schema=schema,
        generate_json=client.generate_json,
        model=config.model,
        repetitions=args.repetitions,
    )
    output = args.output or (
        PROJECT_ROOT / "data" / "reports"
        / f"prompt_baselines_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    print(f"Report saved to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
