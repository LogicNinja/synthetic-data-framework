"""Write a JSON diversity benchmark report for a canonical JSONL dataset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from synthetic_data.evaluation.diversity import benchmark_dataset_diversity
from synthetic_data.serialization.event_serializer import read_jsonl


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="Canonical events JSONL")
    parser.add_argument("--output", type=Path, help="Report path (prints to stdout by default)")
    parser.add_argument("--near-duplicate-threshold", type=float, default=0.9)
    args = parser.parse_args()
    report = benchmark_dataset_diversity(
        read_jsonl(args.dataset),
        near_duplicate_threshold=args.near_duplicate_threshold,
    ).to_dict()
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
