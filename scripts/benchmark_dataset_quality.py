"""Compare named generated dataset cohorts with one reference JSONL file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from synthetic_data.evaluation.quality_benchmark import compare_experiment_cohorts
from synthetic_data.serialization.event_serializer import read_jsonl


def _named_path(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name.strip() or not raw_path.strip():
        raise argparse.ArgumentTypeError("Use NAME=PATH.")
    return name.strip(), Path(raw_path.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument(
        "--variant", action="append", type=_named_path, required=True,
        help="Dataset cohort NAME=JSONL; use generator, critic, and feedback for standard deltas.",
    )
    parser.add_argument(
        "--metadata", action="append", type=_named_path, default=[],
        help="Optional workflow metadata NAME=JSON, including quality_report fields.",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    variants = {name: read_jsonl(path) for name, path in args.variant}
    metadata = {}
    for name, path in args.metadata:
        value = json.loads(path.read_text(encoding="utf-8"))
        metadata[name] = value.get("quality_report", value)
    reference = read_jsonl(args.reference)
    report = compare_experiment_cohorts(variants, reference, metadata=metadata)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Benchmark report saved to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
