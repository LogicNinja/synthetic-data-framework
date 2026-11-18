"""Export a validated telemetry dataset into grouped chat fine-tuning JSONL."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from synthetic_data.fine_tuning import convert_validated_telemetry
from synthetic_data.serialization.event_serializer import read_jsonl


def _atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_text(content, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def load_validated_source(path: Path) -> tuple[list[Any], dict[str, Any], str]:
    manifest_path = path.with_suffix(path.suffix + ".meta.json")
    if not path.is_file() or not manifest_path.is_file():
        raise ValueError("Source telemetry and its .meta.json manifest are both required.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    metadata = manifest.get("metadata") or {}
    report = metadata.get("validation_report") or {}
    layers = report.get("layers") or {}
    if metadata.get("validated") is not True or report.get("decision") != "validated":
        raise ValueError("Source telemetry is not marked as four-layer validated.")
    if set(layers) != {"L1", "L2", "L3", "L4"} or any(
        layer.get("status") != "passed" for layer in layers.values()
    ):
        raise ValueError("Source validation manifest does not show all four layers passing.")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != manifest.get("sha256"):
        raise ValueError("Source telemetry checksum does not match its manifest.")
    events = read_jsonl(path)
    if len(events) != manifest.get("event_count"):
        raise ValueError("Source event count does not match its manifest.")
    return events, manifest, digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Four-layer validated canonical telemetry JSONL")
    parser.add_argument("--dataset-root", type=Path, default=PROJECT_ROOT / "data" / "final")
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--train-ratio", type=float, default=0.8)
    parser.add_argument("--validation-ratio", type=float, default=0.1)
    parser.add_argument("--test-ratio", type=float, default=0.1)
    args = parser.parse_args()
    ratios = (args.train_ratio, args.validation_ratio, args.test_ratio)

    events, manifest, source_digest = load_validated_source(args.source)
    dataset = convert_validated_telemetry(events, split_ratios=ratios, seed=args.seed)
    fine_tuning_dir = args.dataset_root / "fine_tuning"
    for split_name, examples in dataset.splits.items():
        content = "".join(
            json.dumps(example.to_chat_record(), ensure_ascii=False, sort_keys=True) + "\n"
            for example in examples
        )
        _atomic_text(fine_tuning_dir / f"{split_name}.jsonl", content)

    telemetry_dir = args.dataset_root / "telemetry"
    telemetry_dir.mkdir(parents=True, exist_ok=True)
    telemetry_copy = telemetry_dir / "synthetic_events.jsonl"
    if args.source.resolve() != telemetry_copy.resolve():
        _atomic_text(telemetry_copy, args.source.read_text(encoding="utf-8"))

    quality_report = {
        **dataset.report,
        "status": "passed",
        "source_validated": True,
        "source_sha256": source_digest,
        "source_event_count": manifest["event_count"],
        "split_seed": args.seed,
        "split_ratios": dict(zip(("train", "validation", "test"), ratios)),
        "format_schema": "src/synthetic_data/schemas/fine_tuning_chat.schema.json",
    }
    dataset_metadata = {
        "source_dataset_filename": args.source.name,
        "source_sha256": source_digest,
        "source_validation_report": manifest["metadata"]["validation_report"],
        "format": "chat_messages_jsonl",
        "tasks": sorted(dataset.report["task_distribution"]),
        "split_seed": args.seed,
        "split_ratios": dict(zip(("train", "validation", "test"), ratios)),
        "split_counts": dataset.report["split_counts"],
    }
    reports_dir = args.dataset_root / "reports"
    _atomic_text(reports_dir / "quality_report.json", json.dumps(quality_report, indent=2, ensure_ascii=False) + "\n")
    _atomic_text(reports_dir / "dataset_metadata.json", json.dumps(dataset_metadata, indent=2, ensure_ascii=False) + "\n")
    print(f"Exported {dataset.report['example_count']} examples to {fine_tuning_dir}")
    print(f"Quality report: {reports_dir / 'quality_report.json'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Fine-tuning export failed: {error}")
