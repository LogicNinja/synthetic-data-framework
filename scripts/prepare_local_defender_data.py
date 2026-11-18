"""Prepare scenario-disjoint Defender train/held-out files from repository data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from synthetic_data.defender.model import event_label_from_ground_truth
from synthetic_data.serialization.event_serializer import deserialize_event, read_jsonl, write_jsonl


def _read_first(path: Path, limit: int):
    events = []
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                events.append(deserialize_event(json.loads(line)))
            except (json.JSONDecodeError, ValueError, TypeError) as error:
                raise ValueError(f"Invalid reference event at line {line_number}: {error}") from error
            if len(events) >= limit:
                break
    return events


def _deduplicate(events):
    result = []
    seen = set()
    for event in events:
        if event.event_id not in seen:
            result.append(event)
            seen.add(event.event_id)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=PROJECT_ROOT / "data")
    parser.add_argument("--reference-limit", type=int, default=200)
    args = parser.parse_args()
    if args.reference_limit < 30:
        parser.error("--reference-limit must be at least 30 for held-out evaluation.")
    generated_dir = args.data_root / "generated"
    reference_path = args.data_root / "reference" / "lmd2022_normal_process_creation.jsonl"
    train_attack_files = sorted(generated_dir.glob("s2_wmi_powershell_*.jsonl"))
    heldout_attack_files = sorted(generated_dir.glob("s3_cmd_powershell_*.jsonl"))
    heldout_benign_files = sorted(generated_dir.glob("s4_*.jsonl"))
    if not train_attack_files or not heldout_attack_files or not heldout_benign_files:
        raise ValueError("Expected existing S2 training, S3 held-out malicious, and S4 held-out benign event files.")
    if not reference_path.is_file():
        raise FileNotFoundError(f"Reference telemetry file not found: {reference_path}")

    training = _deduplicate([
        event
        for path in train_attack_files
        for event in read_jsonl(path)
    ] + _read_first(reference_path, args.reference_limit))
    heldout = _deduplicate([
        event for path in [*heldout_attack_files, *heldout_benign_files] for event in read_jsonl(path)
    ])
    train_groups = {
        str(event.provenance.scenario_id)
        for event in training
        if event.provenance and event.provenance.scenario_id
    }
    heldout_groups = {
        str(event.provenance.scenario_id)
        for event in heldout
        if event.provenance and event.provenance.scenario_id
    }
    if train_groups & heldout_groups:
        raise ValueError(f"Scenario leakage in prepared evaluation data: {sorted(train_groups & heldout_groups)}")
    if {event_label_from_ground_truth(event) for event in training} != {"benign", "malicious"}:
        raise ValueError("Prepared training split must contain both labels.")
    overlap = {event.event_id for event in training} & {event.event_id for event in heldout}
    if overlap:
        raise ValueError("Prepared train/held-out files share event IDs.")

    output_dir = args.data_root / "training"
    output_dir.mkdir(parents=True, exist_ok=True)
    train_path = output_dir / "defender_train.jsonl"
    heldout_path = output_dir / "defender_heldout.jsonl"
    write_jsonl(training, train_path)
    write_jsonl(heldout, heldout_path)
    print(json.dumps({
        "training_path": str(train_path),
        "training_event_count": len(training),
        "training_labels": {label: sum(event_label_from_ground_truth(e) == label for e in training) for label in ("benign", "malicious")},
        "heldout_path": str(heldout_path),
        "heldout_event_count": len(heldout),
        "heldout_labels": {label: sum(event_label_from_ground_truth(e) == label for e in heldout) for label in ("benign", "malicious")},
        "train_scenario_groups": sorted(train_groups),
        "heldout_scenario_groups": sorted(heldout_groups),
        "limitation": "Development smoke-test split from existing generated/reference data; not a research benchmark.",
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as error:
        raise SystemExit(f"Could not prepare local Defender data: {error}")
