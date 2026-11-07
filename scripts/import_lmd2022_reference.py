
"""Import LMD-2022 Normal.csv Sysmon process-creation rows as reference events.

The source UtcTime values are truncated (for example, "30:32.4").
A fixed, documented canonical timestamp is used only to satisfy the schema.
The original source timestamp and CSV row are preserved.
Do not use these canonical timestamps for temporal analysis.
"""

import argparse
import csv
from collections import Counter
from pathlib import Path
from typing import Any

from synthetic_data.normalization.windows_event_normalizer import (
    WindowsEventNormalizer,
)
from synthetic_data.storage.dataset_store import DatasetStore


# Schema-valid placeholder only; not the actual source event time.
CANONICAL_TIMESTAMP_PLACEHOLDER = "2000-01-01T00:00:00Z"


def _get(row: dict[str, Any], *names: str) -> str | None:
    """Get the first non-empty value, matching CSV field names case-insensitively."""
    lowered = {str(key).strip().lower(): value for key, value in row.items()}

    for name in names:
        value = lowered.get(name.lower())
        if value is not None:
            value = str(value).strip()
            if value:
                return value

    return None


def _normalize_csv_row(
    row: dict[str, Any],
    *,
    row_number: int,
    host_id: str,
    run_id: str,
):
    """Adapt one LMD CSV row into the normalizer's expected Sysmon shape."""
    event_id = _get(row, "EventID", "EventId", "Event ID")

    if event_id and event_id != "1":
        return None, "non_process_creation_skipped"

    image = _get(row, "Image")

    if not image or image == "0":
        return None, "missing_or_placeholder_image_skipped"

    event_data = {
        "ProcessId": _get(row, "ProcessId", "ProcessID", "PID"),
        "ProcessGuid": _get(row, "ProcessGuid", "ProcessGUID"),
        "Image": image,
        "OriginalFileName": _get(row, "OriginalFileName"),
        "CommandLine": _get(row, "CommandLine"),
        "ParentProcessId": _get(row, "ParentProcessId", "ParentProcessID"),
        "ParentProcessGuid": _get(row, "ParentProcessGuid", "ParentProcessGUID"),
        "ParentImage": _get(row, "ParentImage"),
        "ParentCommandLine": _get(row, "ParentCommandLine"),
        "User": _get(row, "User"),
        "UtcTime": _get(row, "UtcTime", "UTC time", "Timestamp"),
    }

    event_data = {
        key: value for key, value in event_data.items() if value is not None
    }

    raw_event = {
        "System": {
            "EventID": "1",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventRecordID": str(row_number),
            "Computer": host_id,
            "TimeCreated": {
                "SystemTime": CANONICAL_TIMESTAMP_PLACEHOLDER
            },
        },
        "EventData": event_data,
        "SourceRow": {
            str(key): value for key, value in row.items()
        },
    }

    event = WindowsEventNormalizer.normalize(
        raw_event,
        host_id=host_id,
        run_id=run_id,
        origin="reference",
        scenario_id="lmd-2022-normal",
    )

    event.validate()
    return event, "imported"


def import_reference_data(
    source_path: Path,
    output_filename: str,
    run_id: str,
    host_id: str,
) -> Path:
    counts: Counter[str] = Counter()
    image_counts: Counter[str] = Counter()
    events = []

    with source_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
        errors="replace",
    ) as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError(f"CSV has no header row: {source_path}")

        for row_number, row in enumerate(reader, start=2):
            counts["rows_seen"] += 1

            if not row or all(
                value is None or not str(value).strip()
                for value in row.values()
            ):
                counts["blank_rows_skipped"] += 1
                continue

            try:
                event, outcome = _normalize_csv_row(
                    row,
                    row_number=row_number,
                    host_id=host_id,
                    run_id=run_id,
                )
            except (ValueError, TypeError, KeyError) as exc:
                counts["normalization_or_validation_failed"] += 1
                print(f"Skipped CSV row {row_number}: {exc}")
                continue

            counts[outcome] += 1

            if event is None:
                continue

            events.append(event)

            image = event.process.image if event.process else None
            executable = (
                (image or "<missing>")
                .replace("/", "\\")
                .rsplit("\\", 1)[-1]
                .lower()
            )

            image_counts[executable] += 1

    if not events:
        raise RuntimeError(
            "No valid process-creation events imported. "
            "Check the CSV columns and source."
        )

    output_path = DatasetStore.save(
        events=events,
        dataset_type="reference",
        filename=output_filename,
        metadata={
            "source": "LMD-2022",
            "source_dataset": "Labelled LMD-2022 / Normal.csv",
            "source_event_id": 1,
            "source_label": "normal (label 0)",
            "description": (
                "Sysmon process-creation reference records used only for "
                "Layer 4 process-image distribution comparison. Original "
                "CSV rows are preserved. Source UtcTime is truncated and "
                "must not be used for temporal analysis."
            ),
            "timestamp_policy": {
                "canonical_timestamp": CANONICAL_TIMESTAMP_PLACEHOLDER,
                "policy": "fixed schema-valid placeholder; not source event time",
                "source_timestamp_field": "UtcTime",
                "source_timestamp_quality": (
                    "truncated/unusable for date-time analysis"
                ),
            },
            "import_counts": dict(counts),
            "distinct_executable_images": len(image_counts),
            "top_executable_counts": dict(image_counts.most_common(20)),
        },
    )

    print("\nLMD-2022 import complete")
    print("------------------------")

    for key, value in sorted(counts.items()):
        print(f"{key}: {value}")

    print(f"Distinct executable images: {len(image_counts)}")
    print("Top executable image counts:")

    for executable, count in image_counts.most_common(20):
        print(f"  {executable}: {count}")

    print(f"\nOutput: {output_path}")
    print(f"Manifest: {output_path}.meta.json")

    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Import LMD-2022 Normal.csv Event ID 1 records "
            "into canonical reference JSONL."
        )
    )

    parser.add_argument(
        "--source",
        type=Path,
        required=True,
        help="Path to LMD-2022 Normal.csv",
    )

    parser.add_argument(
        "--output",
        default="lmd2022_normal_process_creation.jsonl",
        help="Output filename under data/reference",
    )

    parser.add_argument(
        "--run-id",
        default="reference-lmd-2022-normal",
        help="Run identifier assigned to imported reference events",
    )

    parser.add_argument(
        "--host-id",
        default="reference-lmd-2022-normal",
        help="Stable host identifier for these source records",
    )

    args = parser.parse_args()

    if not args.source.is_file():
        raise FileNotFoundError(
            f"Source CSV not found: {args.source}"
        )

    import_reference_data(
        source_path=args.source,
        output_filename=args.output,
        run_id=args.run_id,
        host_id=args.host_id,
    )


if __name__ == "__main__":
    main()
