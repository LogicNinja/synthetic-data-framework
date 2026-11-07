"""Import Splunk Attack Data Sysmon Event ID 1 records as canonical reference events."""

import argparse
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from synthetic_data.normalization.windows_event_normalizer import (
    WindowsEventNormalizer,
)
from synthetic_data.storage.dataset_store import DatasetStore


EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"e": EVENT_NS}


def _local_name(tag: str) -> str:
    """Remove an XML namespace from a tag."""
    return tag.split("}", 1)[-1]


def _system_to_dict(system_element: ET.Element) -> dict:
    """Convert the XML System section into the normalizer's expected shape."""
    system = {}

    for element in system_element:
        name = _local_name(element.tag)

        if name in {"Provider", "Execution", "Security", "TimeCreated"}:
            system[name] = dict(element.attrib)
        elif name == "Correlation":
            system[name] = dict(element.attrib)
        else:
            system[name] = element.text

    return system


def _event_data_to_dict(event_data_element: ET.Element) -> dict:
    """Convert named EventData fields into a dictionary."""
    event_data = {}

    if event_data_element is None:
        return event_data

    for element in event_data_element.findall("e:Data", NS):
        name = element.attrib.get("Name")

        if name:
            event_data[name] = element.text

    return event_data


def parse_sysmon_xml_line(line: str) -> dict | None:
    """Parse one line of Windows Event XML into a normalizer-compatible dict."""
    root = ET.fromstring(line)

    system_element = root.find("e:System", NS)
    if system_element is None:
        return None

    system = _system_to_dict(system_element)
    event_data = _event_data_to_dict(root.find("e:EventData", NS))

    return {
        "System": system,
        "EventData": event_data,
    }


def import_reference_data(
    source_path: Path,
    output_filename: str,
    run_id: str,
) -> None:
    counts = Counter()
    events = []

    with source_path.open("r", encoding="utf-8", errors="replace") as source_file:
        for line_number, line in enumerate(source_file, start=1):
            if not line.strip():
                continue

            counts["lines_seen"] += 1

            try:
                raw_event = parse_sysmon_xml_line(line)
            except ET.ParseError:
                counts["malformed_xml"] += 1
                continue

            if raw_event is None:
                counts["missing_system"] += 1
                continue

            system = raw_event["System"]
            event_id = str(system.get("EventID", ""))

            counts[f"event_id_{event_id}"] += 1

            # Layer 4 currently compares process-creation telemetry only.
            if event_id != "1":
                counts["non_process_creation_skipped"] += 1
                continue

            computer = system.get("Computer")
            if not computer:
                counts["missing_computer"] += 1
                continue

            timestamp = system.get("TimeCreated", {}).get("SystemTime")
            if not timestamp:
                counts["missing_timestamp"] += 1
                continue

            # Keep a stable host identifier derived from the source hostname.
            host_id = f"reference-{computer.lower()}"

            try:
                event = WindowsEventNormalizer.normalize(
                    raw_event,
                    host_id=host_id,
                    run_id=run_id,
                    origin="reference",
                )
                event.validate()
            except (ValueError, TypeError) as exc:
                counts["normalization_or_validation_failed"] += 1
                print(f"Skipped line {line_number}: {exc}")
                continue

            events.append(event)
            counts["imported"] += 1

    if not events:
        raise RuntimeError(
            "No valid Event ID 1 records were imported. "
            "Check the source file and normalizer."
        )

    output_path = DatasetStore.save(
        events=events,
        dataset_type="reference",
        filename=output_filename,
        metadata={
            "source": "Splunk Attack Data",
            "source_repository": "https://github.com/splunk/attack_data",
            "source_dataset": "T1047/execution_scrcons/windows-sysmon.log",
            "source_event_id": 1,
            "description": (
                "Sysmon process-creation records imported for reference "
                "realism validation. Original source fields are preserved."
            ),
            "import_counts": dict(counts),
        },
    )

    print("\nImport complete")
    print("----------------")
    for key, value in sorted(counts.items()):
        print(f"{key}: {value}")

    print(f"\nOutput: {output_path}")
    print(f"Manifest: {output_path}.meta.json")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import Splunk Sysmon Event ID 1 records into reference JSONL."
    )
    parser.add_argument(
        "--source",
        type=Path,
        required=True,
        help="Path to the source windows-sysmon.log file.",
    )
    parser.add_argument(
        "--output",
        default="splunk_t1047_process_creation.jsonl",
        help="Output filename under data/reference.",
    )
    parser.add_argument(
        "--run-id",
        default="reference-splunk-t1047",
        help="Run identifier assigned to imported reference events.",
    )

    args = parser.parse_args()

    if not args.source.is_file():
        raise FileNotFoundError(f"Source log not found: {args.source}")

    import_reference_data(
        source_path=args.source,
        output_filename=args.output,
        run_id=args.run_id,
    )


if __name__ == "__main__":
    main()