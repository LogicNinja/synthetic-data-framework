import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FILES = {
    "S2 synthetic": ROOT
    / "data"
    / "generated"
    / "s2_wmi_powershell_run-20261106T133001Z.jsonl",
    "Splunk reference": ROOT
    / "data"
    / "reference"
    / "splunk_t1047_process_creation.jsonl",
}


def inspect_file(label: str, path: Path) -> None:
    counts = Counter()
    total = 0

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            event = json.loads(line)

            if event.get("event_type") != "process_creation":
                continue

            image = event.get("process", {}).get("image") or "<missing>"
            executable = image.replace("\\", "/").rsplit("/", 1)[-1].lower()

            counts[executable] += 1
            total += 1

    print(f"\n{label}")
    print(f"File: {path}")
    print(f"Process creation events: {total}")
    print("Executable counts:")

    for executable, count in counts.most_common(20):
        print(f"  {executable}: {count}")


for label, path in FILES.items():
    inspect_file(label, path)