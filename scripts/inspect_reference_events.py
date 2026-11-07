import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SYNTHETIC = ROOT / "data" / "generated" / "s2_wmi_powershell_run-20261106T133001Z.jsonl"
REFERENCE = ROOT / "data" / "reference" / "splunk_t1047_process_creation.jsonl"


def load_events(path):
    with path.open("r", encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


synthetic = load_events(SYNTHETIC)
reference = load_events(REFERENCE)

print("=== SYNTHETIC S2 EVENTS ===")
for event in synthetic:
    print(json.dumps(event, indent=2))


print("\n=== REFERENCE EVENTS: FIRST 5 ===")
for event in reference[:5]:
    print(json.dumps(event, indent=2))