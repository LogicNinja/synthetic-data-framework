
"""Run the WMI-to-PowerShell synthetic attack scenario."""

import json
import sys
from pathlib import Path

# Add the src directory to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from synthetic_data.simulator.scenario_runner import ScenarioRunner
from synthetic_data.scenarios.wmi_powershell import run_wmi_powershell


def main() -> None:
    """Execute the scenario and print its generated events."""

    runner = ScenarioRunner()

    result = runner.run(
        scenario_id="S2_WMI_POWERSHELL",
        run_id="run-wmi-001",
        hostname="WIN-TEST-01",
        username="testuser",
        scenario=run_wmi_powershell,
    )

    print(f"Scenario ID: {result.scenario_id}")
    print(f"Run ID: {result.run_id}")
    print(f"Generated events: {len(result.events)}")
    print("\nGenerated Events:\n")

    for event in result.events:
        print(json.dumps(event.to_dict(), indent=2))
        print("-" * 60)


if __name__ == "__main__":
    main()
