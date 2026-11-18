"""Generate one declarative scenario spec with the Grok Scenario Agent."""

from __future__ import annotations

import argparse
import json

from synthetic_data.agents import ScenarioAgent


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a validated Windows scenario spec using Grok."
    )
    parser.add_argument("request", help="Natural-language scenario description")
    parser.add_argument("--scenario-id")
    parser.add_argument("--hostname", default="WS-SYNTH-001")
    parser.add_argument("--username", default="synthetic_user")
    parser.add_argument("--label", choices=["malicious", "benign"])
    parser.add_argument(
        "--technique-label",
        action="append",
        dest="technique_labels",
        help="Trusted ATT&CK technique ID; repeat to supply multiple labels",
    )
    parser.add_argument("--start-timestamp")
    args = parser.parse_args()

    result = ScenarioAgent().generate(
        args.request,
        scenario_id=args.scenario_id,
        hostname=args.hostname,
        username=args.username,
        label=args.label,
        technique_labels=args.technique_labels,
        start_timestamp=args.start_timestamp,
    )
    print(json.dumps(result.spec, indent=2, ensure_ascii=False))
    print(
        "\\nReview the generated ATT&CK labels before treating them as "
        "authoritative ground truth."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
