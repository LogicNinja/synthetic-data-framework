
"""End-to-end pipeline.

spec -> simulator events -> action trace provenance validation
     -> Sigma detections -> schema validation
     -> JSONL dataset -> reload and compare.

Run it from the repo root with:
    python -m synthetic_data.pipeline.runner s2_wmi_powershell
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from synthetic_data.config.settings import KNOWLEDGE_DIR
from synthetic_data.detection.sigma_evaluator import (
    SigmaEvaluationError,
    SigmaEvaluator,
)
from synthetic_data.detection.sigma_loader import SigmaRuleLoader
from synthetic_data.models.event import CanonicalEvent, DetectionResult
from synthetic_data.scenarios.spec import load_builtin_spec, spec_to_scenario
from synthetic_data.schemas.event_validator import validate_event
from synthetic_data.schemas.provenance_validator import validate_provenance
from synthetic_data.simulator.scenario_runner import ScenarioRunner
from synthetic_data.storage.dataset_store import DatasetStore

# Standard SigmaHQ layout. Change it if your submodule is laid out differently.
DEFAULT_RULE_DIR = (
    KNOWLEDGE_DIR
    / "sigma_rules"
    / "rules"
    / "windows"
    / "process_creation"
)


@dataclass
class PipelineReport:
    scenario_id: str
    run_id: str
    label: str
    event_count: int
    rules_loaded: int
    rules_failed_to_load: int = 0
    unsupported_evaluations: int = 0
    schema_errors: dict[str, list[str]] = field(default_factory=dict)
    provenance_errors: list[str] = field(default_factory=list)
    detections: dict[str, list[str]] = field(default_factory=dict)
    saved_path: str | None = None
    roundtrip_ok: bool = False

    @property
    def ok(self) -> bool:
        return (
            not self.schema_errors
            and not self.provenance_errors
            and self.roundtrip_ok
            and self.rules_failed_to_load == 0
        )


def load_rules(rule_dir: str | Path) -> tuple[list[dict[str, Any]], int]:
    """Load every Sigma rule in a directory; return (rules, failed_to_load)."""
    root = Path(rule_dir)

    if not root.is_dir():
        raise NotADirectoryError(f"Rule directory not found: {root}")

    rules: list[dict[str, Any]] = []
    failed = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".yml", ".yaml"}:
            continue

        try:
            rules.append(SigmaRuleLoader.load_rule(path))
        except (ValueError, OSError):
            failed += 1

    return rules, failed


def attach_detections(
    event: CanonicalEvent,
    rules: list[dict[str, Any]],
) -> int:
    """Attach every matching rule to the event.

    Only matches are stored, so the JSONL stays small. Rules the evaluator
    cannot handle are skipped; the number skipped is returned.
    """
    event_dict = event.to_dict()
    unsupported = 0

    for rule in rules:
        try:
            result = SigmaEvaluator.evaluate(rule, event_dict)
        except SigmaEvaluationError:
            unsupported += 1
            continue

        if result["matched"]:
            event.detection_results.append(
                DetectionResult(
                    rule_id=str(
                        result["rule_id"] or rule.get("title") or "unknown"
                    ),
                    matched=True,
                    evaluator_version=result["evaluator_version"],
                    reason=result["reason"],
                )
            )

    return unsupported


def run_pipeline(
    spec: dict[str, Any],
    rules: list[dict[str, Any]],
    *,
    run_id: str,
    rules_failed_to_load: int = 0,
    dataset_type: str = "generated",
    filename: str | None = None,
) -> PipelineReport:
    """Run one spec through the full pipeline and report what happened."""
    result = ScenarioRunner().run(
        scenario_id=spec["scenario_id"],
        run_id=run_id,
        hostname=spec["hostname"],
        username=spec["username"],
        scenario=spec_to_scenario(spec),
    )
    events = result.events

    report = PipelineReport(
        scenario_id=spec["scenario_id"],
        run_id=run_id,
        label=spec["label"],
        event_count=len(events),
        rules_loaded=len(rules),
        rules_failed_to_load=rules_failed_to_load,
    )

    # Layer 1: check that every event's provenance and labels agree
    # with the simulator's recorded action trace.
    report.provenance_errors = validate_provenance(
        events,
        result.trace,
    )

    # Evaluate detection rules and attach matching results.
    for event in events:
        report.unsupported_evaluations += attach_detections(event, rules)

        matched = [d.rule_id for d in event.detection_results if d.matched]
        if matched:
            report.detections[event.event_id] = matched

    # Validate event structure against the canonical schema.
    for event in events:
        errors = validate_event(event.to_dict())
        if errors:
            report.schema_errors[event.event_id] = errors

    # Never save a dataset that fails provenance or schema validation.
    if report.schema_errors or report.provenance_errors:
        return report

    filename = filename or f"{spec['scenario_id'].lower()}_{run_id}.jsonl"
    path = DatasetStore.save(events, dataset_type, filename)
    report.saved_path = str(path)

    reloaded = DatasetStore.load(dataset_type, filename)
    report.roundtrip_ok = (
        [e.to_dict() for e in events] == [e.to_dict() for e in reloaded]
    )

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one scenario spec.")
    parser.add_argument(
        "spec",
        nargs="?",
        default="s2_wmi_powershell",
        help="name of a spec in scenarios/specs (without .json)",
    )
    parser.add_argument("--rules", default=str(DEFAULT_RULE_DIR))
    args = parser.parse_args(argv)

    try:
        rules, failed = load_rules(args.rules)
    except NotADirectoryError as error:
        print(error)
        print("Pass the right folder with --rules <path>.")
        return 2

    run_id = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
    report = run_pipeline(
        load_builtin_spec(args.spec),
        rules,
        run_id=run_id,
        rules_failed_to_load=failed,
    )

    print(json.dumps(asdict(report), indent=2, default=str))
    print(f"rules failed to load: {failed}")
    print(f"OK: {report.ok}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
