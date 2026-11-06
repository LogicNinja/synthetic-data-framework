"""End-to-end pipeline.

spec -> simulator events -> action trace provenance validation
     -> Sigma detections -> schema validation
     -> domain realism validation
     -> JSONL dataset -> reload and compare
     -> optional reference-based statistical realism evaluation.

Run it from the repo root with:
    python -m synthetic_data.pipeline.runner s2_wmi_powershell

To include Layer 4:
    python -m synthetic_data.pipeline.runner s2_wmi_powershell --reference data/reference/windows_events.jsonl
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
from synthetic_data.validation.domain_realism import validate_domain_realism
from synthetic_data.validation.reference_realism import (
    evaluate_reference_realism,
)


DEFAULT_RULE_DIR = (
    KNOWLEDGE_DIR
    / "sigma_rules"
    / "sigma"
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
    unsupported_reasons: dict[str, int] = field(default_factory=dict)
    schema_errors: dict[str, list[str]] = field(default_factory=dict)
    provenance_errors: list[str] = field(default_factory=list)
    domain_realism_errors: list[str] = field(default_factory=list)
    domain_realism_warnings: list[str] = field(default_factory=list)
    reference_realism_status: str = "not_requested"
    reference_event_count: int = 0
    reference_similarity_score: float | None = None
    reference_feature_distances: dict[str, float] = field(default_factory=dict)
    reference_realism_errors: list[str] = field(default_factory=list)
    detections: dict[str, list[str]] = field(default_factory=dict)
    saved_path: str | None = None
    roundtrip_ok: bool = False

    @property
    def ok(self) -> bool:
        """L1-L3 and dataset round-trip must pass.

        Reference realism is informational until a suitable baseline is
        available and the project defines an acceptance threshold.
        """
        return (
            not self.schema_errors
            and not self.provenance_errors
            and not self.domain_realism_errors
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
    unsupported_reasons: dict[str, int] | None = None,
) -> int:
    """Attach matching rules and optionally aggregate unsupported reasons."""
    event_dict = event.to_dict()
    unsupported = 0

    for rule in rules:
        try:
            result = SigmaEvaluator.evaluate(rule, event_dict)
        except SigmaEvaluationError as error:
            unsupported += 1

            if unsupported_reasons is not None:
                reason = str(error)
                unsupported_reasons[reason] = (
                    unsupported_reasons.get(reason, 0) + 1
                )

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


def _build_dataset_metadata(
    spec: dict[str, Any],
    run_id: str,
    rules_loaded: int,
    unsupported_evaluations: int,
) -> dict[str, Any]:
    """Build descriptive metadata from the declarative scenario spec."""
    technique_labels = sorted(
        {
            label
            for step in spec["steps"]
            for label in step.get("technique_labels", [])
        }
    )

    metadata: dict[str, Any] = {
        "generation_method": "simulator",
        "scenario_id": spec["scenario_id"],
        "label": spec["label"],
        "run_id": run_id,
        "hostname": spec["hostname"],
        "username": spec["username"],
        "technique_labels": technique_labels,
        "sigma_rules_loaded": rules_loaded,
        "unsupported_sigma_evaluations": unsupported_evaluations,
    }

    if "description" in spec:
        metadata["description"] = spec["description"]

    return metadata


def run_pipeline(
    spec: dict[str, Any],
    rules: list[dict[str, Any]],
    *,
    run_id: str,
    rules_failed_to_load: int = 0,
    dataset_type: str = "generated",
    filename: str | None = None,
    reference_path: str | Path | None = None,
) -> PipelineReport:
    """Run one spec through the pipeline and report what happened.

    Layer 4 is optional. If reference_path is omitted, the report records
    that no reference comparison was requested. If supplied, the reference
    dataset is evaluated after the generated dataset is saved and reloaded.
    """
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

    # Layer 1: validate provenance against the simulator action trace.
    report.provenance_errors = validate_provenance(
        events,
        result.trace,
    )

    # Evaluate detection rules and attach matching results.
    for event in events:
        report.unsupported_evaluations += attach_detections(
            event,
            rules,
            report.unsupported_reasons,
        )

        matched = [d.rule_id for d in event.detection_results if d.matched]
        if matched:
            report.detections[event.event_id] = matched

    # Layer 2: validate event structure against the canonical schema.
    for event in events:
        errors = validate_event(event.to_dict())

        if errors:
            report.schema_errors[event.event_id] = errors

    # Layer 3: domain-aware consistency checks.
    domain_report = validate_domain_realism(
        [event.to_dict() for event in events]
    )
    report.domain_realism_errors = domain_report.errors
    report.domain_realism_warnings = domain_report.warnings

    # Do not save datasets that fail L1, L2, or L3.
    if (
        report.schema_errors
        or report.provenance_errors
        or report.domain_realism_errors
    ):
        return report

    filename = filename or f"{spec['scenario_id'].lower()}_{run_id}.jsonl"
    metadata = _build_dataset_metadata(
        spec,
        run_id,
        len(rules),
        report.unsupported_evaluations,
    )

    path = DatasetStore.save(
        events,
        dataset_type,
        filename,
        metadata=metadata,
    )
    report.saved_path = str(path)

    reloaded = DatasetStore.load(dataset_type, filename)
    report.roundtrip_ok = (
        [e.to_dict() for e in events] == [e.to_dict() for e in reloaded]
    )

    # Layer 4: optional comparison against reference telemetry.
    if reference_path is not None:
        reference_report = evaluate_reference_realism(
            path,
            reference_path,
        )

        report.reference_realism_status = reference_report.status
        report.reference_event_count = reference_report.reference_event_count
        report.reference_similarity_score = (
            reference_report.similarity_score
        )
        report.reference_feature_distances = (
            reference_report.feature_distances
        )
        report.reference_realism_errors = reference_report.errors

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
    parser.add_argument(
        "--reference",
        default=None,
        help="optional reference telemetry JSONL file for Layer 4",
    )
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
        reference_path=args.reference,
    )

    print(json.dumps(asdict(report), indent=2, default=str))
    print(f"rules failed to load: {failed}")
    print(f"Layer 4 status: {report.reference_realism_status}")
    print(f"Layer 4 similarity: {report.reference_similarity_score}")
    print(f"OK: {report.ok}")

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
