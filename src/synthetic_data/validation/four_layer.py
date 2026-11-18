"""Consolidated four-layer dataset validation and acceptance policy."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ValidationCriteria:
    """Acceptance thresholds plus reporting thresholds for advisory metrics."""

    minimum_reference_sample_size: int = 30
    minimum_reference_similarity: float = 0.5
    maximum_unsupported_sigma_evaluations: int = 0
    minimum_macro_f1: float = 0.7
    minimum_macro_f1_delta: float = 0.0

    @classmethod
    def from_mapping(cls, values: dict[str, Any]) -> "ValidationCriteria":
        known = {
            "minimum_reference_sample_size",
            "minimum_reference_similarity",
            "maximum_unsupported_sigma_evaluations",
            "minimum_macro_f1",
            "minimum_macro_f1_delta",
        }
        unknown = values.keys() - known
        if unknown:
            raise ValueError(f"Unknown validation criteria: {sorted(unknown)}")
        return cls(**values)

    def __post_init__(self) -> None:
        if self.minimum_reference_sample_size < 1:
            raise ValueError("minimum_reference_sample_size must be positive.")
        if not 0 <= self.minimum_reference_similarity <= 1:
            raise ValueError("minimum_reference_similarity must be in [0, 1].")
        if self.maximum_unsupported_sigma_evaluations < 0:
            raise ValueError("maximum_unsupported_sigma_evaluations cannot be negative.")
        if not 0 <= self.minimum_macro_f1 <= 1:
            raise ValueError("minimum_macro_f1 must be in [0, 1].")
        if self.minimum_macro_f1_delta < -1 or self.minimum_macro_f1_delta > 1:
            raise ValueError("minimum_macro_f1_delta must be in [-1, 1].")


def load_validation_criteria(path: str | Path) -> ValidationCriteria:
    """Load and validate acceptance thresholds from JSON configuration."""
    values = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(values, dict):
        raise ValueError("Validation criteria file must contain a JSON object.")
    return ValidationCriteria.from_mapping(values)


@dataclass
class LayerValidation:
    name: str
    status: str
    checks: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class FourLayerValidationReport:
    """A single validation result. Only four passing layers mean validated."""

    criteria: dict[str, Any]
    layers: dict[str, LayerValidation]
    validated: bool
    decision: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _status(errors: list[str], complete: bool) -> str:
    if errors:
        return "failed"
    return "passed" if complete else "not_run"


def build_four_layer_report(
    *,
    criteria: ValidationCriteria | None = None,
    provenance_errors: list[str] | None = None,
    schema_errors: dict[str, list[str]] | None = None,
    logic_errors: list[str] | None = None,
    logic_warnings: list[str] | None = None,
    roundtrip_ok: bool = False,
    rules_failed_to_load: int = 0,
    unsupported_sigma_evaluations: int = 0,
    domain_errors: list[str] | None = None,
    domain_warnings: list[str] | None = None,
    reference_report: Any | None = None,
    critic_accepted: bool | None = None,
    utility_report: dict[str, Any] | None = None,
) -> FourLayerValidationReport:
    """Combine provenance, structural, realism/critic, and utility results.

    L1 is provenance. L2 combines schema, logical consistency, serialization
    round-trip. Sigma compatibility is reported as detection-coverage
    warnings. L3 requires domain checks and an accepted Critic review;
    reference similarity is advisory until calibrated on class-matched data.
    L4 requires held-out model metrics to meet configured thresholds.
    """
    criteria = criteria or ValidationCriteria()
    l1_errors = list(provenance_errors or [])
    l1 = LayerValidation(
        name="Internal provenance",
        status=_status(l1_errors, True),
        checks={"provenance_error_count": len(l1_errors)},
        errors=l1_errors,
    )

    schema_errors = schema_errors or {}
    l2_errors = [
        f"{event_id}: {error}"
        for event_id, errors in schema_errors.items()
        for error in errors
    ]
    l2_errors.extend(logic_errors or [])
    l2_warnings = list(logic_warnings or [])
    if rules_failed_to_load:
        l2_warnings.append(
            f"{rules_failed_to_load} selected Sigma rule(s) failed to load; detection coverage is incomplete."
        )
    if unsupported_sigma_evaluations > criteria.maximum_unsupported_sigma_evaluations:
        l2_warnings.append(
            "Unsupported Sigma evaluations exceed the configured reporting threshold "
            f"({unsupported_sigma_evaluations} > "
            f"{criteria.maximum_unsupported_sigma_evaluations}); detection coverage is incomplete."
        )
    if not roundtrip_ok:
        l2_errors.append("Dataset JSONL save/reload round-trip did not pass.")
    l2 = LayerValidation(
        name="Structural and logical correctness",
        status=_status(l2_errors, True),
        checks={
            "schema_error_count": sum(len(errors) for errors in schema_errors.values()),
            "logic_error_count": len(logic_errors or []),
            "roundtrip_ok": roundtrip_ok,
            "rules_failed_to_load": rules_failed_to_load,
            "unsupported_sigma_evaluations": unsupported_sigma_evaluations,
        },
        errors=l2_errors,
        warnings=l2_warnings,
    )

    l3_errors = list(domain_errors or [])
    l3_warnings = list(domain_warnings or [])
    l3_complete = critic_accepted is not None
    if critic_accepted is False:
        l3_errors.append("Critic did not accept the sample.")
    elif critic_accepted is None:
        l3_complete = False
        l3_warnings.append("Critic review was not supplied.")

    reference_status = getattr(reference_report, "status", None)
    reference_score = getattr(reference_report, "similarity_score", None)
    reference_count = getattr(reference_report, "reference_event_count", 0)
    sample_adequacy = getattr(reference_report, "sample_adequacy", None)
    reference_errors = list(getattr(reference_report, "errors", []) or [])
    if reference_report is None:
        l3_warnings.append("Reference telemetry comparison was not run.")
    elif reference_status != "evaluated" or reference_errors:
        l3_warnings.extend(reference_errors or [
            f"Reference comparison status is {reference_status!r}; similarity is informational until a class-matched benchmark is available."
        ])
    elif sample_adequacy != "adequate" or reference_count < criteria.minimum_reference_sample_size:
        l3_warnings.append(
            "Reference comparison sample is below the configured reporting minimum "
            f"of {criteria.minimum_reference_sample_size}."
        )
    if (
        reference_status == "evaluated"
        and not reference_errors
        and reference_score is not None
        and reference_score < criteria.minimum_reference_similarity
    ):
        l3_warnings.append(
            "Descriptive reference similarity is below the configured reporting threshold "
            f"({reference_score:.3f} < {criteria.minimum_reference_similarity:.3f}); "
            "this metric is not a hard gate because the current comparator uses process-image frequency only."
        )

    if reference_score is not None:
        l3_warnings.append(
            "Reference similarity is descriptive and uses the currently "
            "implemented process-image distribution only."
        )
    l3 = LayerValidation(
        name="Domain and reference realism",
        status=_status(l3_errors, l3_complete),
        checks={
            "critic_accepted": critic_accepted,
            "domain_error_count": len(domain_errors or []),
            "reference_status": reference_status or "not_run",
            "reference_event_count": reference_count,
            "reference_sample_adequacy": sample_adequacy or "not_assessable",
            "reference_similarity": reference_score,
            "minimum_reference_similarity": criteria.minimum_reference_similarity,
            "reference_similarity_is_hard_gate": False,
        },
        errors=l3_errors,
        warnings=l3_warnings,
    )

    l4_errors: list[str] = []
    l4_complete = utility_report is not None
    if utility_report is None:
        l4_warnings = ["Held-out model utility evaluation was not supplied."]
        final_macro_f1 = None
        delta = None
    else:
        l4_warnings = []
        if utility_report.get("error"):
            l4_complete = False
            l4_warnings.append(f"Held-out model utility evaluation failed: {utility_report['error']}")
        final_macro_f1 = utility_report.get("macro_f1")
        delta = utility_report.get("macro_f1_delta")
        if not isinstance(final_macro_f1, (int, float)) or not isinstance(delta, (int, float)):
            l4_complete = False
            l4_warnings.append("Utility report must include macro_f1 and macro_f1_delta.")
        else:
            if final_macro_f1 < criteria.minimum_macro_f1:
                l4_errors.append(
                    f"Held-out macro-F1 is below minimum ({final_macro_f1:.3f} < "
                    f"{criteria.minimum_macro_f1:.3f})."
                )
            if delta < criteria.minimum_macro_f1_delta:
                l4_errors.append(
                    f"Macro-F1 improvement is below minimum ({delta:.3f} < "
                    f"{criteria.minimum_macro_f1_delta:.3f})."
                )
    l4 = LayerValidation(
        name="Held-out model utility",
        status=_status(l4_errors, l4_complete),
        checks={
            "macro_f1": final_macro_f1,
            "macro_f1_delta": delta,
            "minimum_macro_f1": criteria.minimum_macro_f1,
            "minimum_macro_f1_delta": criteria.minimum_macro_f1_delta,
        },
        errors=l4_errors,
        warnings=l4_warnings,
    )

    layers = {"L1": l1, "L2": l2, "L3": l3, "L4": l4}
    validated = all(layer.status == "passed" for layer in layers.values())
    decision = "validated" if validated else "rejected" if any(
        layer.status == "failed" for layer in layers.values()
    ) else "incomplete"
    return FourLayerValidationReport(
        criteria=asdict(criteria),
        layers=layers,
        validated=validated,
        decision=decision,
    )


def aggregate_validation_reports(
    reports: list[FourLayerValidationReport],
    *,
    criteria: ValidationCriteria | None = None,
) -> FourLayerValidationReport:
    """Require every sample in a batch to pass each required layer."""
    criteria = criteria or ValidationCriteria()
    if not reports:
        layers = {
            "L1": LayerValidation("Internal provenance", "not_run"),
            "L2": LayerValidation("Structural and logical correctness", "not_run"),
            "L3": LayerValidation("Domain and reference realism", "not_run"),
            "L4": LayerValidation("Held-out model utility", "not_run"),
        }
        for layer in layers.values():
            layer.warnings.append("No samples were supplied for batch validation.")
        return FourLayerValidationReport(
            asdict(criteria), layers, False, "incomplete"
        )

    layers: dict[str, LayerValidation] = {}
    for key in ("L1", "L2", "L3", "L4"):
        per_sample = [report.layers[key] for report in reports]
        statuses = {layer.status for layer in per_sample}
        status = (
            "failed" if "failed" in statuses
            else "passed" if statuses == {"passed"}
            else "not_run"
        )
        layers[key] = LayerValidation(
            name=per_sample[0].name,
            status=status,
            checks={"sample_count": len(reports), "sample_statuses": [item.status for item in per_sample]},
            errors=[error for layer in per_sample for error in layer.errors],
            warnings=[warning for layer in per_sample for warning in layer.warnings],
        )
    validated = all(layer.status == "passed" for layer in layers.values())
    decision = "validated" if validated else "rejected" if any(
        layer.status == "failed" for layer in layers.values()
    ) else "incomplete"
    return FourLayerValidationReport(asdict(criteria), layers, validated, decision)
