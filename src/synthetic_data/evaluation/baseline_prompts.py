"""Repeatable, validator-based comparison of scenario-generation prompts."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Callable

from jsonschema import Draft202012Validator, FormatChecker

from synthetic_data.scenarios.spec import ScenarioSpecError, validate_spec


def evaluate_prompt_baselines(
    *,
    cases: list[dict[str, Any]],
    prompts: dict[str, str],
    schema: dict[str, Any],
    generate_json: Callable[..., dict[str, Any]],
    model: str,
    repetitions: int = 1,
) -> dict[str, Any]:
    """Evaluate prompt variants on fixed cases using schema and spec checks.

    API errors are recorded as failed attempts so a partial run still yields a
    useful report. No generated sample is labeled trusted solely by this run.
    """
    if repetitions < 1:
        raise ValueError("repetitions must be at least 1.")
    if not cases or not prompts:
        raise ValueError("At least one case and one prompt are required.")

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    results: list[dict[str, Any]] = []

    for prompt_id, system_prompt in prompts.items():
        for case in cases:
            for repetition in range(1, repetitions + 1):
                constraints = case.get("constraints", {})
                user_prompt = (
                    "Create one scenario for this request.\n"
                    f"Request: {case['request']}\n"
                    "Caller constraints (use supplied values exactly):\n"
                    f"{json.dumps(constraints, ensure_ascii=False, indent=2)}\n"
                    "Follow the supplied JSON Schema and the system instructions."
                )
                started = time.perf_counter()
                result: dict[str, Any] = {
                    "prompt_id": prompt_id,
                    "case_id": case["case_id"],
                    "repetition": repetition,
                    "valid": False,
                    "latency_seconds": None,
                    "errors": [],
                    "spec": None,
                }
                try:
                    spec = generate_json(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        schema_name="windows_scenario_spec",
                        schema=schema,
                    )
                    schema_errors = sorted(
                        validator.iter_errors(spec),
                        key=lambda error: list(map(str, error.absolute_path)),
                    )
                    if schema_errors:
                        result["errors"].extend(
                            f"schema: {error.message}" for error in schema_errors
                        )
                    else:
                        try:
                            validate_spec(spec)
                        except ScenarioSpecError as error:
                            result["errors"].append(f"scenario: {error}")
                    for key, expected in constraints.items():
                        if spec.get(key) != expected:
                            result["errors"].append(
                                f"constraint: {key} did not match caller value"
                            )
                    result["spec"] = spec
                    result["valid"] = not result["errors"]
                except Exception as error:  # Keep failed API attempts in the report.
                    result["errors"].append(f"generation: {type(error).__name__}: {error}")
                finally:
                    result["latency_seconds"] = round(
                        time.perf_counter() - started, 4
                    )
                results.append(result)

    by_prompt: dict[str, dict[str, Any]] = {}
    for prompt_id in prompts:
        prompt_results = [item for item in results if item["prompt_id"] == prompt_id]
        valid_count = sum(item["valid"] for item in prompt_results)
        by_prompt[prompt_id] = {
            "attempts": len(prompt_results),
            "valid_attempts": valid_count,
            "valid_rate": valid_count / len(prompt_results),
            "mean_latency_seconds": round(
                mean(item["latency_seconds"] for item in prompt_results), 4
            ),
            "prompt_sha256": hashlib.sha256(
                prompts[prompt_id].encode("utf-8")
            ).hexdigest(),
        }

    return {
        "report_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "repetitions": repetitions,
        "cases": [case["case_id"] for case in cases],
        "metrics_note": (
            "Validity means JSON Schema compliance, scenario-spec validity, "
            "and caller-constraint compliance. It does not measure realism, "
            "label correctness, model utility, or token cost."
        ),
        "summary": by_prompt,
        "results": results,
    }


def load_prompt_files(paths: dict[str, Path]) -> dict[str, str]:
    """Read named UTF-8 prompt files, rejecting empty prompts."""
    prompts = {name: path.read_text(encoding="utf-8").strip() for name, path in paths.items()}
    if any(not prompt for prompt in prompts.values()):
        raise ValueError("Prompt files must not be empty.")
    return prompts
