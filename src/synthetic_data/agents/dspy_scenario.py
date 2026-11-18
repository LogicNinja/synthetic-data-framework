"""Optional DSPy program and optimizer for scenario-spec generation.

Install the optional dependency with ``pip install -e '.[dspy]'``. DSPy and
its model client are imported lazily so the core simulator does not depend on
them.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from synthetic_data.scenarios.spec import ScenarioSpecError, validate_spec


class DSPyUnavailableError(RuntimeError):
    """Raised when an optional DSPy operation is requested without DSPy."""


def _import_dspy() -> Any:
    try:
        import dspy
    except ImportError as error:
        raise DSPyUnavailableError(
            "DSPy integration requires the optional dependency: "
            "pip install -e '.[dspy]'"
        ) from error
    return dspy


def scenario_quality_metric(example: Any, prediction: Any, trace: Any = None) -> float:
    """Score valid outputs and reward agreement with trusted training examples."""
    try:
        predicted = json.loads(prediction.scenario_json)
        gold = json.loads(example.scenario_json)
        validate_spec(predicted)
        validate_spec(gold)
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError, ScenarioSpecError):
        return 0.0

    score = 0.5
    if predicted["label"] == gold["label"]:
        score += 0.25
    predicted_actions = [step["action"] for step in predicted["steps"]]
    gold_actions = [step["action"] for step in gold["steps"]]
    p_set, g_set = set(predicted_actions), set(gold_actions)
    action_jaccard = len(p_set & g_set) / len(p_set | g_set) if p_set | g_set else 1.0
    score += 0.25 * action_jaccard
    return score


class DSPyScenarioProgram:
    """DSPy-backed StructuredGenerationClient with a validity-based optimizer."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str = "grok-4.7",
        base_url: str = "https://api.x.ai/v1",
        max_tokens: int = 6000,
    ) -> None:
        if not api_key:
            raise ValueError("api_key must be provided.")
        if not base_url.startswith("https://"):
            raise ValueError("base_url must use HTTPS.")
        dspy = _import_dspy()
        self.dspy = dspy
        self.lm = dspy.LM(
            f"openai/{model}",
            api_key=api_key,
            api_base=base_url.rstrip("/"),
            max_tokens=max_tokens,
            cache=False,
        )
        self.signature = self._make_signature(dspy)
        self.program = dspy.Predict(self.signature)

    @staticmethod
    def _make_signature(dspy: Any) -> type:
        class ScenarioSignature(dspy.Signature):
            """Follow the instructions and emit one JSON object matching schema."""

            system_prompt = dspy.InputField()
            user_prompt = dspy.InputField()
            schema_json = dspy.InputField()
            scenario_json = dspy.OutputField(desc="A JSON object; no markdown.")

        return ScenarioSignature

    def generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema_name: str,
        schema: dict[str, Any],
        image_paths: Iterable[str] = (),
    ) -> dict[str, Any]:
        if image_paths:
            raise ValueError("DSPy text backend does not accept image_paths.")
        del schema_name
        with self.dspy.context(lm=self.lm):
            result = self.program(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                schema_json=json.dumps(schema, ensure_ascii=False),
            )
        try:
            parsed = json.loads(result.scenario_json)
        except (json.JSONDecodeError, TypeError) as error:
            raise ValueError("DSPy returned invalid JSON for scenario output.") from error
        if not isinstance(parsed, dict):
            raise ValueError("DSPy output must be a JSON object.")
        return parsed

    def compile_with_examples(
        self,
        examples: list[dict[str, str]],
        *,
        max_bootstrapped_demos: int = 4,
        max_labeled_demos: int = 8,
    ) -> Any:
        """Compile few-shot demonstrations from trusted request/spec pairs.

        Each example requires ``system_prompt``, ``user_prompt``, ``schema``
        and a ground-truth ``scenario_json`` string. Evaluation should use a
        disjoint set; the metric checks validity and label/action agreement.
        """
        if not examples:
            raise ValueError("At least one trusted training example is required.")
        trainset = []
        for item in examples:
            gold = json.loads(item["scenario_json"])
            validate_spec(gold)
            trainset.append(
                self.dspy.Example(
                    system_prompt=item["system_prompt"],
                    user_prompt=item["user_prompt"],
                    schema_json=item["schema"],
                    scenario_json=item["scenario_json"],
                ).with_inputs("system_prompt", "user_prompt", "schema_json")
            )
        optimizer = self.dspy.BootstrapFewShot(
            metric=scenario_quality_metric,
            max_bootstrapped_demos=max_bootstrapped_demos,
            max_labeled_demos=max_labeled_demos,
        )
        self.program = optimizer.compile(self.program, trainset=trainset)
        return self.program
