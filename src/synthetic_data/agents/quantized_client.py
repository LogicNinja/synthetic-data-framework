"""Optional local Hugging Face client using bitsandbytes quantization."""

from __future__ import annotations

import json
import threading
from typing import Any, Sequence

from jsonschema import Draft202012Validator, FormatChecker


class QuantizedBackendUnavailableError(RuntimeError):
    """Raised when local quantization dependencies or hardware are unavailable."""


def parse_json_object(text: str) -> dict[str, Any]:
    """Parse the first JSON object in model output and reject non-object data."""
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("Local model output contained no valid JSON object.")


class TransformersQuantizedClient:
    """StructuredGenerationClient for a local CUDA model quantized to 4/8 bit.

    This adapter is opt-in and lazy-loads PyTorch, Transformers and
    bitsandbytes. The model must be an instruction-tuned causal language model.
    """

    def __init__(
        self,
        model_id: str,
        *,
        quantization: str = "4bit",
        max_new_tokens: int = 6000,
    ) -> None:
        if not model_id.strip():
            raise ValueError("model_id must be non-empty.")
        if quantization not in {"4bit", "8bit"}:
            raise ValueError("quantization must be '4bit' or '8bit'.")
        if max_new_tokens < 1:
            raise ValueError("max_new_tokens must be positive.")
        try:
            import torch
            from transformers import (
                AutoModelForCausalLM,
                AutoTokenizer,
                BitsAndBytesConfig,
            )
        except ImportError as error:
            raise QuantizedBackendUnavailableError(
                "Install the optional local model dependencies from the "
                "quantized extra; see docs/advanced_integrations.md."
            ) from error
        if not torch.cuda.is_available():
            raise QuantizedBackendUnavailableError(
                "bitsandbytes 4/8-bit inference requires a compatible CUDA GPU."
            )

        options: dict[str, Any]
        if quantization == "4bit":
            options = {
                "load_in_4bit": True,
                "bnb_4bit_quant_type": "nf4",
                "bnb_4bit_use_double_quant": True,
                "bnb_4bit_compute_dtype": torch.float16,
            }
        else:
            options = {"load_in_8bit": True}
        try:
            quant_config = BitsAndBytesConfig(**options)
            self.tokenizer = AutoTokenizer.from_pretrained(model_id)
            self.model = AutoModelForCausalLM.from_pretrained(
                model_id,
                quantization_config=quant_config,
                device_map="auto",
            )
        except Exception as error:
            raise QuantizedBackendUnavailableError(
                f"Could not load quantized model {model_id!r}: {error}"
            ) from error
        self.model_id = model_id
        self.max_new_tokens = max_new_tokens
        self._lock = threading.Lock()

    def generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema_name: str,
        schema: dict[str, Any],
        image_paths: Sequence[str] = (),
    ) -> dict[str, Any]:
        if image_paths:
            raise ValueError("This quantized text backend does not accept images.")
        del schema_name
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    f"{user_prompt}\n\nJSON Schema:\n"
                    f"{json.dumps(schema, ensure_ascii=False)}"
                ),
            },
        ]
        if getattr(self.tokenizer, "chat_template", None):
            prompt = self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        else:
            prompt = (
                f"System:\n{system_prompt}\n\nUser:\n{user_prompt}\n\n"
                f"JSON Schema:\n{json.dumps(schema, ensure_ascii=False)}\n\nAssistant:\n"
            )
        inputs = self.tokenizer(prompt, return_tensors="pt")
        input_device = self.model.get_input_embeddings().weight.device
        inputs = {name: value.to(input_device) for name, value in inputs.items()}
        with self._lock:
            generated = self.model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id,
            )
        new_tokens = generated[0][inputs["input_ids"].shape[1] :]
        text = self.tokenizer.decode(new_tokens, skip_special_tokens=True)
        result = parse_json_object(text)
        errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(result))
        if errors:
            raise ValueError(
                "Local model output did not match the JSON Schema: "
                + "; ".join(error.message for error in errors)
            )
        return result
