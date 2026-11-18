"""Minimal xAI Responses API client using only the Python standard library."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from synthetic_data.agents.config import GrokConfig


class GrokAPIError(RuntimeError):
    """Raised when the xAI API request fails or returns an unusable response."""


class GrokResponsesClient:
    """Call xAI's Responses API with strict JSON-schema output formatting."""

    def __init__(self, config: GrokConfig | None = None) -> None:
        self.config = config or GrokConfig.from_env()

    def generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema_name: str,
        schema: dict[str, Any],
    ) -> dict[str, Any]:
        if not schema_name.strip():
            raise ValueError("schema_name must not be empty.")

        payload = {
            "model": self.config.model,
            "input": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_output_tokens": self.config.max_output_tokens,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": schema_name,
                    "strict": False,
                    "schema": schema,
                }
            },
        }
        request = urllib.request.Request(
            f"{self.config.base_url}/responses",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request, timeout=self.config.timeout_seconds
            ) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise GrokAPIError(
                f"xAI API returned HTTP {error.code}: {detail[:1000]}"
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise GrokAPIError(f"Could not reach xAI API: {error}") from error
        except json.JSONDecodeError as error:
            raise GrokAPIError("xAI API returned invalid JSON.") from error

        if response_data.get("status") == "incomplete":
            details = response_data.get("incomplete_details") or {}
            raise GrokAPIError(f"Grok response was incomplete: {details}")

        output_text = self._extract_output_text(response_data)
        try:
            parsed = json.loads(output_text)
        except json.JSONDecodeError as error:
            raise GrokAPIError(
                "Grok returned content that was not valid JSON."
            ) from error

        if not isinstance(parsed, dict):
            raise GrokAPIError("Grok JSON response must be an object.")
        return parsed

    @staticmethod
    def _extract_output_text(response_data: dict[str, Any]) -> str:
        """Extract visible text from Responses API output items."""
        chunks: list[str] = []
        for item in response_data.get("output", []):
            if item.get("type") != "message":
                continue
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    chunks.append(content.get("text", ""))
        text = "".join(chunks).strip()
        if not text:
            raise GrokAPIError("Grok response contained no output text.")
        return text
