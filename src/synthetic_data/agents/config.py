"""Configuration for the xAI Grok API integration."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class GrokConfig:
    """Runtime settings; credentials are read from the environment, never files."""

    api_key: str
    model: str = "grok-4.7"
    base_url: str = "https://api.x.ai/v1"
    timeout_seconds: float = 90.0
    max_output_tokens: int = 6000

    @classmethod
    def from_env(cls) -> "GrokConfig":
        api_key = os.getenv("XAI_API_KEY") or os.getenv("GROK_API_KEY")
        if not api_key:
            raise ValueError(
                "Grok API key not found. Set XAI_API_KEY (recommended) "
                "or GROK_API_KEY in your environment."
            )

        model = os.getenv("GROK_MODEL", "grok-4.7").strip()
        base_url = os.getenv("XAI_BASE_URL", "https://api.x.ai/v1").rstrip("/")
        if not model:
            raise ValueError("GROK_MODEL must not be empty.")
        if not base_url.startswith("https://"):
            raise ValueError("XAI_BASE_URL must use HTTPS.")

        return cls(api_key=api_key, model=model, base_url=base_url)
