"""Shared interfaces and result types for LLM agents."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Protocol


class StructuredGenerationClient(Protocol):
    """Small interface that lets agents use real or deterministic test clients."""

    def generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema_name: str,
        schema: dict[str, Any],
    ) -> dict[str, Any]: ...


class BaseAgent(ABC):
    """Common base class; agents own prompts and validate their own outputs."""

    def __init__(self, client: StructuredGenerationClient) -> None:
        self.client = client

    @abstractmethod
    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the agent's task."""
