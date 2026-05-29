from __future__ import annotations

from typing import Protocol

from ..schemas import LLMOutput


class LLM(Protocol):
    name: str

    def complete(self, system: str, context: str, user: str) -> LLMOutput: ...


def make_llm(model: str) -> "LLM":
    if model == "mock":
        from .mock import GullibleLLM

        return GullibleLLM()
    from .anthropic import AnthropicLLM

    return AnthropicLLM(model)
