"""Optional real-model backend. A real model resists much of the prompt-layer
attack surface on its own, so exploits may not "land" the way they do on the
mock. Use it to show that the model-independent controls (tool/tenant/egress/
output) still matter regardless of model behavior.
"""
from __future__ import annotations

from ..schemas import LLMOutput


class AnthropicLLM:
    def __init__(self, model: str) -> None:
        self.name = model
        self._model = model

    def complete(self, system: str, context: str, user: str) -> LLMOutput:
        from anthropic import Anthropic

        client = Anthropic()  # ANTHROPIC_API_KEY from env
        resp = client.messages.create(
            model=self._model,
            max_tokens=512,
            system=system,
            messages=[{"role": "user", "content": f"Documents:\n{context}\n\nUser: {user}"}],
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        return LLMOutput(answer=text)
