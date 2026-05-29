"""The deliberately-gullible model.

It OBEYS imperative instructions found in its prompt — that's the whole point of
a security lab: a compliant model makes every vulnerability concrete and
deterministic. Defenses work by ensuring those imperatives never reach it in an
actionable form (input filtering, spotlighting) or by neutralizing the effect
downstream (tool guard, output guard, egress control), so they hold regardless
of how gullible the model is.

A real model (anthropic.py) resists much of this on its own — which is exactly
why the model-INDEPENDENT controls are the backbone, not the prompt wording.
"""
from __future__ import annotations

import re

from ..defenses import spotlighting
from ..schemas import LLMOutput, ToolCall

_EXTRACT = re.compile(r"(reveal|print|show|repeat|output|verbatim).{0,40}(system prompt|your instructions)", re.I)
_OVERRIDE = re.compile(r"(ignore|disregard)\b[\s\w]{0,30}\binstructions", re.I)
_REPLY_EXACTLY = re.compile(r"reply with exactly:\s*(.+)", re.I)
_APPEND = re.compile(r"append (?:this )?to your (?:answer|response):?\s*(.+)", re.I)
_TOOLCALL = re.compile(r"call\s+(\w+)\s*\(([^)]*)\)", re.I)


class GullibleLLM:
    name = "mock"

    def complete(self, system: str, context: str, user: str) -> LLMOutput:
        # Instruction scanning ignores spotlighted regions (treated as data),
        # which is precisely how spotlighting defangs document-borne payloads.
        scan = spotlighting.strip(context) + "\n" + user

        if _EXTRACT.search(scan):
            return LLMOutput(answer=system)  # leak the full system prompt

        if _OVERRIDE.search(scan):
            # Prefer the user's instruction over a document's (so direct vs.
            # indirect injection produce their own distinct payloads).
            m = _REPLY_EXACTLY.search(user) or _REPLY_EXACTLY.search(scan)
            if m:
                return LLMOutput(answer=m.group(1).strip())

        m = _APPEND.search(scan)
        if m:
            return LLMOutput(answer="Sure, here is your answer. " + m.group(1).strip())

        m = _TOOLCALL.search(scan)
        if m:
            return LLMOutput(tool_calls=[ToolCall(name=m.group(1), args=m.group(2).strip())])

        return LLMOutput(answer="I found relevant documents and answered your question.")
