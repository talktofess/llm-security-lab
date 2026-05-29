"""Block egress of the system prompt / operational secret in the final output.
Model-independent: even if the model leaks, the secret never reaches the user.
"""
from __future__ import annotations

from ..constants import SECRET


def redact(answer: str, system_prompt: str) -> str:
    out = answer
    out = out.replace(SECRET, "[REDACTED]")
    # Redact any non-trivial line of the system prompt that appears verbatim.
    for line in system_prompt.splitlines():
        line = line.strip()
        if len(line) > 15 and line in out:
            out = out.replace(line, "[REDACTED system prompt]")
    return out
