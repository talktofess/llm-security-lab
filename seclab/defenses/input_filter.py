"""Block instruction-override patterns in *user* input before they reach the
model. Scoped to override phrasing; extraction/tool payloads are handled by
their own downstream controls.
"""
from __future__ import annotations

import re

_PATTERNS = re.compile(
    r"(ignore|disregard)\b[\s\w]{0,30}\binstructions"
    r"|you are now"
    r"|system note:",
    re.I,
)


def is_malicious(user_input: str) -> bool:
    return bool(_PATTERNS.search(user_input))
