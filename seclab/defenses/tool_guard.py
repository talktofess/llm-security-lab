"""Least privilege on tools: an allowlist of tool names plus argument
validation. file_read is scoped to a safe base directory; absolute paths and
traversal are rejected. Model-independent — blocks the call no matter what the
model emits.
"""
from __future__ import annotations

from ..schemas import ToolCall

ALLOWED_TOOLS = {"file_read", "db_query"}
SAFE_BASE = "data/files/"


def allowed(call: ToolCall) -> bool:
    if call.name not in ALLOWED_TOOLS:
        return False
    if call.name == "file_read":
        p = call.args.strip().strip("'\"")
        if p.startswith("/") or p.startswith("\\") or ".." in p or ":" in p:
            return False
        if not p.startswith(SAFE_BASE):
            return False
    return True
