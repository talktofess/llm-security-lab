"""Heuristic detectors, one tap per pipeline stage. They tag each signal with a
canonical attack class so a dashboard / SOC view can report per-class detection.
Detection runs independently of prevention.
"""
from __future__ import annotations

import re

from .. import constants as C
from ..schemas import RetrievedDoc, SecurityEvent, ToolCall
from .events import EventLog

_OVERRIDE = re.compile(r"(ignore|disregard)\b[\s\w]{0,30}\binstructions|system note:", re.I)
_EXTRACT = re.compile(r"(reveal|print|show|repeat|output|verbatim).{0,40}(system prompt|your instructions)", re.I)
_TOOLCALL = re.compile(r"call\s+\w+\s*\(", re.I)
_TRAVERSAL = re.compile(r"\.\./|/etc/|/root/|[A-Za-z]:\\|\.\.\\")
_EXFIL = re.compile(r"(append|include|add).{0,40}(https?://|!\[)", re.I)


def _ev(cls: str, sev: str, signal: str, excerpt: str = "") -> SecurityEvent:
    return SecurityEvent(attack_class=cls, severity=sev, signal=signal, excerpt=excerpt[:120])


def detect_input(log: EventLog, user_input: str) -> None:
    if _OVERRIDE.search(user_input):
        log.add(_ev(C.DIRECT_INJECTION, "high", "instruction-override pattern in user input", user_input))
    if _EXTRACT.search(user_input):
        log.add(_ev(C.PROMPT_EXTRACTION, "high", "system-prompt extraction attempt", user_input))
    if _TOOLCALL.search(user_input) or _TRAVERSAL.search(user_input):
        log.add(_ev(C.TOOL_ABUSE, "critical", "tool-call / path-traversal pattern in user input", user_input))


def detect_docs(log: EventLog, docs: list[RetrievedDoc]) -> None:
    for d in docs:
        if _OVERRIDE.search(d.text):
            log.add(_ev(C.INDIRECT_INJECTION, "high", "override pattern in retrieved document", d.source))
        if _EXFIL.search(d.text):
            log.add(_ev(C.EXFILTRATION, "high", "exfiltration directive in retrieved document", d.source))


def detect_cross_tenant(log: EventLog, docs: list[RetrievedDoc], user_id: str) -> None:
    for d in docs:
        if d.tenant not in (user_id, "public"):
            log.add(_ev(C.CROSS_TENANT, "high", f"retrieval matched foreign-tenant doc ({d.tenant})", d.source))


def detect_tool(log: EventLog, call: ToolCall) -> None:
    if _TRAVERSAL.search(call.args) or call.name not in ("file_read", "db_query"):
        log.add(_ev(C.TOOL_ABUSE, "critical", f"suspicious tool call {call.name}({call.args})", call.args))


def detect_output(log: EventLog, answer: str, system_prompt: str) -> None:
    for line in system_prompt.splitlines():
        line = line.strip()
        if len(line) > 15 and line in answer:
            log.add(_ev(C.PROMPT_EXTRACTION, "high", "system-prompt text present in output", line))
            break
