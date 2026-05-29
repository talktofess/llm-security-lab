from __future__ import annotations

from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    name: str
    args: str = ""


class LLMOutput(BaseModel):
    answer: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)


class RetrievedDoc(BaseModel):
    doc_id: str
    tenant: str
    source: str
    text: str


class SecurityEvent(BaseModel):
    attack_class: str
    severity: str
    signal: str
    excerpt: str = ""


class AgentResult(BaseModel):
    output: str
    tool_results: list[str] = Field(default_factory=list)
    retrieved: list[str] = Field(default_factory=list)
    retrieved_tenants: list[str] = Field(default_factory=list)
    blocked: bool = False
