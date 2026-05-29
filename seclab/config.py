from __future__ import annotations

from pydantic import BaseModel, Field

from .constants import SYSTEM_PROMPT


class Defenses(BaseModel):
    model_config = {"frozen": True}

    spotlighting: bool = False      # delimit/mark untrusted content as data
    input_filter: bool = False      # block injection patterns in user input
    tool_allowlist: bool = False    # validate tool name + args, scope paths
    output_guard: bool = False      # redact system-prompt / secret egress
    tenant_isolation: bool = False  # access control AT the retrieval layer
    egress_control: bool = False    # strip external URLs / auto-rendered images

    @classmethod
    def vulnerable(cls) -> "Defenses":
        return cls()

    @classmethod
    def hardened(cls) -> "Defenses":
        return cls(
            spotlighting=True, input_filter=True, tool_allowlist=True,
            output_guard=True, tenant_isolation=True, egress_control=True,
        )


class AgentConfig(BaseModel):
    system_prompt: str = SYSTEM_PROMPT
    user_id: str = "alice"                 # the requesting tenant
    model: str = "mock"                    # "mock" | "claude-..."
    defenses: Defenses = Field(default_factory=Defenses.vulnerable)
