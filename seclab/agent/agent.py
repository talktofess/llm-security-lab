"""The target agent. The pipeline is identical in both modes; each defense
inserts at its layer only when enabled in cfg.defenses. Detection runs at every
stage regardless of defenses.
"""
from __future__ import annotations

from .. import constants as C
from ..config import AgentConfig
from ..defenses import egress, input_filter, output_guard, spotlighting, tenant, tool_guard
from ..detection import rules
from ..detection.events import EventLog
from ..llm.base import make_llm
from ..schemas import AgentResult, SecurityEvent
from . import tools
from .corpus import Corpus


class Agent:
    def __init__(self, cfg: AgentConfig, corpus: Corpus | None = None) -> None:
        self.cfg = cfg
        self.llm = make_llm(cfg.model)
        self.corpus = corpus or Corpus.load()
        self.events = EventLog()

    def handle(self, user_input: str) -> AgentResult:
        d = self.cfg.defenses
        ev = self.events

        rules.detect_input(ev, user_input)

        # 1. Input filtering (prevention) — user path only.
        if d.input_filter and input_filter.is_malicious(user_input):
            ev.add(SecurityEvent(attack_class=C.DIRECT_INJECTION, severity="high",
                                 signal="user input rejected by input filter"))
            return AgentResult(output="[blocked: input rejected by guardrail]", blocked=True)

        # 2. Retrieval (detection sees the raw matches before isolation).
        matches = self.corpus.search(user_input)
        rules.detect_cross_tenant(ev, matches, self.cfg.user_id)
        rules.detect_docs(ev, matches)
        docs = tenant.isolate(matches, self.cfg.user_id) if d.tenant_isolation else matches

        # 3. Assemble context (spotlighting marks untrusted data).
        context = spotlighting.apply(docs) if d.spotlighting else "\n".join(x.text for x in docs)

        # 4. Model.
        out = self.llm.complete(self.cfg.system_prompt, context, user_input)

        # 5. Tool loop (allowlist + arg validation).
        tool_results: list[str] = []
        for call in out.tool_calls:
            rules.detect_tool(ev, call)
            if d.tool_allowlist and not tool_guard.allowed(call):
                ev.add(SecurityEvent(attack_class=C.TOOL_ABUSE, severity="critical",
                                     signal=f"tool call blocked: {call.name}({call.args})"))
                tool_results.append("[blocked: tool call rejected]")
                continue
            tool_results.append(tools.dispatch(call))

        answer = out.answer
        if tool_results:
            answer = (answer + " " + " ".join(tool_results)).strip()

        # 6. Output guard + 7. egress control.
        rules.detect_output(ev, answer, self.cfg.system_prompt)
        if d.output_guard:
            answer = output_guard.redact(answer, self.cfg.system_prompt)
        if d.egress_control:
            answer = egress.sanitize(answer, ev)

        return AgentResult(
            output=answer,
            tool_results=tool_results,
            retrieved=[x.doc_id for x in docs],
            retrieved_tenants=[x.tenant for x in docs],
            blocked=False,
        )
