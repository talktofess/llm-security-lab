# Threat Model — Vulnerable LLM Agent

> **Ethics & scope.** The target is an intentionally-vulnerable application we
> built ourselves, for defensive study. Nothing here is to be used against
> systems you do not own or lack written authorization to test.

## System under test

An LLM agent that:
- runs under a developer-authored **system prompt** (contains an operational secret),
- answers questions over a **document corpus** (multi-tenant; some documents are
  attacker-controlled),
- can call **tools** (`file_read`, `db_query`).

## Assets

| Asset | Why it matters |
|---|---|
| System prompt / instructions | contains an operational secret; leaks erode all other controls |
| Other tenants' documents | confidentiality; multi-tenant isolation |
| Host filesystem (via `file_read`) | arbitrary read = credential/secret theft |
| Outbound network (via output / `http`) | exfiltration channel |

## Attackers & entry points

| Attacker | Entry point | Technique |
|---|---|---|
| Malicious user | the prompt box | **direct** prompt injection, tool abuse, extraction |
| Malicious document author | a retrieved document | **indirect** prompt injection, exfiltration payloads |

## Trust boundaries (the key insight)

- **User input is untrusted.**
- **Retrieved documents are equally untrusted** — the payload can ride in through
  the *data* path, not just the user path. This is the boundary most LLM apps
  get wrong.
- Tool outputs are untrusted.
- The **only** trusted text is the developer's own system prompt.

## Attack classes (OWASP LLM Top 10 aligned)

1. **Direct prompt injection** — user input overrides the system prompt.
2. **Indirect prompt injection** — a poisoned document overrides it.
3. **System-prompt extraction** — leak the instructions / secret.
4. **Tool abuse** — drive a tool with attacker-chosen args (path traversal).
5. **Cross-tenant data exposure** — read another tenant's documents.
6. **Exfiltration** — smuggle data out via an auto-rendered image / outbound URL.

## Controls (mapped in the report)

Input filtering · spotlighting of untrusted data · tool allowlist + argument
validation · output guarding (egress of secrets) · tenant isolation **at the
retrieval layer** · egress control (URL/host allowlist). The last four are
**model-independent** — they hold even against a model that obeys the attacker.

## Residual risk

A determined attacker who finds a tool whose *legitimate* arguments still cause
harm, or a novel injection phrasing the input filter misses, may bypass the
prompt-layer controls — which is why the model-independent controls
(tool/tenant/egress/output) are the backbone. See the report's residual-risk
section.
