# LLM Security Lab

Attack a deliberately-vulnerable LLM agent, fix it, and **detect** the attacks —
the deliverable is a professional **[security report](REPORT.md)** backed by an
automated **exploit-regression suite**.

> **Ethics & scope.** The target is an intentionally-vulnerable app we built
> ourselves, for defensive study. Never test systems you don't own or lack
> written authorization to test. Start with [THREAT_MODEL.md](THREAT_MODEL.md).

> Implements the scope in [`../04-llm-security-lab.md`](../04-llm-security-lab.md).
> Defenses are toggleable, so the **same** exploit suite runs against the
> `vulnerable` and `hardened` builds — that's the before/after evidence *and* the
> regression suite. A deliberately-**gullible mock model** makes every vuln fire
> deterministically offline (no API key); a real Claude backend is optional.

## The result

| # | Finding | Severity | Vulnerable | Hardened | Primary control | Detected |
|---|---|---|---|---|---|---|
| 1 | Direct prompt injection | High | EXPLOITED | blocked | `input_filter` | yes |
| 2 | Indirect prompt injection (poisoned doc) | High | EXPLOITED | blocked | `spotlighting` | yes |
| 3 | System-prompt / secret extraction | High | EXPLOITED | blocked | `output_guard` | yes |
| 4 | Tool abuse (path traversal) | Critical | EXPLOITED | blocked | `tool_allowlist` | yes |
| 5 | Cross-tenant data exposure | High | EXPLOITED | blocked | `tenant_isolation` | yes |
| 6 | Exfiltration via auto-rendered image | High | EXPLOITED | blocked | `egress_control` | yes |

The strongest controls (`tool_allowlist`, `tenant_isolation`, `output_guard`,
`egress_control`) are **model-independent** — they hold even against a model that
obeys the attacker. The prompt-layer controls (`input_filter`, `spotlighting`)
sit on top for defense-in-depth.

## Architecture

```
attacker ─[input_filter]─▶ agent
                            │ assemble: system + [spotlight] retrieved docs + user
   poisoned doc ─corpus─[tenant_isolation]─┘
                            ▼ LLM (gullible mock | Claude)
                  [tool_guard]──▶ tools (file_read, db_query)
                            ▼
                  [output_guard]+[egress_control] ─▶ response
                            │
   every stage ──▶ detection.rules ─▶ events (per attack class)
```

| Layer | Package |
|---|---|
| Target agent | `seclab/agent/` (agent, corpus, tools) |
| Gullible model / seam | `seclab/llm/` (mock + anthropic) |
| Defenses (toggleable) | `seclab/defenses/` (6 controls) |
| Detection | `seclab/detection/` (events, rules) |
| Exploits | `seclab/exploits/` (6 attack classes) |
| Report | `seclab/report.py` |

## Run it offline (no API key)

```powershell
cd "llm-security-lab"
python -m venv .venv ; .venv\Scripts\Activate.ps1
pip install -r requirements-test.txt        # just pydantic + pytest

pytest -q                                    # exploit-regression suite (24 tests)
python -m seclab.cli attack                  # 6/6 EXPLOITED on the vulnerable build
python -m seclab.cli attack --hardened       # 6/6 blocked
python -m seclab.cli detect                  # detection events per attack
python -m seclab.cli report                  # regenerate REPORT.md from live runs
```

## The exploit-regression suite (the standout artifact)

- `tests/test_exploits_vulnerable.py` — every exploit **lands** on the vulnerable build.
- `tests/test_exploits_hardened.py` — every exploit is **blocked AND detected** on the hardened build.
- `tests/test_defenses_unit.py` — each exploit is blocked by its **single** primary control in isolation.

CI runs all of it on every push — no API key, no network.

## Real model (optional)

Set `model="claude-..."` (and `ANTHROPIC_API_KEY`). A real model resists much of
the prompt-layer surface on its own, which is exactly why the model-independent
controls are the backbone. The point of the lab is the controls, not the model.

## Design notes

- **Defenses behind flags** (`Defenses.vulnerable()` / `.hardened()`) is the
  pivot: one agent pipeline, two postures, one exploit suite.
- **Detection is a monitor**, independent of prevention — you can detect an
  attack you don't block, and you should detect one you do.
- **The report can't drift:** PoC inputs and before/after evidence are generated
  from real exploit runs (`seclab report`).
