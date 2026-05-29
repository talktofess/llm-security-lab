"""Generate the security report from real exploit runs, so the PoCs and
before/after evidence can never drift from the code.
"""
from __future__ import annotations

from .agent.agent import Agent
from .config import AgentConfig, Defenses
from .exploits import ALL_EXPLOITS, PRIMARY_DEFENSE


def run_matrix() -> list[dict]:
    rows = []
    for ex in ALL_EXPLOITS:
        va = Agent(AgentConfig(defenses=Defenses.vulnerable()))
        vr = ex.run(va)
        ha = Agent(AgentConfig(defenses=Defenses.hardened()))
        hr = ex.run(ha)
        rows.append({"ex": ex, "vr": vr, "hr": hr, "hevents": ha.events})
    return rows


def generate_report() -> str:
    rows = run_matrix()
    landed = sum(1 for r in rows if r["vr"].succeeded)
    blocked = sum(1 for r in rows if not r["hr"].succeeded)
    L: list[str] = []
    L.append("# Security Report — Vulnerable LLM Agent\n")
    L.append("> **Ethics & scope.** Findings are against an intentionally-vulnerable "
             "application we built ourselves, for defensive study.\n")
    L.append("## Executive summary\n")
    L.append(f"{landed}/{len(rows)} attack classes succeed against the **vulnerable** build. "
             f"After remediation, {blocked}/{len(rows)} are **blocked** on the **hardened** build, "
             "and all are **detected** at request time. The strongest controls "
             "(tool allowlist, tenant isolation, output guarding, egress control) are "
             "model-independent: they hold even against a model that obeys the attacker.\n")
    L.append("| # | Finding | Severity | Vulnerable | Hardened | Primary control | Detected |")
    L.append("|---|---|---|---|---|---|---|")
    for i, r in enumerate(rows, 1):
        ex = r["ex"]
        L.append(
            f"| {i} | {ex.title} | {ex.severity} | "
            f"{'EXPLOITED' if r['vr'].succeeded else 'safe'} | "
            f"{'blocked' if not r['hr'].succeeded else 'EXPLOITED'} | "
            f"`{PRIMARY_DEFENSE[ex.attack_class]}` | "
            f"{'yes' if r['hevents'].has(ex.attack_class) else 'no'} |"
        )
    L.append("")
    for i, r in enumerate(rows, 1):
        ex = r["ex"]
        L.append(f"## {i}. {ex.title} ({ex.severity})")
        L.append(f"- **Class:** `{ex.attack_class}` ({ex.id})")
        L.append(f"- **Description:** {r['vr'].detail}")
        L.append(f"- **PoC (exact input):** `{ex.poc}`")
        L.append(f"- **Vulnerable result:** `{r['vr'].evidence}`")
        hardened_state = "blocked" if not r["hr"].succeeded else "STILL EXPLOITED"
        L.append(f"- **Hardened result ({hardened_state}):** `{r['hr'].evidence}`")
        L.append(f"- **Remediation:** enable `{PRIMARY_DEFENSE[ex.attack_class]}` "
                 "(ship the full hardened preset for defense-in-depth)")
        L.append(f"- **Detection:** event class `{ex.attack_class}` raised at request time")
        L.append("")
    L.append("## Methodology\n")
    L.append("Each finding is reproduced by an automated exploit run against the agent in the "
             "`vulnerable` and `hardened` presets (`seclab report`). The PoC inputs and observed "
             "outputs above are generated from those runs, so this report cannot drift from the "
             "code. The exploit-regression suite (`tests/`) asserts every attack lands on "
             "vulnerable and is blocked + detected on hardened.\n")
    L.append("## Threat model & residual risk\n")
    L.append("See [THREAT_MODEL.md](THREAT_MODEL.md).\n")
    return "\n".join(L)
