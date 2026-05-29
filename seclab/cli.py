"""Command-line entry points.

  seclab attack [--hardened]   # run the exploit catalogue, show land/blocked
  seclab detect                # run attacks, show the detection events raised
  seclab report                # regenerate REPORT.md from live exploit runs

All offline on the gullible mock model — no API key.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def _agent(hardened: bool):
    from .agent.agent import Agent
    from .config import AgentConfig, Defenses

    d = Defenses.hardened() if hardened else Defenses.vulnerable()
    return Agent(AgentConfig(defenses=d))


def cmd_attack(args) -> None:
    from .exploits import ALL_EXPLOITS

    mode = "hardened" if args.hardened else "vulnerable"
    print(f"Running {len(ALL_EXPLOITS)} exploits against the {mode} agent:\n")
    for ex in ALL_EXPLOITS:
        r = ex.run(_agent(args.hardened))
        status = "EXPLOITED" if r.succeeded else "blocked  "
        print(f"  [{status}] {ex.id:20s} {ex.title}")


def cmd_detect(args) -> None:
    from .exploits import ALL_EXPLOITS

    print("Detection events raised while attacking the vulnerable agent:\n")
    for ex in ALL_EXPLOITS:
        a = _agent(hardened=False)
        ex.run(a)
        classes = ", ".join(a.events.classes()) or "(none)"
        print(f"  {ex.id:20s} -> {classes}")


def cmd_report(args) -> None:
    from .report import generate_report

    out = Path(args.out)
    out.write_text(generate_report(), encoding="utf-8")
    print(f"wrote {out}")


def main() -> None:
    p = argparse.ArgumentParser(prog="seclab")
    sub = p.add_subparsers(required=True)

    pa = sub.add_parser("attack", help="run the exploit catalogue")
    pa.add_argument("--hardened", action="store_true", help="attack the hardened build")
    pa.set_defaults(fn=cmd_attack)

    pd = sub.add_parser("detect", help="show detection events for each attack")
    pd.set_defaults(fn=cmd_detect)

    pr = sub.add_parser("report", help="regenerate the security report")
    pr.add_argument("--out", default="REPORT.md")
    pr.set_defaults(fn=cmd_report)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
