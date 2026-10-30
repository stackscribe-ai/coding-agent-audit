from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks import run_all_ioc_checks
from .configscan import default_config_paths, scan_paths
from .findings import Finding, worst_severity

_SEVERITY_ICON = {"critical": "[CRITICAL]", "warning": "[WARNING]", "info": "[INFO]"}


def _print_human(findings: list[Finding]) -> None:
    if not findings:
        print("coding-agent-audit: no indicators of compromise or risky config found.")
        return
    order = {"critical": 0, "warning": 1, "info": 2}
    for f in sorted(findings, key=lambda x: order[x.severity]):
        print(f"{_SEVERITY_ICON[f.severity]} {f.title}")
        print(f"    {f.detail}")
        if f.path:
            print(f"    path: {f.path}")
        for ref in f.references:
            print(f"    ref: {ref}")
        print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-audit",
        description=(
            "Scan this machine for known AI-coding-assistant supply-chain "
            "backdoor indicators and risky Claude Code / MCP configuration "
            "patterns."
        ),
    )
    parser.add_argument(
        "--project",
        type=Path,
        default=None,
        help="also scan this project directory's .claude/.mcp.json config",
    )
    parser.add_argument(
        "--skip-ioc",
        action="store_true",
        help="skip the known-incident IOC scan (config-only)",
    )
    parser.add_argument(
        "--skip-config",
        action="store_true",
        help="skip the risky-config heuristic scan (IOC-only)",
    )
    parser.add_argument("--json", action="store_true", help="output JSON instead of text")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    if not args.skip_ioc:
        findings += run_all_ioc_checks()
    if not args.skip_config:
        home = Path.home()
        paths = default_config_paths(home, args.project)
        findings += scan_paths(paths)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        _print_human(findings)

    worst = worst_severity(findings)
    if worst == "critical":
        return 2
    if worst == "warning":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
