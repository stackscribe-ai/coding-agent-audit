from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks import run_all_ioc_checks
from .configscan import default_config_paths, scan_paths
from .findings import Finding, worst_severity
from .phantomdeps import check_phantom_dependencies

_SEVERITY_ICON = {"critical": "[CRITICAL]", "warning": "[WARNING]", "info": "[INFO]"}

FOOTER = (
    "\nWant a shareable, client-ready HTML/Markdown report instead of this terminal "
    "output (or a human to review it by hand)? -> "
    "https://stackscribe-config-report.stackscribe-paywall-worker.workers.dev/ "
    "(instant, 12 USDC) or https://stackscribe-ai.github.io/services/ (human audit, from EUR149)"
)


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
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help=(
            "with --project, also check package.json/requirements.txt/"
            "pyproject.toml dependencies against npm/PyPI and flag any "
            "that don't exist (possible AI-hallucinated/slopsquattable "
            "package name). Makes read-only network requests."
        ),
    )
    parser.add_argument("--json", action="store_true", help="output JSON instead of text")
    parser.add_argument(
        "--no-footer", action="store_true", help="suppress the closing promo line"
    )
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

    if args.check_deps and args.project is not None:
        findings += check_phantom_dependencies(args.project)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        _print_human(findings)
        if findings and not args.no_footer:
            print(FOOTER)

    worst = worst_severity(findings)
    if worst == "critical":
        return 2
    if worst == "warning":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
