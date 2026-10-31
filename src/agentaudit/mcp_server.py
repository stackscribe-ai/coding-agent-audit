"""MCP server wrapper: exposes the same scans as ``agent-audit`` (the CLI)
as MCP tools, so an MCP client (Claude Desktop, Claude Code, etc.) can run
them directly inside a chat without a human running a terminal command.

Run with:
    agent-audit-mcp
    # or, without installing first:
    uvx coding-agent-audit agent-audit-mcp
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from mcp.server.mcpserver import MCPServer

from . import __version__
from .checks import run_all_ioc_checks
from .configscan import default_config_paths, scan_paths
from .findings import Finding, worst_severity

server = MCPServer(
    name="coding-agent-audit",
    version=__version__,
    instructions=(
        "Scans this machine for known AI-coding-assistant supply-chain "
        "backdoor indicators (e.g. the October 2026 trojanized Claude Code "
        "/ Open-VSX / Cursor Marketplace extension) and for risky Claude "
        "Code / MCP configuration patterns (hooks piping curl into a "
        "shell, overly broad auto-approved permissions, unpinned MCP "
        "server packages). Independent, open-source, not affiliated with "
        "Anthropic. Built and run by StackScribe AI, an autonomous AI "
        "project - no human reviews a run before you see its result."
    ),
)


def _render(findings: list[Finding]) -> str:
    if not findings:
        return "No indicators of compromise or risky config patterns found."
    order = {"critical": 0, "warning": 1, "info": 2}
    lines = [f"{len(findings)} finding(s), worst severity: {worst_severity(findings)}", ""]
    for f in sorted(findings, key=lambda x: order[x.severity]):
        lines.append(f"[{f.severity.upper()}] {f.title}")
        lines.append(f"  {f.detail}")
        if f.path:
            lines.append(f"  path: {f.path}")
        for ref in f.references:
            lines.append(f"  ref: {ref}")
        lines.append("")
    return "\n".join(lines)


@server.tool()
def scan_for_known_backdoors() -> str:
    """Scan this machine for known, publicly-documented indicators of
    compromise from AI-coding-assistant supply-chain attacks (SSH backdoor
    keys, C2 processes, persistence via cron/LaunchAgent/scheduled task,
    the trojanized extension.js hash). Read-only; no file is modified."""
    return _render(run_all_ioc_checks())


@server.tool()
def scan_mcp_config(project_dir: Optional[str] = None) -> str:
    """Scan this machine's Claude Code / Claude Desktop / MCP config files
    for risky patterns: hooks that pipe a remote download into a shell,
    overly broad auto-approved permission rules (e.g. 'Bash(*)'), unpinned
    MCP server packages, raw IP literals in hook commands or env vars.

    Args:
        project_dir: optional path to a project whose .claude/ and
            .mcp.json should also be scanned, in addition to the user's
            home-directory config.
    """
    home = Path.home()
    project = Path(project_dir) if project_dir else None
    paths = default_config_paths(home, project)
    return _render(scan_paths(paths))


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
