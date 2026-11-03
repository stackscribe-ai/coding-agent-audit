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
from mcp.types import ToolAnnotations

from . import __version__
from .checks import run_all_ioc_checks
from .configscan import default_config_paths, scan_paths, scan_paths_for_phantom_mcp_packages
from .findings import Finding, worst_severity
from .phantomdeps import check_phantom_dependencies

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


_LOCAL_READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

_NETWORK_READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)


@server.tool(annotations=_LOCAL_READ_ONLY)
def scan_for_known_backdoors() -> str:
    """Scan this machine for known, publicly-documented indicators of
    compromise from AI-coding-assistant supply-chain attacks (SSH backdoor
    keys, C2 processes, persistence via cron/LaunchAgent/scheduled task,
    the trojanized extension.js hash). Read-only; no file is modified."""
    return _render(run_all_ioc_checks())


@server.tool(annotations=_LOCAL_READ_ONLY)
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


@server.tool(annotations=_NETWORK_READ_ONLY)
def scan_phantom_dependencies(project_dir: str) -> str:
    """Check a project's package.json / requirements.txt / pyproject.toml
    dependencies against the npm/PyPI registries and flag any package name
    that doesn't actually exist there. AI coding assistants occasionally
    hallucinate a plausible-but-nonexistent package name; if one ends up in
    a manifest, an attacker can register that exact name with malicious
    code and have it silently installed on the next install
    ("slopsquatting"). Read-only HTTP lookups only; nothing is installed.

    Args:
        project_dir: path to the project directory containing the manifest
            file(s) to check.
    """
    return _render(check_phantom_dependencies(Path(project_dir)))


@server.tool(annotations=_NETWORK_READ_ONLY)
def scan_mcp_phantom_packages(project_dir: Optional[str] = None) -> str:
    """Check the `npx`/`uvx`/`pipx run` commands in this machine's (and
    optionally a project's) MCP server config against the npm/PyPI
    registries, and flag any package name that doesn't actually exist
    there - the "MCPhantom" pattern (Glow Labs, Nov 2026): a coding agent
    fills in a plausible-sounding MCP server name from training data, or
    copies one from a long-archived tutorial whose package was since
    renamed or unpublished. An attacker can register that exact name and
    have it run as the MCP server, with the user's own permissions, the
    next time the config is loaded. Read-only HTTP lookups only; this
    never connects to or executes the MCP server itself.

    Args:
        project_dir: optional path to a project whose .claude/ and
            .mcp.json should also be scanned, in addition to the user's
            home-directory config.
    """
    home = Path.home()
    project = Path(project_dir) if project_dir else None
    paths = default_config_paths(home, project)
    return _render(scan_paths_for_phantom_mcp_packages(paths))


@server.tool(annotations=_LOCAL_READ_ONLY)
def scan_tool_descriptions(tools: list[dict]) -> str:
    """Scan a list of MCP tool definitions (the 'tools/list' response an
    MCP server returns, e.g. [{"name": "search", "description": "..."}])
    for instructions hidden in the description field - 'tool definition
    injection'. A malicious or compromised MCP server can register a tool
    whose description tells the LLM to also call a second,
    attacker-controlled tool, or to hide an action from the user, without
    ever shipping malicious code in a package. Pass another MCP server's
    own tools/list output straight through; this never connects to or
    executes any server itself.

    Args:
        tools: list of tool definitions, each with at least a
            "description" field.
    """
    from .configscan import scan_tool_descriptions as _scan

    return _render(_scan(tools))


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
