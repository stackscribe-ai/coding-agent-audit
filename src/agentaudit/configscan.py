"""Heuristic checks for risky configuration in Claude Code / MCP-style
config files (hooks, MCP server definitions, broad permission grants).

These are NOT indicators of an active, confirmed compromise the way
checks.py's IOC checks are - they flag *patterns* that are worth a human
looking at, at "warning"/"info" severity. False positives are expected and
fine; silence on a real risk is not.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from .findings import Finding

# Commands/strings that show up in real exfiltration or persistence attempts.
# Deliberately broad; this is a heuristic triage tool, not a prover.
_RISKY_COMMAND_PATTERNS = [
    (r"authorized_keys", "writes to an SSH authorized_keys file"),
    (r"\bcurl\b.*\|\s*(sh|bash)\b", "pipes a remote download directly into a shell"),
    (r"\bwget\b.*\|\s*(sh|bash)\b", "pipes a remote download directly into a shell"),
    (r"base64\s+-d\s*\|", "decodes base64 and pipes it onward (common obfuscation)"),
    (r"\bnc\b\s+-e\b", "uses netcat in reverse-shell mode (-e)"),
    (r"/dev/tcp/", "opens a raw bash TCP socket (common reverse-shell technique)"),
    (r"\bcrontab\b", "modifies the crontab (possible persistence)"),
    (r"launchctl\s+load", "loads a LaunchAgent/LaunchDaemon (possible persistence)"),
    (r"chmod\s+\+s", "sets a setuid bit (possible privilege-escalation backdoor)"),
]

_IP_LITERAL = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def _iter_hook_commands(hooks_obj) -> Iterable[str]:
    """Walk a Claude Code-style `hooks` object and yield every shell command
    string found, regardless of nesting shape."""
    if isinstance(hooks_obj, str):
        yield hooks_obj
    elif isinstance(hooks_obj, dict):
        for key, value in hooks_obj.items():
            if key == "command" and isinstance(value, str):
                yield value
            else:
                yield from _iter_hook_commands(value)
    elif isinstance(hooks_obj, list):
        for item in hooks_obj:
            yield from _iter_hook_commands(item)


def scan_hooks(config: dict, source_path: str) -> list[Finding]:
    hooks = config.get("hooks")
    if not hooks:
        return []
    findings: list[Finding] = []
    for command in _iter_hook_commands(hooks):
        for pattern, explanation in _RISKY_COMMAND_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                findings.append(
                    Finding(
                        check_id="risky-hook-command",
                        severity="warning",
                        title="Hook command matches a risky pattern",
                        detail=(
                            f"A hook command {explanation}: {command!r}"
                        ),
                        path=source_path,
                    )
                )
        if _IP_LITERAL.search(command):
            findings.append(
                Finding(
                    check_id="hook-raw-ip",
                    severity="info",
                    title="Hook command contains a raw IP literal",
                    detail=(
                        f"A hook command talks directly to a numeric IP "
                        f"address rather than a domain name, which is "
                        f"unusual for legitimate tooling: {command!r}"
                    ),
                    path=source_path,
                )
            )
    return findings


def scan_mcp_servers(config: dict, source_path: str) -> list[Finding]:
    servers = config.get("mcpServers") or config.get("mcp_servers")
    if not isinstance(servers, dict):
        return []
    findings: list[Finding] = []
    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue
        command = server_cfg.get("command", "")
        args = server_cfg.get("args") or []
        full_cmdline = " ".join([command, *[str(a) for a in args]])

        if re.search(r"\b(npx|uvx|pipx run)\b", full_cmdline, re.IGNORECASE) and not re.search(
            r"@\d|==|>=|~=", full_cmdline
        ):
            findings.append(
                Finding(
                    check_id="mcp-unpinned-package",
                    severity="info",
                    title=f"MCP server '{server_name}' runs an unpinned package",
                    detail=(
                        f"Command '{full_cmdline}' installs/runs a package "
                        f"without pinning a version, so a future malicious "
                        f"release would be picked up silently on next run."
                    ),
                    path=source_path,
                )
            )

        env = server_cfg.get("env") or {}
        for env_key, env_val in env.items():
            if isinstance(env_val, str) and _IP_LITERAL.search(env_val):
                findings.append(
                    Finding(
                        check_id="mcp-raw-ip-env",
                        severity="info",
                        title=f"MCP server '{server_name}' env var contains a raw IP",
                        detail=f"Env var '{env_key}' points at a raw IP address.",
                        path=source_path,
                    )
                )
    return findings


def scan_permissions(config: dict, source_path: str) -> list[Finding]:
    permissions = config.get("permissions")
    if not isinstance(permissions, dict):
        return []
    findings: list[Finding] = []
    allow = permissions.get("allow") or []
    for rule in allow:
        if not isinstance(rule, str):
            continue
        if rule.strip() in ("*", "Bash(*)", "Bash") or rule.strip().endswith("(*)"):
            findings.append(
                Finding(
                    check_id="broad-permission-grant",
                    severity="warning",
                    title="Overly broad auto-approved permission rule",
                    detail=(
                        f"Permission rule '{rule}' auto-approves an entire "
                        f"tool/command family without scoping, which "
                        f"removes the confirmation step that would "
                        f"normally catch an unexpected destructive or "
                        f"exfiltrating command."
                    ),
                    path=source_path,
                )
            )
    return findings


def scan_config_dict(config: dict, source_path: str) -> list[Finding]:
    findings: list[Finding] = []
    findings += scan_hooks(config, source_path)
    findings += scan_mcp_servers(config, source_path)
    findings += scan_permissions(config, source_path)
    return findings


def default_config_paths(home: Path, project_dir: Path | None = None) -> list[Path]:
    """Common locations for Claude Code / Claude Desktop / MCP config."""
    paths = [
        home / ".claude" / "settings.json",
        home / ".claude.json",
        home / ".config" / "claude" / "claude_desktop_config.json",
        home
        / "Library"
        / "Application Support"
        / "Claude"
        / "claude_desktop_config.json",
        home
        / "AppData"
        / "Roaming"
        / "Claude"
        / "claude_desktop_config.json",
    ]
    if project_dir is not None:
        paths += [
            project_dir / ".claude" / "settings.json",
            project_dir / ".claude" / "settings.local.json",
            project_dir / ".mcp.json",
        ]
    return paths


def scan_paths(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            config = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(config, dict):
            findings += scan_config_dict(config, str(path))
    return findings
