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

from . import phantomdeps
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

# Phrases that show up in "tool definition injection": an MCP server's own
# `description` field (shown to the LLM at tools/list time, not to the user)
# carries an instruction rather than documentation, steering the agent into
# calling a second, attacker-controlled tool or hiding/forwarding data.
# Heuristic and easy to evade with synonyms/obfuscation - a first-pass filter,
# not a guarantee the server is safe.
_TOOL_DESCRIPTION_INJECTION_PATTERNS = [
    (r"after (every|each|all)\s+(tool\s*call|file\s*operation|request|response)",
     "instructs the agent to take a follow-up action after every tool call"),
    (r"\b(also|additionally)\s+(call|invoke|run|execute)\b", "tells the agent to also call another tool"),
    (r"ignore (previous|prior|all)\s+instructions", "attempts a prompt-injection override phrase"),
    (r"\b(system|assistant|user)\s*:", "embeds a fake conversation-role label"),
    (r"do not\s+(tell|inform|mention|disclose|reveal)\b", "tells the agent to hide the action from the user"),
    (r"\bsecretly\b", "uses the word 'secretly' to describe the tool's behaviour"),
    (r"send\s+(this|the|all)\s+(data|result|output|context|file)s?\s+to\b",
     "instructs the agent to forward data to a destination"),
    (r"before\s+(returning|responding|completing)\b.*\b(call|invoke|send)\b",
     "instructs an extra action before the agent's normal response"),
    (r"always\s+(include|append|attach)\b", "tells the agent to always attach extra data to its calls"),
]
_COMPILED_TOOL_DESCRIPTION_PATTERNS = [
    (re.compile(p, re.IGNORECASE), label) for p, label in _TOOL_DESCRIPTION_INJECTION_PATTERNS
]


def scan_tool_descriptions(tools: Iterable[dict], source_path: str = "<mcp tools/list>") -> list[Finding]:
    """Scan MCP tool definitions (the ``tools/list`` response an MCP server
    hands to the client, i.e. a list of ``{"name": ..., "description": ...}``
    dicts) for instructions hidden in the ``description`` field.

    Unlike the rest of this module, this does not read local config: callers
    must supply the already-fetched tool list (e.g. from a Claude Desktop/
    Code debug export, or from calling the server's own ``tools/list`` and
    passing the result straight through). This tool never connects to or
    executes an MCP server itself - running a possibly-malicious server's
    command just to audit it would defeat the point.
    """
    findings: list[Finding] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name", "<unnamed>")
        description = tool.get("description") or ""
        if not isinstance(description, str):
            continue
        for pattern, explanation in _COMPILED_TOOL_DESCRIPTION_PATTERNS:
            match = pattern.search(description)
            if match:
                findings.append(
                    Finding(
                        check_id="mcp-tool-description-injection",
                        severity="warning",
                        title=f"Tool '{name}' description {explanation}",
                        detail=(
                            f"The description field of tool '{name}' matches "
                            f"pattern {pattern.pattern!r} at position "
                            f"{match.start()}. MCP clients show tool "
                            f"descriptions to the LLM as authoritative "
                            f"guidance, so a server can steer the agent into "
                            f"calling an attacker-controlled tool or hiding "
                            f"an action from the user without ever "
                            f"compromising a package. Matched text: "
                            f"{description[max(0, match.start()-20):match.end()+20]!r}"
                        ),
                        path=source_path,
                    )
                )
    return findings


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


# Packages with a known, disclosed RCE/command-injection CVE in an old
# version range that still shows up pinned in copy-pasted configs/tutorials
# written before the fix shipped. `fixed_version` is the first version where
# the chain is fully closed; anything strictly older is still exploitable.
_KNOWN_VULNERABLE_PACKAGES = [
    (
        "mcp-remote",
        (0, 1, 16),
        ("CVE-2025-6514",),
        "OS command injection (CVSS 9.6): a malicious/compromised remote MCP "
        "server can return an `authorization_endpoint` URL during the OAuth "
        "handshake that mcp-remote passes unsanitized to the OS, achieving "
        "full remote code execution with no further user interaction beyond "
        "opening the client. Affects v0.0.5-v0.1.15.",
    ),
    (
        "mcp-server-git",
        (2025, 12, 18),
        ("CVE-2025-68143", "CVE-2025-68144", "CVE-2025-68145"),
        "Chained path-validation bypass, unrestricted git_init, and argument "
        "injection in Anthropic's reference git MCP server, usable via "
        "indirect prompt injection (e.g. a planted README) to reach RCE "
        "together with a filesystem MCP server. Fully fixed in v2025.12.18.",
    ),
]


def _parse_leading_version(text: str) -> tuple[int, ...] | None:
    match = re.match(r"^(\d+(?:\.\d+)*)", text)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _version_lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    n = max(len(a), len(b))
    a_padded = a + (0,) * (n - len(a))
    b_padded = b + (0,) * (n - len(b))
    return a_padded < b_padded


def scan_known_cve_packages(config: dict, source_path: str) -> list[Finding]:
    """Flag MCP server commands pinned to a package version with a
    disclosed, fixed RCE/command-injection CVE (see
    ``_KNOWN_VULNERABLE_PACKAGES``). Unpinned installs are not flagged here -
    they pick up the current (patched) release and are already covered by
    the generic 'unpinned package' info finding in `scan_mcp_servers`.
    """
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

        for pkg_name, fixed_version, cve_ids, description in _KNOWN_VULNERABLE_PACKAGES:
            pin_match = re.search(
                rf"\b{re.escape(pkg_name)}(?:@|==)([0-9][0-9.]*)", full_cmdline
            )
            if not pin_match:
                continue
            pinned_version = _parse_leading_version(pin_match.group(1))
            if pinned_version is None or not _version_lt(pinned_version, fixed_version):
                continue
            findings.append(
                Finding(
                    check_id="mcp-known-cve-package",
                    severity="critical",
                    title=(
                        f"MCP server '{server_name}' pins {pkg_name}@"
                        f"{pin_match.group(1)}, vulnerable to {', '.join(cve_ids)}"
                    ),
                    detail=(
                        f"{description} The config explicitly pins a version "
                        f"older than the fixed {'.'.join(map(str, fixed_version))}, "
                        f"so upgrading `{pkg_name}` globally will not help "
                        f"until this pin is also updated."
                    ),
                    path=source_path,
                    references=list(cve_ids),
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


_MCP_RUNNER_RE = re.compile(r"\b(npx|uvx|pipx\s+run)\b", re.IGNORECASE)


def _extract_mcp_package_spec(full_cmdline: str) -> tuple[str, str] | None:
    """Return ``(ecosystem, package_name)`` for the package a `npx`/`uvx`/
    `pipx run` MCP server command would fetch, or ``None`` if no such
    runner (or no package argument after it) is found."""
    match = _MCP_RUNNER_RE.search(full_cmdline)
    if not match:
        return None
    ecosystem = "npm" if match.group(1).lower() == "npx" else "pypi"
    for token in full_cmdline[match.end():].split():
        if token.startswith("-"):
            continue
        if token.startswith("@"):
            # scoped npm package, optionally pinned: @scope/name[@version]
            scoped, _, _version = token[1:].partition("@")
            return ecosystem, f"@{scoped}"
        name, _, _version = token.partition("@")
        name = name.split("==", 1)[0]
        return ecosystem, name
    return None


def scan_mcp_phantom_packages(config: dict, source_path: str) -> list[Finding]:
    """Flag MCP servers launched via `npx`/`uvx`/`pipx run` that point at a
    package name which doesn't exist on the registry - the "MCPhantom"
    pattern (Glow Labs research, Nov 2026): coding agents fill in a
    plausible-sounding MCP server name from training data, or copy one
    from a long-archived tutorial/repo whose package was since renamed or
    unpublished. Either way, nothing stops an attacker from registering
    that exact name and having it run with the user's own permissions on
    the very next launch. Makes read-only registry lookups; network
    errors are treated as "unknown", never as "phantom" (see phantomdeps).
    """
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
        spec = _extract_mcp_package_spec(full_cmdline)
        if spec is None:
            continue
        ecosystem, name = spec
        if ecosystem == "npm":
            if not phantomdeps._is_plausible_npm_name(name):
                continue
            exists = phantomdeps.check_npm_package_exists(name)
        else:
            exists = phantomdeps.check_pypi_package_exists(name)
        if exists is not False:
            continue
        findings.append(
            Finding(
                check_id="mcp-phantom-package",
                severity="critical",
                title=f"MCP server '{server_name}' launches a package that doesn't exist ('{name}')",
                detail=(
                    f"Command '{full_cmdline}' fetches '{name}' from "
                    f"{'npm' if ecosystem == 'npm' else 'PyPI'} on every launch, but no "
                    f"package by that name currently exists there (the "
                    f"'MCPhantom' pattern: a hallucinated or long-deprecated "
                    f"MCP server name). Anyone can register it and have "
                    f"their code run as this MCP server, with no update or "
                    f"confirmation step in between."
                ),
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


# Tools that pull in content the agent did not ask for and cannot fully
# trust (web pages, search results, scraped/rendered pages).
_FETCH_CAPABLE_TOOLS = (
    "webfetch", "websearch", "fetch", "browser", "puppeteer", "playwright",
    "crawl", "scrape",
)
# Tools capable of taking an irreversible or exfiltrating action once the
# agent decides (correctly or not, after reading untrusted content) to call
# them: running shell commands, writing files, or talking to the network.
_ACTION_CAPABLE_TOOLS = (
    "bash", "write", "edit", "shell", "exec", "curl", "http",
)


def _allow_rule_tool_name(rule: str) -> str:
    return rule.split("(", 1)[0].strip().lower()


def scan_lethal_trifecta(config: dict, source_path: str) -> list[Finding]:
    """Flag configs that auto-approve both an untrusted-content-fetching
    tool and an action-capable tool in the same `permissions.allow` list.

    This is the "lethal trifecta" pattern (private/sensitive access +
    exposure to untrusted content + an exfiltration path) that turns a
    prompt-injection payload hidden in a fetched page, search result or
    MCP tool response into actual data loss or remote code execution,
    without ever showing the user a confirmation prompt.
    """
    permissions = config.get("permissions")
    if not isinstance(permissions, dict):
        return []
    allow = permissions.get("allow") or []
    tool_names = {_allow_rule_tool_name(r) for r in allow if isinstance(r, str)}
    tool_names |= {
        name
        for server_name in (config.get("mcpServers") or config.get("mcp_servers") or {})
        for name in (str(server_name).lower(),)
    }

    fetch_hits = [t for t in tool_names if any(k in t for k in _FETCH_CAPABLE_TOOLS)]
    action_hits = [t for t in tool_names if any(k in t for k in _ACTION_CAPABLE_TOOLS)]
    if not fetch_hits or not action_hits:
        return []

    return [
        Finding(
            check_id="lethal-trifecta-permissions",
            severity="warning",
            title="Auto-approved tools combine untrusted-content fetch with an action path",
            detail=(
                f"Permissions auto-approve both a content-fetching tool "
                f"({', '.join(sorted(fetch_hits))}) and an action-capable "
                f"tool ({', '.join(sorted(action_hits))}) with no "
                f"confirmation step in between. A prompt-injection payload "
                f"hidden in a fetched page, search result or tool response "
                f"can chain these two to exfiltrate data or run commands "
                f"without the user ever seeing a prompt."
            ),
            path=source_path,
        )
    ]


def scan_config_dict(config: dict, source_path: str) -> list[Finding]:
    findings: list[Finding] = []
    findings += scan_hooks(config, source_path)
    findings += scan_mcp_servers(config, source_path)
    findings += scan_known_cve_packages(config, source_path)
    findings += scan_permissions(config, source_path)
    findings += scan_lethal_trifecta(config, source_path)
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
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
    ]
    if project_dir is not None:
        paths += [
            project_dir / ".claude" / "settings.json",
            project_dir / ".claude" / "settings.local.json",
            project_dir / ".mcp.json",
            project_dir / ".cursor" / "mcp.json",
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


def scan_paths_for_phantom_mcp_packages(paths: Iterable[Path]) -> list[Finding]:
    """Like `scan_paths`, but only runs `scan_mcp_phantom_packages` (the
    network-dependent check), for callers that opt in with `--check-deps`.
    """
    findings: list[Finding] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            config = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(config, dict):
            findings += scan_mcp_phantom_packages(config, str(path))
    return findings
