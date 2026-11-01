#!/usr/bin/env python3
"""Self-contained, zero-dependency security audit for Claude Code / MCP-style
coding-agent setups.

Combines two kinds of checks:
  1. IOC checks for the publicly documented Oct 2026 Open-VSX "svc-telemetry"
     trojanized Claude Code extension (SSH backdoor, persistence, C2 beacon).
  2. Heuristic config checks for risky patterns in Claude Code / MCP config
     files: dangerous hook commands, unpinned MCP server packages, raw IP
     literals, overly broad auto-approved permissions.

This is a trimmed, single-file port of the open-source `coding-agent-audit`
PyPI package (https://pypi.org/project/coding-agent-audit/, MIT licensed,
by StackScribe AI) so it can run anywhere with just a stdlib Python 3
interpreter - no `pip install` required. For the full CLI, test suite and
an MCP-server mode, see the PyPI package or
https://github.com/stackscribe-ai/coding-agent-audit.

Usage:
    python3 audit.py                       # scan common local config/IOC locations
    python3 audit.py path/to/.mcp.json      # scan one or more specific config files
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}

_IOC = {
    "name": "Trojanized Claude Code extension on Open-VSX / Cursor Marketplace (Oct 2026)",
    "references": [
        "https://doublepulsar.com/anthropic-hacked-to-deliver-remote-access-trojan-to-claude-developer-laptops-worldwide-1148a92baae2",
        "https://dev.to/slabb/a-trojanized-claude-code-extension-plants-an-ssh-backdoor-the-7-point-audit-for-your-machine-23cj",
    ],
    "ssh_key_comment": "svc-telemetry",
    "extension_sha256": "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15",
    "c2_hosts": ["134.209.82.225"],
    "macos_launch_agent": "com.apple.sysmond.plist",
    "marker_filenames": [".smt", ".smtk", "smt.cmd", "smtk"],
    "tmp_tunnel_glob": ".stk_*",
    "linux_cron_marker": "SysMon",
    "windows_task_name": "SysMon",
    "windows_startup_relpath": "Microsoft/Windows/Start Menu/Programs/Startup/sysmon.cmd",
}

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


class Finding:
    def __init__(self, check_id, severity, title, detail, path=None, references=None):
        self.check_id = check_id
        self.severity = severity
        self.title = title
        self.detail = detail
        self.path = path
        self.references = references or []


# -- IOC checks (known-compromise indicators) -------------------------------

def check_ssh_authorized_keys(home: Path) -> list:
    path = home / ".ssh" / "authorized_keys"
    if not path.is_file():
        return []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return []
    if _IOC["ssh_key_comment"] in text:
        return [Finding("ssh-authorized-keys", "critical",
                         "Known backdoor SSH key found in authorized_keys",
                         f"'{path}' contains a key with the comment '{_IOC['ssh_key_comment']}', "
                         f"matching the key planted by the {_IOC['name']}.",
                         str(path), _IOC["references"])]
    return []


def check_marker_files(home: Path) -> list:
    findings = []
    config_dir = home / ".config"
    for name in _IOC["marker_filenames"]:
        path = config_dir / name
        if path.exists():
            findings.append(Finding("marker-file", "critical",
                                     "Known backdoor marker file found",
                                     f"'{path}' matches a marker file created by the {_IOC['name']}.",
                                     str(path), _IOC["references"]))
    return findings


def check_tmp_tunnel_keys(tmp_dir: Path) -> list:
    if not tmp_dir.is_dir():
        return []
    matches = sorted(tmp_dir.glob(_IOC["tmp_tunnel_glob"]))
    if matches:
        return [Finding("tmp-tunnel-key", "critical",
                         "Known backdoor temporary tunnel key found",
                         f"Found {len(matches)} file(s) matching '{_IOC['tmp_tunnel_glob']}' in '{tmp_dir}'.",
                         str(matches[0]), _IOC["references"])]
    return []


def _sha256_of(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def check_extension_hashes(scan_dirs: Iterable[Path]) -> list:
    findings = []
    for base in scan_dirs:
        if not base.is_dir():
            continue
        for ext_js in base.rglob("extension.js"):
            if _sha256_of(ext_js) == _IOC["extension_sha256"]:
                findings.append(Finding("extension-hash", "critical",
                                         "Trojanized extension.js found",
                                         f"'{ext_js}' matches the known-malicious build from the {_IOC['name']}.",
                                         str(ext_js), _IOC["references"]))
    return findings


def check_c2_network_indicators(process_lines: Iterable[str]) -> list:
    findings = []
    for host in _IOC["c2_hosts"]:
        for line in process_lines:
            if host in line:
                findings.append(Finding("c2-network", "critical",
                                         "Process referencing known C2 host found",
                                         f"A running process references {host}: {line.strip()!r}",
                                         None, _IOC["references"]))
    return findings


def check_linux_cron_persistence(crontab_text: str) -> list:
    if _IOC["linux_cron_marker"] in crontab_text and "@reboot" in crontab_text:
        return [Finding("cron-persistence", "critical",
                         "Known backdoor cron persistence entry found",
                         f"The crontab contains an '@reboot' entry referencing '{_IOC['linux_cron_marker']}'.",
                         None, _IOC["references"])]
    return []


def _live_process_lines() -> list:
    try:
        r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return []
    return r.stdout.splitlines() if r.returncode == 0 else []


def _live_crontab_text() -> str:
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout if r.returncode == 0 else ""


def run_all_ioc_checks(home: Optional[Path] = None) -> list:
    home = home or Path.home()
    tmp_dir = Path(os.environ.get("TMPDIR", "/tmp"))
    findings = []
    findings += check_ssh_authorized_keys(home)
    findings += check_marker_files(home)
    findings += check_tmp_tunnel_keys(tmp_dir)
    findings += check_extension_hashes([
        home / ".vscode" / "extensions", home / ".vscode-server" / "extensions",
        home / ".cursor" / "extensions", home / ".windsurf" / "extensions",
        home / ".vscode-oss" / "extensions",
    ])
    findings += check_c2_network_indicators(_live_process_lines())
    findings += check_linux_cron_persistence(_live_crontab_text())
    if platform.system() == "Darwin":
        path = home / "Library" / "LaunchAgents" / _IOC["macos_launch_agent"]
        if path.exists():
            findings.append(Finding("macos-launch-agent", "critical",
                                     "Known backdoor persistence LaunchAgent found",
                                     f"'{path}' matches the disguised LaunchAgent from the {_IOC['name']}.",
                                     str(path), _IOC["references"]))
    return findings


# -- config heuristic checks -------------------------------------------------

def _iter_hook_commands(hooks_obj):
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


def scan_hooks(config: dict, source_path: str) -> list:
    hooks = config.get("hooks")
    if not hooks:
        return []
    findings = []
    for command in _iter_hook_commands(hooks):
        for pattern, explanation in _RISKY_COMMAND_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                findings.append(Finding("risky-hook-command", "warning",
                                         "Hook command matches a risky pattern",
                                         f"A hook command {explanation}: {command!r}", source_path))
        if _IP_LITERAL.search(command):
            findings.append(Finding("hook-raw-ip", "info",
                                     "Hook command contains a raw IP literal",
                                     f"Hook command talks to a raw IP rather than a domain: {command!r}", source_path))
    return findings


def scan_mcp_servers(config: dict, source_path: str) -> list:
    servers = config.get("mcpServers") or config.get("mcp_servers")
    if not isinstance(servers, dict):
        return []
    findings = []
    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue
        command = server_cfg.get("command", "")
        args = server_cfg.get("args") or []
        full_cmdline = " ".join([command, *[str(a) for a in args]])
        if re.search(r"\b(npx|uvx|pipx run)\b", full_cmdline, re.IGNORECASE) and not re.search(r"@\d|==|>=|~=", full_cmdline):
            findings.append(Finding("mcp-unpinned-package", "info",
                                     f"MCP server '{server_name}' runs an unpinned package",
                                     f"Command '{full_cmdline}' has no version pin, so a future malicious "
                                     f"release would be picked up silently on next run.", source_path))
        env = server_cfg.get("env") or {}
        for env_key, env_val in env.items():
            if isinstance(env_val, str) and _IP_LITERAL.search(env_val):
                findings.append(Finding("mcp-raw-ip-env", "info",
                                         f"MCP server '{server_name}' env var contains a raw IP",
                                         f"Env var '{env_key}' points at a raw IP address.", source_path))
    return findings


def scan_permissions(config: dict, source_path: str) -> list:
    permissions = config.get("permissions")
    if not isinstance(permissions, dict):
        return []
    findings = []
    for rule in permissions.get("allow") or []:
        if not isinstance(rule, str):
            continue
        if rule.strip() in ("*", "Bash(*)", "Bash") or rule.strip().endswith("(*)"):
            findings.append(Finding("broad-permission-grant", "warning",
                                     "Overly broad auto-approved permission rule",
                                     f"Permission rule '{rule}' auto-approves an entire tool/command family "
                                     f"without scoping, removing the confirmation step that would normally "
                                     f"catch an unexpected destructive or exfiltrating command.", source_path))
    return findings


def scan_config_file(path: Path) -> list:
    try:
        config = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(config, dict):
        return []
    findings = []
    findings += scan_hooks(config, str(path))
    findings += scan_mcp_servers(config, str(path))
    findings += scan_permissions(config, str(path))
    return findings


def default_config_paths(home: Path) -> list:
    paths = [
        home / ".claude" / "settings.json",
        home / ".claude.json",
        home / ".config" / "claude" / "claude_desktop_config.json",
        Path.cwd() / ".claude" / "settings.json",
        Path.cwd() / ".claude" / "settings.local.json",
        Path.cwd() / ".mcp.json",
    ]
    return paths


def main(argv: list) -> int:
    home = Path.home()
    findings = run_all_ioc_checks(home)

    explicit_paths = [Path(p) for p in argv]
    config_paths = explicit_paths if explicit_paths else default_config_paths(home)
    for path in config_paths:
        if path.is_file():
            findings += scan_config_file(path)

    if not findings:
        print("No issues found by coding-agent-security-audit.")
        return 0

    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    worst = findings[0].severity
    print(f"coding-agent-security-audit: {len(findings)} finding(s), worst severity: {worst}\n")
    for f in findings:
        print(f"[{f.severity.upper()}] {f.title}")
        print(f"  {f.detail}")
        if f.path:
            print(f"  path: {f.path}")
        for ref in f.references:
            print(f"  ref: {ref}")
        print()
    return 2 if worst == "critical" else (1 if worst == "warning" else 0)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
