"""Indicator-of-compromise checks for documented AI-coding-assistant
supply-chain attacks (see iocs.py). Every function takes explicit paths /
inputs (with sensible defaults pointing at the real filesystem) so the whole
module is unit-testable without touching a real home directory.
"""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
from pathlib import Path
from typing import Iterable, Optional

from .findings import Finding
from .iocs import INCIDENTS

_IOC = INCIDENTS["openvsx-claude-code-2026-10"]


def check_ssh_authorized_keys(home: Path) -> list[Finding]:
    """Flag the known 'svc-telemetry' key comment in authorized_keys."""
    path = home / ".ssh" / "authorized_keys"
    if not path.is_file():
        return []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return []
    if _IOC["ssh_key_comment"] in text:
        return [
            Finding(
                check_id="ssh-authorized-keys",
                severity="critical",
                title="Known backdoor SSH key found in authorized_keys",
                detail=(
                    f"'{path}' contains a key with the comment "
                    f"'{_IOC['ssh_key_comment']}', which matches the key "
                    f"planted by the {_IOC['name']}."
                ),
                path=str(path),
                references=_IOC["references"],
            )
        ]
    return []


def check_macos_launch_agent(home: Path) -> list[Finding]:
    """Flag the disguised LaunchAgent plist used for persistence on macOS."""
    path = home / "Library" / "LaunchAgents" / _IOC["macos_launch_agent"]
    if path.exists():
        return [
            Finding(
                check_id="macos-launch-agent",
                severity="critical",
                title="Known backdoor persistence LaunchAgent found",
                detail=(
                    f"'{path}' exists and matches the disguised system "
                    f"daemon installed by the {_IOC['name']}."
                ),
                path=str(path),
                references=_IOC["references"],
            )
        ]
    return []


def check_marker_files(home: Path) -> list[Finding]:
    """Flag known marker files dropped under ~/.config."""
    findings: list[Finding] = []
    config_dir = home / ".config"
    for name in _IOC["marker_filenames"]:
        path = config_dir / name
        if path.exists():
            findings.append(
                Finding(
                    check_id="marker-file",
                    severity="critical",
                    title="Known backdoor marker file found",
                    detail=(
                        f"'{path}' exists and matches a marker file "
                        f"created by the {_IOC['name']}."
                    ),
                    path=str(path),
                    references=_IOC["references"],
                )
            )
    return findings


def check_tmp_tunnel_keys(tmp_dir: Path) -> list[Finding]:
    """Flag leftover temporary SSH tunnel key files."""
    if not tmp_dir.is_dir():
        return []
    pattern = _IOC["tmp_tunnel_glob"]
    matches = sorted(tmp_dir.glob(pattern))
    if matches:
        return [
            Finding(
                check_id="tmp-tunnel-key",
                severity="critical",
                title="Known backdoor temporary tunnel key found",
                detail=(
                    f"Found {len(matches)} file(s) matching '{pattern}' in "
                    f"'{tmp_dir}', matching the temporary SSH tunnel keys "
                    f"used by the {_IOC['name']}."
                ),
                path=str(matches[0]),
                references=_IOC["references"],
            )
        ]
    return []


def _sha256_of(path: Path) -> Optional[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()


def check_extension_hashes(scan_dirs: Iterable[Path]) -> list[Finding]:
    """Walk the given directories for an extension.js matching the known
    trojanized hash."""
    findings: list[Finding] = []
    bad_hash = _IOC["extension_sha256"]
    for base in scan_dirs:
        if not base.is_dir():
            continue
        for ext_js in base.rglob("extension.js"):
            digest = _sha256_of(ext_js)
            if digest == bad_hash:
                findings.append(
                    Finding(
                        check_id="extension-hash",
                        severity="critical",
                        title="Trojanized extension.js found",
                        detail=(
                            f"'{ext_js}' hashes to {digest}, which matches "
                            f"the known-malicious build from the "
                            f"{_IOC['name']}."
                        ),
                        path=str(ext_js),
                        references=_IOC["references"],
                    )
                )
    return findings


def default_extension_scan_dirs(home: Path) -> list[Path]:
    """Common install locations for VS Code / forks' extensions."""
    return [
        home / ".vscode" / "extensions",
        home / ".vscode-server" / "extensions",
        home / ".cursor" / "extensions",
        home / ".windsurf" / "extensions",
        home / ".vscode-oss" / "extensions",
    ]


def check_c2_network_indicators(process_lines: Iterable[str]) -> list[Finding]:
    """Flag running processes (e.g. `ps aux` output, injected for testing)
    that reference the known C2 host."""
    findings: list[Finding] = []
    for host in _IOC["c2_hosts"]:
        for line in process_lines:
            if host in line:
                findings.append(
                    Finding(
                        check_id="c2-network",
                        severity="critical",
                        title="Process referencing known C2 host found",
                        detail=(
                            f"A running process references {host}, the C2 "
                            f"host used by the {_IOC['name']}: {line.strip()!r}"
                        ),
                        references=_IOC["references"],
                    )
                )
    return findings


def check_linux_cron_persistence(crontab_text: str) -> list[Finding]:
    """Flag a crontab entry referencing the known persistence marker."""
    marker = _IOC["linux_cron_marker"]
    if marker in crontab_text and "@reboot" in crontab_text:
        return [
            Finding(
                check_id="cron-persistence",
                severity="critical",
                title="Known backdoor cron persistence entry found",
                detail=(
                    f"The user crontab contains an '@reboot' entry "
                    f"referencing '{marker}', matching the persistence "
                    f"mechanism used by the {_IOC['name']}."
                ),
                references=_IOC["references"],
            )
        ]
    return []


def live_crontab_text() -> str:
    """Best-effort read of the current user's crontab; empty string if
    unavailable (no cron, not installed, permission denied, etc.)."""
    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout


def live_process_lines() -> list[str]:
    """Best-effort snapshot of running processes; empty list if `ps` is
    unavailable (e.g. on Windows without WSL)."""
    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    return result.stdout.splitlines()


def run_all_ioc_checks(home: Optional[Path] = None) -> list[Finding]:
    """Run every IOC check against the real local machine."""
    home = home or Path.home()
    tmp_dir = Path(os.environ.get("TMPDIR", "/tmp"))

    findings: list[Finding] = []
    findings += check_ssh_authorized_keys(home)
    findings += check_marker_files(home)
    findings += check_tmp_tunnel_keys(tmp_dir)
    findings += check_extension_hashes(default_extension_scan_dirs(home))
    findings += check_c2_network_indicators(live_process_lines())
    findings += check_linux_cron_persistence(live_crontab_text())
    if platform.system() == "Darwin":
        findings += check_macos_launch_agent(home)
    return findings
