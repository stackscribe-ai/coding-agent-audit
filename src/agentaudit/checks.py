"""Indicator-of-compromise checks for documented AI-coding-assistant
supply-chain attacks (see iocs.py). Every function takes explicit paths /
inputs (with sensible defaults pointing at the real filesystem) so the whole
module is unit-testable without touching a real home directory.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Iterable, Optional

from .findings import Finding
from .iocs import INCIDENTS

_IOC = INCIDENTS["openvsx-claude-code-2026-10"]
_EMBRACE = INCIDENTS["embrace-embedded-browser-2026-10"]


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


def check_windows_scheduled_task(schtasks_output: str) -> list[Finding]:
    """Flag a `schtasks /query` output that reports the known SYSTEM
    persistence task."""
    task_name = _IOC["windows_task_name"]
    if task_name in schtasks_output and "ERROR" not in schtasks_output.upper():
        return [
            Finding(
                check_id="windows-scheduled-task",
                severity="critical",
                title="Known backdoor scheduled task found",
                detail=(
                    f"A scheduled task named '{task_name}' exists, matching "
                    f"the SYSTEM-level persistence task created by the "
                    f"{_IOC['name']}."
                ),
                references=_IOC["references"],
            )
        ]
    return []


def check_windows_startup_folder(appdata: Path) -> list[Finding]:
    """Flag the Startup-folder fallback script used on Windows when the
    SYSTEM scheduled task cannot be created (non-admin user)."""
    path = appdata / _IOC["windows_startup_relpath"]
    if path.exists():
        return [
            Finding(
                check_id="windows-startup-folder",
                severity="critical",
                title="Known backdoor Startup-folder script found",
                detail=(
                    f"'{path}' exists and matches the Startup-folder "
                    f"fallback script dropped by the {_IOC['name']} when it "
                    f"can't create a SYSTEM scheduled task."
                ),
                path=str(path),
                references=_IOC["references"],
            )
        ]
    return []


def live_windows_scheduled_task_text() -> str:
    """Best-effort `schtasks /query` for the known task name; empty string
    if unavailable (not Windows, task not found, etc.)."""
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/tn", _IOC["windows_task_name"], "/fo", "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout


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


_EXTENSION_VERSION_RE = re.compile(r"^(.+)-(\d+(?:\.\d+)*)$")


def _parse_extension_version(dirname: str) -> Optional[tuple[int, ...]]:
    match = _EXTENSION_VERSION_RE.match(dirname)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(2).split("."))
    except ValueError:
        return None


def check_embrace_copilot_version(scan_dirs: Iterable[Path]) -> list[Finding]:
    """Flag a GitHub Copilot VS Code extension older than the version that
    fixed the EMBRACE address-bar-spoofing flaw in its embedded browser."""
    patched = _EMBRACE["copilot_patched_version"]
    findings: list[Finding] = []
    for base in scan_dirs:
        if not base.is_dir():
            continue
        for entry in sorted(base.iterdir()):
            if not entry.is_dir():
                continue
            name = entry.name.lower()
            # The base "GitHub Copilot" extension only; copilot-chat ships
            # its own, differently-numbered releases not covered by the fix
            # version above.
            if not name.startswith("github.copilot-") or name.startswith(
                "github.copilot-chat-"
            ):
                continue
            version = _parse_extension_version(entry.name)
            if version is None or version >= patched:
                continue
            findings.append(
                Finding(
                    check_id="embrace-copilot-version",
                    severity="warning",
                    title=(
                        "GitHub Copilot extension predates the EMBRACE "
                        "address-bar-spoofing fix"
                    ),
                    detail=(
                        f"'{entry}' is version {'.'.join(map(str, version))}, "
                        f"older than {'.'.join(map(str, patched))} (released "
                        f"2026-10-13), which fixed an address-bar-spoofing "
                        f"flaw in Copilot's embedded browser (part of the "
                        f"EMBRACE disclosure). Update the extension."
                    ),
                    path=str(entry),
                    references=_EMBRACE["references"],
                )
            )
    return findings


def check_embrace_unpatched_tools(home: Path) -> list[Finding]:
    """Flag the presence of AI coding tools named in the EMBRACE embedded-
    browser disclosure, calling out the ones reported unpatched at
    disclosure time."""
    detected: list[str] = []
    if (home / ".vscode").is_dir() or (home / ".vscode-server").is_dir():
        detected.append("VS Code")
    if (home / ".codex").is_dir():
        detected.append("OpenAI Codex")
    claude_desktop_dirs = [
        home / "Library" / "Application Support" / "Claude",
        home / ".config" / "Claude",
        home / "AppData" / "Roaming" / "Claude",
    ]
    if any(p.is_dir() for p in claude_desktop_dirs):
        detected.append("Claude Desktop")
    if not detected:
        return []

    unpatched = [d for d in detected if d in _EMBRACE["unpatched_products"]]
    unconfirmed = [d for d in detected if d not in _EMBRACE["unpatched_products"]]

    parts = []
    if unpatched:
        parts.append(
            f"{', '.join(unpatched)} detected on this machine and was still "
            f"unpatched as of the EMBRACE disclosure referenced below."
        )
    if unconfirmed:
        parts.append(
            f"{', '.join(unconfirmed)} also detected; the researchers did "
            f"not confirm a patch status for it at disclosure time."
        )
    parts.append(
        "Until a fix ships: don't open links or HTML the assistant "
        "generates from untrusted/external content inside the tool's "
        "built-in browser or preview pane - a malicious page there can "
        "read SSH keys, .env files and other local secrets, per the "
        "EMBRACE write-up."
    )
    return [
        Finding(
            check_id="embrace-unpatched-tool-present",
            severity="warning" if unpatched else "info",
            title="AI coding tool named in the EMBRACE embedded-browser disclosure detected",
            detail=" ".join(parts),
            references=_EMBRACE["references"],
        )
    ]


def run_all_ioc_checks(home: Optional[Path] = None) -> list[Finding]:
    """Run every IOC check against the real local machine."""
    home = home or Path.home()
    tmp_dir = Path(os.environ.get("TMPDIR", "/tmp"))

    findings: list[Finding] = []
    findings += check_ssh_authorized_keys(home)
    findings += check_marker_files(home)
    findings += check_tmp_tunnel_keys(tmp_dir)
    findings += check_extension_hashes(default_extension_scan_dirs(home))
    findings += check_embrace_copilot_version(default_extension_scan_dirs(home))
    findings += check_embrace_unpatched_tools(home)
    findings += check_c2_network_indicators(live_process_lines())
    findings += check_linux_cron_persistence(live_crontab_text())
    if platform.system() == "Darwin":
        findings += check_macos_launch_agent(home)
    if platform.system() == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        findings += check_windows_startup_folder(appdata)
        findings += check_windows_scheduled_task(live_windows_scheduled_task_text())
    return findings
