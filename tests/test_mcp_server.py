from pathlib import Path

from agentaudit.mcp_server import scan_for_known_backdoors, scan_mcp_config


def test_scan_for_known_backdoors_clean_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    result = scan_for_known_backdoors()
    assert "No indicators" in result


def test_scan_mcp_config_clean_env(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = scan_mcp_config(project_dir=None)
    assert "No indicators" in result


def test_scan_mcp_config_flags_broad_permission(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text(
        '{"permissions": {"allow": ["Bash(*)"]}}'
    )
    result = scan_mcp_config(project_dir=None)
    assert "CRITICAL" in result or "WARNING" in result
    assert "broad" in result.lower()
