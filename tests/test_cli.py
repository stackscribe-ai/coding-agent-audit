import json
from pathlib import Path

from agentaudit.cli import build_parser, main


def test_build_parser_defaults():
    args = build_parser().parse_args([])
    assert args.project is None
    assert args.skip_ioc is False
    assert args.skip_config is False


def test_main_json_output_clean_env(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    code = main(["--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert code == 0


def test_main_skip_both_is_clean(capsys):
    code = main(["--skip-ioc", "--skip-config"])
    captured = capsys.readouterr()
    assert code == 0
    assert "no indicators" in captured.out
