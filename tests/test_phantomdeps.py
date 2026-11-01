from pathlib import Path
from unittest.mock import patch

from agentaudit.phantomdeps import (
    check_phantom_dependencies,
    parse_npm_package_names,
    parse_pyproject_packages,
    parse_requirements_txt,
)


def test_parse_npm_package_names(tmp_path: Path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        '{"dependencies": {"left-pad": "1.0.0"}, '
        '"devDependencies": {"@scope/tool": "2.0.0"}}'
    )
    names = parse_npm_package_names(pkg)
    assert set(names) == {"left-pad", "@scope/tool"}


def test_parse_npm_package_names_invalid_json(tmp_path: Path):
    pkg = tmp_path / "package.json"
    pkg.write_text("{not json")
    assert parse_npm_package_names(pkg) == []


def test_parse_requirements_txt(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "requests==2.31.0\n"
        "# a comment\n"
        "\n"
        "numpy>=1.20,<2.0\n"
        "-e git+https://example.com/foo.git\n"
        "pandas\n"
    )
    names = parse_requirements_txt(req)
    assert names == ["requests", "numpy", "pandas"]


def test_parse_pyproject_packages_pep621(tmp_path: Path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        "[project]\n"
        'dependencies = [\n'
        '    "requests>=2.0",\n'
        '    "totally-made-up-pkg-xyz",\n'
        "]\n"
    )
    names = parse_pyproject_packages(pp)
    assert set(names) == {"requests", "totally-made-up-pkg-xyz"}


def test_parse_pyproject_packages_poetry(tmp_path: Path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        "[tool.poetry.dependencies]\n"
        'python = "^3.9"\n'
        'requests = "^2.0"\n'
        "\n"
        "[tool.poetry.group.dev.dependencies]\n"
        'pytest = "^7.0"\n'
    )
    names = parse_pyproject_packages(pp)
    assert "requests" in names
    assert "python" not in names


def test_check_phantom_dependencies_flags_nonexistent_npm(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"left-pad": "1.0.0", "definitely-not-a-real-pkg-9x7z": "1.0.0"}}'
    )

    def fake_exists(name: str):
        return name != "definitely-not-a-real-pkg-9x7z"

    with patch("agentaudit.phantomdeps.check_npm_package_exists", side_effect=fake_exists):
        findings = check_phantom_dependencies(tmp_path)

    assert len(findings) == 1
    assert findings[0].check_id == "phantom-dependency"
    assert "definitely-not-a-real-pkg-9x7z" in findings[0].title


def test_check_phantom_dependencies_network_unknown_not_flagged(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("some-package\n")

    with patch("agentaudit.phantomdeps.check_pypi_package_exists", return_value=None):
        findings = check_phantom_dependencies(tmp_path)

    assert findings == []


def test_check_phantom_dependencies_no_manifests(tmp_path: Path):
    assert check_phantom_dependencies(tmp_path) == []
