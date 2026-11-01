"""Checks for dependency-manifest entries that reference a package which
does not actually exist on the relevant registry (npm / PyPI).

AI coding agents occasionally hallucinate plausible-but-nonexistent package
names. If a project's manifest references one, an attacker can register
that exact name on the registry with malicious code ("slopsquatting") and
the next `npm install` / `pip install` run pulls it in silently. This module
only reads local manifest files and makes read-only HTTP lookups against
the public registries - it never installs or modifies anything.

Network errors (offline, timeout, DNS failure, rate limiting) are treated
as "unknown" rather than "phantom", so a flaky connection never produces a
false positive.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from .findings import Finding

_REQUEST_TIMEOUT = 4
_USER_AGENT = "coding-agent-audit (+https://github.com/stackscribe-ai/coding-agent-audit)"

_NPM_NAME_RE = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.IGNORECASE)
# Stdlib / common built-in module names that show up in requirements-style
# files but are never installed from PyPI under that name.
_PY_SKIP = {"python", "pip", "setuptools", "wheel"}


def _http_exists(url: str) -> Optional[bool]:
    """Return True if `url` resolves (2xx), False if it 404s, None if the
    check itself was inconclusive (network error, timeout, non-404 error)."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        return None
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


def check_npm_package_exists(name: str) -> Optional[bool]:
    if "/" in name:
        scope, _, rest = name.partition("/")
        encoded = f"{quote(scope, safe='')}%2F{quote(rest, safe='')}"
    else:
        encoded = quote(name, safe="")
    return _http_exists(f"https://registry.npmjs.org/{encoded}")


def check_pypi_package_exists(name: str) -> Optional[bool]:
    return _http_exists(f"https://pypi.org/pypi/{quote(name, safe='')}/json")


def parse_npm_package_names(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    names: list[str] = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict):
            names.extend(n for n in deps if isinstance(n, str))
    return names


_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def parse_requirements_txt(path: Path) -> list[str]:
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    names: list[str] = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        match = _REQ_LINE_RE.match(line)
        if not match:
            continue
        name = match.group(1).lower()
        if name not in _PY_SKIP:
            names.append(name)
    return names


_TOML_DEP_LIST_RE = re.compile(r"(?m)^\s*dependencies\s*=\s*\[(.*?)\]", re.DOTALL)
_TOML_STRING_RE = re.compile(r'"([^"]+)"|\'([^\']+)\'')
_TOML_POETRY_TABLE_RE = re.compile(
    r"(?m)^\[tool\.poetry\.(?:dependencies|dev-dependencies)\]\s*\n(.*?)(?=\n\[|\Z)", re.DOTALL
)
_TOML_POETRY_KEY_RE = re.compile(r"(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=")


def parse_pyproject_packages(path: Path) -> list[str]:
    """Best-effort regex extraction (no TOML parser dependency, no need for
    3.11+ tomllib given this project's py3.9 floor). False negatives (a
    dependency we fail to spot) are fine; this is a heuristic triage tool."""
    try:
        text = path.read_text()
    except OSError:
        return []
    names: list[str] = []
    for list_match in _TOML_DEP_LIST_RE.finditer(text):
        for entry_match in _TOML_STRING_RE.finditer(list_match.group(1)):
            entry = entry_match.group(1) or entry_match.group(2)
            name = re.split(r"[<>=!~\[; ]", entry, 1)[0].strip()
            if name:
                names.append(name)
    for table_match in _TOML_POETRY_TABLE_RE.finditer(text):
        for key_match in _TOML_POETRY_KEY_RE.finditer(table_match.group(1)):
            name = key_match.group(1)
            if name.lower() != "python":
                names.append(name)
    return names


def _is_plausible_npm_name(name: str) -> bool:
    return bool(_NPM_NAME_RE.match(name))


def check_phantom_dependencies(project_dir: Path) -> list[Finding]:
    """Scan a project directory's manifest files for dependencies that
    don't resolve on their registry."""
    findings: list[Finding] = []

    npm_names: dict[str, str] = {}
    pkg_json = project_dir / "package.json"
    if pkg_json.is_file():
        for name in parse_npm_package_names(pkg_json):
            if _is_plausible_npm_name(name):
                npm_names.setdefault(name, str(pkg_json))

    py_names: dict[str, str] = {}
    requirements = project_dir / "requirements.txt"
    if requirements.is_file():
        for name in parse_requirements_txt(requirements):
            py_names.setdefault(name, str(requirements))
    pyproject = project_dir / "pyproject.toml"
    if pyproject.is_file():
        for name in parse_pyproject_packages(pyproject):
            py_names.setdefault(name, str(pyproject))

    for name, source in npm_names.items():
        exists = check_npm_package_exists(name)
        if exists is False:
            findings.append(
                Finding(
                    check_id="phantom-dependency",
                    severity="warning",
                    title=f"npm dependency '{name}' not found on the npm registry",
                    detail=(
                        f"'{name}' is listed as a dependency but does not "
                        f"exist on registry.npmjs.org. This can happen when "
                        f"an AI coding assistant hallucinates a plausible "
                        f"package name. Until it's removed or corrected, "
                        f"anyone could publish a malicious package under "
                        f"this exact name and have it silently installed on "
                        f"the next `npm install` (slopsquatting)."
                    ),
                    path=source,
                )
            )

    for name, source in py_names.items():
        exists = check_pypi_package_exists(name)
        if exists is False:
            findings.append(
                Finding(
                    check_id="phantom-dependency",
                    severity="warning",
                    title=f"Python dependency '{name}' not found on PyPI",
                    detail=(
                        f"'{name}' is listed as a dependency but does not "
                        f"exist on pypi.org. This can happen when an AI "
                        f"coding assistant hallucinates a plausible package "
                        f"name. Until it's removed or corrected, anyone "
                        f"could publish a malicious package under this "
                        f"exact name and have it silently installed on the "
                        f"next `pip install` (slopsquatting)."
                    ),
                    path=source,
                )
            )

    return findings
