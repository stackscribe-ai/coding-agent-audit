"""Shared Finding type used by every check module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


@dataclass
class Finding:
    check_id: str
    severity: str  # "info" | "warning" | "critical"
    title: str
    detail: str
    path: Optional[str] = None
    references: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {self.severity!r}")

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "path": self.path,
            "references": self.references,
        }


def worst_severity(findings: list[Finding]) -> Optional[str]:
    if not findings:
        return None
    return max(findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity
