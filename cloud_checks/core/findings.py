"""Findings and severities shared by the audit tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

SEVERITIES = ("critical", "high", "medium", "low", "info")


def severity_rank(severity: str) -> int:
    """0 is critical, 4 is info. Unknown values sort last."""
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return len(SEVERITIES)


def raise_severity(severity: str, levels: int = 1) -> str:
    return SEVERITIES[max(0, severity_rank(severity) - levels)]


def lower_severity(severity: str, levels: int = 1) -> str:
    return SEVERITIES[min(len(SEVERITIES) - 1, severity_rank(severity) + levels)]


def validate_severity(value: str) -> str:
    value = value.strip().lower()
    if value not in SEVERITIES and value != "none":
        raise ValueError(f"severity must be one of {', '.join(SEVERITIES)} or none")
    return value


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    target: str
    detail: str
    recommendation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (severity_rank(f.severity), f.check, f.target.lower()))


def count_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def meets_threshold(findings: Iterable[Finding], threshold: str) -> bool:
    """True when any finding is at or above ``threshold`` ("none" never trips)."""
    if threshold == "none":
        return False
    limit = severity_rank(threshold)
    return any(severity_rank(f.severity) <= limit for f in findings)
