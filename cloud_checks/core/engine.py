"""The check engine: a registry of checks and a runner that turns a snapshot into results.

A *snapshot* is what a collector read from a cloud account::

    {"cloud": "aws", "captured_at": "...", "account": {...},
     "data": {"security_groups": [...], ...},      # one key per kind of resource
     "errors": {"rds_instances": "AccessDenied ..."}}  # sections that could not be read

A *check* is a pure function over ``snapshot["data"]`` that yields a Hit for every resource
that fails. Each check names the data keys it needs; if one of them could not be collected the
check is reported as SKIPPED (with the reason) rather than silently passing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from cloud_checks.core.findings import SEVERITIES, Finding, severity_rank

CLOUDS = ("aws", "azure", "gcp")
PASS, FAIL, SKIPPED = "pass", "fail", "skipped"


@dataclass
class Hit:
    """One failing resource."""

    resource: str
    detail: str
    region: str = ""
    severity: str | None = None  # overrides the check's default severity for this resource
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Check:
    id: str
    cloud: str
    service: str
    title: str
    severity: str
    why: str
    fix: str
    needs: tuple[str, ...]
    fn: Callable[[dict[str, Any]], Iterable[Hit]]
    cis: str = ""


@dataclass
class CheckResult:
    check: Check
    status: str
    hits: list[Hit] = field(default_factory=list)
    reason: str = ""


REGISTRY: dict[str, Check] = {}


def check(*, id: str, cloud: str, service: str, title: str, severity: str, why: str, fix: str,
          needs: Iterable[str], cis: str = "") -> Callable[[Callable], Callable]:
    """Register a check. Validation happens at import time so a bad definition fails the tests."""

    def register(fn: Callable[[dict[str, Any]], Iterable[Hit]]) -> Callable:
        if id in REGISTRY:
            raise ValueError(f"duplicate check id {id}")
        if cloud not in CLOUDS:
            raise ValueError(f"{id}: unknown cloud {cloud}")
        if severity not in SEVERITIES:
            raise ValueError(f"{id}: unknown severity {severity}")
        if not id.startswith(cloud + "-"):
            raise ValueError(f"{id}: check ids start with the cloud name")
        REGISTRY[id] = Check(id, cloud, service, title, severity, why, fix, tuple(needs), fn, cis)
        return fn

    return register


def load_checks() -> None:
    """Import the check modules so their decorators run."""
    from cloud_checks.aws import checks as _aws  # noqa: F401
    from cloud_checks.azure import checks as _azure  # noqa: F401
    from cloud_checks.gcp import checks as _gcp  # noqa: F401


def checks_for(cloud: str) -> list[Check]:
    load_checks()
    return sorted((c for c in REGISTRY.values() if c.cloud == cloud), key=lambda c: (c.service, c.id))


def select(cloud: str, only: Iterable[str] = (), skip: Iterable[str] = ()) -> list[Check]:
    """Checks for a cloud, filtered by id or service name. Unknown names raise ValueError."""
    available = checks_for(cloud)
    names = {c.id for c in available} | {c.service for c in available}
    only, skip = [o.strip() for o in only if o.strip()], [s.strip() for s in skip if s.strip()]
    unknown = sorted(set(only + skip) - names)
    if unknown:
        raise ValueError(f"unknown check or service for {cloud}: {', '.join(unknown)} "
                         f"(run 'cloud-checks list --cloud {cloud}')")
    chosen = [c for c in available if not only or c.id in only or c.service in only]
    return [c for c in chosen if c.id not in skip and c.service not in skip]


def run(snapshot: dict[str, Any], checks: Iterable[Check]) -> list[CheckResult]:
    data = dict(snapshot.get("data") or {})
    data.setdefault("captured_at", snapshot.get("captured_at"))  # checks that reason about age need "now"
    errors = snapshot.get("errors") or {}
    results: list[CheckResult] = []
    for chk in checks:
        missing = [key for key in chk.needs if data.get(key) is None]
        if missing:
            reason = "; ".join(f"{key}: {errors.get(key, 'not collected')}" for key in missing)
            results.append(CheckResult(chk, SKIPPED, reason=reason))
            continue
        hits = list(chk.fn(data))
        hits.sort(key=lambda h: (severity_rank(h.severity or chk.severity), h.region, h.resource.lower()))
        results.append(CheckResult(chk, FAIL if hits else PASS, hits))
    return results


def to_findings(results: Iterable[CheckResult]) -> list[Finding]:
    findings: list[Finding] = []
    for result in results:
        chk = result.check
        for hit in result.hits:
            evidence = dict(hit.evidence)
            evidence.update({"cloud": chk.cloud, "service": chk.service, "region": hit.region, "cis": chk.cis})
            findings.append(Finding(chk.id, hit.severity or chk.severity, chk.title, hit.resource, hit.detail,
                                    chk.fix, evidence))
    return sorted(findings, key=lambda f: (severity_rank(f.severity), f.check, f.target.lower()))
