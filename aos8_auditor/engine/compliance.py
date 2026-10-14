"""Compliance framework packs: crosswalk hardening controls to requirements.

A pack (``compliance/<name>.yaml``) maps a framework's requirements to the
control IDs that evidence them, plus an optional strictness ``profile``, sensible
``org_profile`` defaults, framework-specific ``severity_overrides`` /
``suppressions``, and a ``disclaimer``. The audit runs once; this layer groups the
resulting findings by requirement and computes a per-requirement status and an
overall coverage figure.

IMPORTANT: these are ADVISORY crosswalks of the WLAN-controller-configuration
slice of each requirement — they help scope an assessment, they are not a
certification, and a requirement marked MET here may still need non-WLAN
evidence. Every pack carries a disclaimer that is surfaced in the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

from .models import Finding, Status


def packs_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "compliance"


class ReqStatus(str, Enum):
    MET = "met"            # all mapped controls pass (or pass/NA), >=1 pass
    GAP = "gap"            # a mapped control fails
    PARTIAL = "partial"    # warn/error present, no hard fail
    REVIEW = "review"      # manual attestation needed (and otherwise clean)
    ACCEPTED = "accepted"  # only-blocker(s) are suppressed (documented risk)
    NOT_APPLICABLE = "not_applicable"  # all mapped controls N/A
    NOT_ASSESSED = "not_assessed"      # no mapped controls present in this run


# Worst-first precedence for rolling a requirement's controls into one status.
_PRECEDENCE = [ReqStatus.GAP, ReqStatus.PARTIAL, ReqStatus.REVIEW,
               ReqStatus.ACCEPTED, ReqStatus.MET, ReqStatus.NOT_APPLICABLE,
               ReqStatus.NOT_ASSESSED]


@dataclass
class Requirement:
    id: str
    title: str
    controls: list[str] = field(default_factory=list)
    description: str | None = None


@dataclass
class CompliancePack:
    name: str               # slug, e.g. "pci_dss"
    framework: str          # display name, e.g. "PCI DSS"
    version: str | None = None
    description: str | None = None
    disclaimer: str | None = None
    profile: str | None = None
    org_profile_defaults: dict = field(default_factory=dict)
    severity_overrides: dict = field(default_factory=dict)
    suppressions: list = field(default_factory=list)
    requirements: list[Requirement] = field(default_factory=list)

    def all_control_ids(self) -> set[str]:
        ids: set[str] = set()
        for r in self.requirements:
            ids.update(r.controls)
        return ids


@dataclass
class RequirementResult:
    requirement: Requirement
    status: ReqStatus
    control_statuses: dict[str, str]   # control_id -> finding status (or "missing")
    missing_controls: list[str] = field(default_factory=list)


@dataclass
class ComplianceResult:
    pack: CompliancePack
    requirements: list[RequirementResult]
    counts: dict[str, int]
    coverage_pct: float | None  # met / (assessable requirements)

    @property
    def gaps(self) -> list[RequirementResult]:
        return [r for r in self.requirements if r.status == ReqStatus.GAP]


def load_pack(name: str) -> CompliancePack:
    path = packs_dir() / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"compliance pack not found: {name} ({path})")
    data = yaml.safe_load(path.read_text()) or {}
    reqs = [
        Requirement(id=str(r["id"]), title=r.get("title", ""), controls=list(r.get("controls", [])),
                    description=r.get("description"))
        for r in (data.get("requirements") or [])
    ]
    return CompliancePack(
        name=data.get("name", name),
        framework=data.get("framework", name),
        version=str(data.get("version")) if data.get("version") is not None else None,
        description=data.get("description"),
        disclaimer=data.get("disclaimer"),
        profile=data.get("profile"),
        org_profile_defaults=data.get("org_profile_defaults") or {},
        severity_overrides=data.get("severity_overrides") or {},
        suppressions=data.get("suppressions") or [],
        requirements=reqs,
    )


def list_packs() -> list[str]:
    d = packs_dir()
    if not d.exists():
        return []
    return sorted(p.stem for p in d.glob("*.yaml"))


def _roll_up(statuses: list[Status], any_suppressed_blocker: bool) -> ReqStatus:
    # ``statuses`` excludes suppressed findings; ``any_suppressed_blocker`` is True
    # if a mapped control was suppressed (documented/accepted risk).
    s = set(statuses)
    if Status.FAIL in s:
        return ReqStatus.GAP
    if Status.WARN in s or Status.ERROR in s:
        return ReqStatus.PARTIAL
    if Status.MANUAL in s:
        return ReqStatus.REVIEW
    if Status.PASS in s:
        return ReqStatus.MET
    # No live pass/fail/warn/manual remaining.
    if any_suppressed_blocker:
        return ReqStatus.ACCEPTED
    if s and s <= {Status.NOT_APPLICABLE}:
        return ReqStatus.NOT_APPLICABLE
    return ReqStatus.NOT_ASSESSED


def evaluate_compliance(pack: CompliancePack, findings: list[Finding]) -> ComplianceResult:
    by_id = {f.control_id: f for f in findings}
    results: list[RequirementResult] = []

    for req in pack.requirements:
        statuses: list[Status] = []
        ctl_statuses: dict[str, str] = {}
        missing: list[str] = []
        any_suppressed = False
        for cid in req.controls:
            f = by_id.get(cid)
            if f is None:
                missing.append(cid)
                ctl_statuses[cid] = "missing"
                continue
            ctl_statuses[cid] = ("suppressed" if f.suppressed else f.status.value)
            if f.suppressed:
                any_suppressed = True
                continue  # accepted risk: not a live blocker
            statuses.append(f.status)
        status = _roll_up(statuses, any_suppressed)
        results.append(RequirementResult(requirement=req, status=status,
                                         control_statuses=ctl_statuses, missing_controls=missing))

    counts: dict[str, int] = {}
    for r in results:
        counts[r.status.value] = counts.get(r.status.value, 0) + 1
    assessable = sum(1 for r in results if r.status not in (ReqStatus.NOT_APPLICABLE, ReqStatus.NOT_ASSESSED))
    met = counts.get(ReqStatus.MET.value, 0) + counts.get(ReqStatus.ACCEPTED.value, 0)
    coverage = round(100.0 * met / assessable, 1) if assessable else None

    # Stable, worst-first ordering for the report.
    results.sort(key=lambda r: (_PRECEDENCE.index(r.status), r.requirement.id))
    return ComplianceResult(pack=pack, requirements=results, counts=counts, coverage_pct=coverage)


def validate_pack_controls(pack: CompliancePack, valid_ids: set[str]) -> list[str]:
    """Return control IDs referenced by the pack that do not exist (dangling)."""
    return sorted(cid for cid in pack.all_control_ids() if cid not in valid_ids)
