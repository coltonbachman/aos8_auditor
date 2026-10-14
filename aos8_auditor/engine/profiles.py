"""Security profile overlays (baseline / high_security / fips).

Profiles are overlays, not control copies: they may change a control's
*severity* and remap its emitted *verdict* (e.g. baseline treats a password
fallback as ``warn``; high_security/fips escalate it to ``fail``). They never
change match logic — that stays in the control YAML, reviewable in one place.

Profile files live in ``controls/_profiles/<name>.yaml``. Missing file = no
overlay (controls evaluate at their base severity/verdict).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import Finding, Severity, Status


@dataclass
class ProfileOverlay:
    name: str
    extends: str | None = None
    severity_overrides: dict[str, str] = field(default_factory=dict)
    # control_id -> {from_status: to_status}
    verdict_overrides: dict[str, dict[str, str]] = field(default_factory=dict)


def _profiles_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "controls" / "_profiles"


def load_profile(name: str) -> ProfileOverlay:
    path = _profiles_dir() / f"{name}.yaml"
    if not path.exists():
        return ProfileOverlay(name=name)
    data = yaml.safe_load(path.read_text()) or {}
    return ProfileOverlay(
        name=data.get("name", name),
        extends=data.get("extends"),
        severity_overrides=data.get("severity_overrides", {}) or {},
        verdict_overrides=data.get("verdict_overrides", {}) or {},
    )


def resolve_overlay(name: str, _seen: set[str] | None = None) -> ProfileOverlay:
    """Load a profile and fold in any profile it ``extends`` (child wins)."""
    _seen = _seen or set()
    if name in _seen:
        return ProfileOverlay(name=name)
    _seen.add(name)
    overlay = load_profile(name)
    if overlay.extends:
        parent = resolve_overlay(overlay.extends, _seen)
        sev = dict(parent.severity_overrides)
        sev.update(overlay.severity_overrides)
        ver = {k: dict(v) for k, v in parent.verdict_overrides.items()}
        for cid, mapping in overlay.verdict_overrides.items():
            ver.setdefault(cid, {}).update(mapping)
        overlay = ProfileOverlay(name=overlay.name, extends=overlay.extends,
                                 severity_overrides=sev, verdict_overrides=ver)
    return overlay


# A profile may only remap/retune ACTIONABLE verdicts. A manual (undeterminable /
# attestation), error (collection failure), or not_applicable outcome must never
# be convertible to a fail by a profile — that would break the false-positive
# backbone (capability-gated evidence becoming a hard fail).
_OVERLAYABLE = {Status.PASS, Status.WARN, Status.FAIL}


def apply_overlay(finding: Finding, overlay: ProfileOverlay) -> Finding:
    if finding.status not in _OVERLAYABLE:
        return finding
    cid = finding.control_id
    if cid in overlay.severity_overrides:
        finding.severity = Severity(overlay.severity_overrides[cid])
    remap = overlay.verdict_overrides.get(cid)
    if remap and finding.status.value in remap:
        new = Status(remap[finding.status.value])
        if new in _OVERLAYABLE:
            finding.notes = ((finding.notes + " ") if finding.notes else "") + \
                f"[profile '{overlay.name}': {finding.status.value}->{new.value}]"
            finding.status = new
    return finding
