"""Finding suppressions — accept documented, time-boxed risk without hiding it.

A suppression entry requires a justification and an expiry date, and is keyed by
``control_id`` (optionally narrowed to a ``host``). A matched, unexpired
suppression marks the finding ``suppressed=True`` (it STAYS in the report and is
excluded from the posture score). Expired suppressions do NOT suppress and are
surfaced as warnings; suppressions that matched nothing are flagged as stale, so
the report stays honest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from .models import Finding


@dataclass
class Suppression:
    control_id: str
    justification: str
    expires: str | None = None  # YYYY-MM-DD
    host: str | None = None  # optional narrowing to a target host
    matched: int = field(default=0, compare=False)

    def is_expired(self, today: date) -> bool:
        if not self.expires:
            return False
        try:
            return date.fromisoformat(self.expires) < today
        except ValueError:
            return False  # malformed date -> treat as non-expiring but flag elsewhere

    def applies_to(self, finding: Finding, host: str | None) -> bool:
        if finding.control_id != self.control_id:
            return False
        return self.host is None or self.host == host


def suppressions_from_items(items: list | None) -> list[Suppression]:
    out: list[Suppression] = []
    for item in items or []:
        if not item or "control_id" not in item:
            continue
        if not item.get("justification"):
            raise ValueError(f"suppression for {item['control_id']!r} is missing a required 'justification'")
        out.append(Suppression(
            control_id=item["control_id"], justification=item["justification"],
            expires=item.get("expires"), host=item.get("host"),
        ))
    return out


def load_suppressions(path: str | Path | None) -> list[Suppression]:
    if not path:
        return []
    data = yaml.safe_load(Path(path).read_text()) or []
    items = data if isinstance(data, list) else data.get("suppressions", [])
    out: list[Suppression] = []
    for item in items:
        if not item or "control_id" not in item:
            continue
        if not item.get("justification"):
            raise ValueError(f"suppression for {item['control_id']!r} is missing a required 'justification'")
        out.append(Suppression(
            control_id=item["control_id"],
            justification=item["justification"],
            expires=item.get("expires"),
            host=item.get("host"),
        ))
    return out


def apply_suppressions(
    findings: list[Finding],
    suppressions: list[Suppression],
    *,
    host: str | None,
    today: date,
) -> list[str]:
    """Mark matching, unexpired findings as suppressed. Returns warnings."""
    warnings: list[str] = []
    for sup in suppressions:
        expired = sup.is_expired(today)
        if sup.expires and not _valid_date(sup.expires):
            warnings.append(f"suppression {sup.control_id}: malformed expires {sup.expires!r} (ignored as non-expiring)")
        for f in findings:
            if sup.applies_to(f, host):
                sup.matched += 1
                if expired:
                    continue  # expired -> does not suppress
                f.suppressed = True
                f.suppression_reason = sup.justification
        if expired:
            warnings.append(f"suppression {sup.control_id}: EXPIRED on {sup.expires} (no longer suppressing)")
        elif sup.matched == 0:
            warnings.append(f"suppression {sup.control_id}: stale (matched no finding this run)")
    return warnings


def _valid_date(s: str) -> bool:
    try:
        date.fromisoformat(s)
        return True
    except ValueError:
        return False
