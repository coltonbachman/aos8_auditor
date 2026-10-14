"""Turn a skip into a suppression entry the next audit will honour.

A skip is not automatically a suppression. Most skips mean "not this week", and
the control should keep failing until it is fixed. A suppression means "we have
looked at this and decided to carry the risk", which is a different statement, so
the wizard only writes one when the operator says so — and then it writes the
justification and the expiry date, both required, because a suppression without
an end date is a failure that quietly stops being reported.

Existing entries for the same control and host are replaced rather than appended,
so re-running the wizard does not accumulate duplicates that shadow each other.
"""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path

import yaml

from ..engine.suppressions import Suppression, suppressions_from_items
from .plan import Change, RemediationPlan

BANNER = (
    "# Suppressions — documented, time-boxed accepted risk.\n"
    "#\n"
    "# A suppressed control STAYS in the report and is excluded from the posture\n"
    "# score. Every entry needs a justification and an expiry: on the expiry date\n"
    "# the finding comes back, which is the point.\n"
    "#\n"
    "# Entries below were written by 'aos8-audit --remediate'. Edit them freely.\n"
)


def entries_from_plan(plan: RemediationPlan, *, host: str | None = None) -> list[dict]:
    """The suppression entries implied by this plan's skipped changes."""
    target = host or plan.report.run_metadata.target.get("host") or plan.context.host
    out = []
    for c in plan.skipped:
        if not c.suppress_expires:
            continue  # a plain skip; the control keeps failing, as it should
        out.append(_entry(c, target))
    return out


def _entry(c: Change, host: str | None) -> dict:
    item = {
        "control_id": c.control_id,
        "justification": c.skip_reason or "",
        "expires": c.suppress_expires,
    }
    if host:
        item["host"] = host
    return item


def merge(existing: list[dict], new: list[dict]) -> list[dict]:
    """New entries win over existing ones with the same (control_id, host)."""
    keyed = {(e.get("control_id"), e.get("host")): e for e in existing}
    for e in new:
        keyed[(e.get("control_id"), e.get("host"))] = e
    return sorted(keyed.values(), key=lambda e: (e.get("control_id") or "",
                                                 e.get("host") or ""))


def read_existing(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
    items = data if isinstance(data, list) else (data.get("suppressions") or [])
    return [i for i in items if isinstance(i, dict) and i.get("control_id")]


def write_suppressions(path: str | Path, entries: list[dict], *,
                       merge_existing: bool = True) -> Path:
    """Write ``suppressions.yaml``, validating it the way the auditor will read it.

    Validation happens here, at write time, rather than being discovered on the
    next run: a file the auditor refuses to load is worse than no file, because
    the operator believes the risk was recorded.
    """
    p = Path(path)
    items = merge(read_existing(p), entries) if merge_existing else list(entries)
    suppressions_from_items(items)  # raises if a justification is missing
    for item in items:
        _check_expiry(item)
    body = yaml.safe_dump({"suppressions": items}, sort_keys=False,
                          default_flow_style=False, width=88)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(BANNER + "\n" + body, encoding="utf-8")
    os.chmod(p, 0o600)
    return p


def _check_expiry(item: dict) -> None:
    expires = item.get("expires")
    if not expires:
        raise ValueError(
            f"suppression for {item.get('control_id')!r} has no expiry; the wizard "
            "does not write risk acceptance that never comes back up for review"
        )
    try:
        date.fromisoformat(str(expires))
    except ValueError as exc:
        raise ValueError(
            f"suppression for {item.get('control_id')!r}: {expires!r} is not a "
            "YYYY-MM-DD date"
        ) from exc


def to_suppression_objects(entries: list[dict]) -> list[Suppression]:
    """For tests and for previewing the effect without writing a file."""
    return suppressions_from_items(entries)
