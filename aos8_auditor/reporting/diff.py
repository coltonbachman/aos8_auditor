"""Run-over-run diffing: compare two reports to surface posture drift.

Classifies each control as fixed / regressed / new-fail / resolved / changed /
unchanged / added / removed. Drives remediation tracking and CI gating.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..engine.models import Report, Status

_BAD = {Status.FAIL, Status.ERROR}


@dataclass
class ControlDelta:
    control_id: str
    title: str
    old_status: str | None
    new_status: str | None
    change: str  # see classify below


@dataclass
class ReportDiff:
    old_run: str
    new_run: str
    regressed: list[ControlDelta] = field(default_factory=list)   # got worse (e.g. pass->fail)
    fixed: list[ControlDelta] = field(default_factory=list)       # got better (e.g. fail->pass)
    changed: list[ControlDelta] = field(default_factory=list)     # other status change
    added: list[ControlDelta] = field(default_factory=list)       # new control id
    removed: list[ControlDelta] = field(default_factory=list)     # gone control id
    score_old: float | None = None
    score_new: float | None = None

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressed)


def _rank(status: Status) -> int:
    # Lower is healthier. Used to decide regressed vs fixed.
    return {Status.PASS: 0, Status.NOT_APPLICABLE: 0, Status.MANUAL: 1,
            Status.WARN: 2, Status.ERROR: 3, Status.FAIL: 4}.get(status, 1)


def diff_reports(old: Report, new: Report) -> ReportDiff:
    old_by = {f.control_id: f for f in old.results}
    new_by = {f.control_id: f for f in new.results}
    d = ReportDiff(old_run=old.run_metadata.run_id, new_run=new.run_metadata.run_id,
                   score_old=old.summary.posture_score, score_new=new.summary.posture_score)

    for cid, nf in new_by.items():
        of = old_by.get(cid)
        if of is None:
            d.added.append(ControlDelta(cid, nf.title, None, nf.status.value, "added"))
            continue
        if of.status == nf.status:
            continue
        delta = ControlDelta(cid, nf.title, of.status.value, nf.status.value, "changed")
        if _rank(nf.status) > _rank(of.status):
            delta.change = "regressed"
            d.regressed.append(delta)
        elif _rank(nf.status) < _rank(of.status):
            delta.change = "fixed"
            d.fixed.append(delta)
        else:
            d.changed.append(delta)

    for cid, of in old_by.items():
        if cid not in new_by:
            d.removed.append(ControlDelta(cid, of.title, of.status.value, None, "removed"))
    return d


def load_report(run_dir: str | Path) -> Report:
    path = Path(run_dir) / "report.json"
    if not path.exists():
        raise FileNotFoundError(f"no report.json under {run_dir}")
    return Report.model_validate_json(path.read_text())


def render_diff_text(d: ReportDiff) -> str:
    lines = [f"diff {d.old_run} -> {d.new_run}  score {d.score_old} -> {d.score_new}"]
    for label, items in (("REGRESSED", d.regressed), ("FIXED", d.fixed),
                         ("CHANGED", d.changed), ("ADDED", d.added), ("REMOVED", d.removed)):
        for c in items:
            lines.append(f"  [{label}] {c.control_id}: {c.old_status} -> {c.new_status}")
    if len(lines) == 1:
        lines.append("  (no control status changes)")
    return "\n".join(lines)
