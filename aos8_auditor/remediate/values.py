"""Non-interactive remediation: answers supplied by file instead of by keyboard.

The wizard is the good experience, but it is a terminal experience, and the same
change set often has to be regenerated in a pipeline after a re-audit. This module
takes the answers as YAML and applies them to a plan without a screen, producing
the identical artifacts.

Secrets are read from the environment, never from the file: a values file lands in
a repository. ``secret_env`` names the variable to read.

Everything is validated exactly as it would have been by hand. A values file that
puts VLAN 9000 in a VLAN field fails here for the same reason and with the same
message it would have failed on screen.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from .plan import Change, ChangeState, RemediationPlan
from .validate import validate

TEMPLATE_HEADER = """\
# Answers for 'aos8-audit --remediate-from'. Generated from a real audit, so it
# lists exactly the controls that failed on this controller and exactly the
# values each one needs.
#
#   accept:  true to include the change, false to skip it.
#   values:  one entry per <placeholder>. Secrets are NOT written here — set
#            'secret_env: VAR_NAME' and export the value instead.
#   skip:    reason + expires, to record a skip as accepted risk.
#
# Anything left blank is treated as undecided and is not exported.
#
# node_path names the node these answers were gathered for. On a Mobility Master
# each managed node runs a different config, so this file is applied only to the
# node named here and skipped for the others. Delete the key to apply it
# everywhere, which is almost never what you want.
"""


@dataclass
class ApplyReport:
    """What a values file did, and everything it got wrong."""

    accepted: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unknown_controls: list[str] = field(default_factory=list)
    # Set when the file was gathered for a different node. Not an error: on a
    # Mobility Master the caller loops over every node and only one will match.
    node_mismatch: str | None = None

    @property
    def ok(self) -> bool:
        return not self.errors


def template_for(plan: RemediationPlan) -> str:
    """A values file pre-filled with this plan's controls and placeholders."""
    controls = []
    for c in plan.ordered(plan.actionable):
        entry: dict = {
            "control_id": c.control_id,
            # title/impact are comments-as-data: they make the file reviewable by
            # someone who is not looking at the report next to it.
            "title": c.title,
            "impact": c.band.value,
            "accept": False,
        }
        plain = [f for f in c.fields if not f.is_secret]
        secrets = [f for f in c.fields if f.is_secret]
        if plain:
            entry["values"] = {f.placeholder.strip("<>"): "" for f in plain}
        if secrets:
            # Named, not valued: the secret itself never belongs in this file.
            entry["secret_env"] = {s.placeholder.strip("<>"): "CHANGE_ME"
                                   for s in secrets}
        controls.append(entry)
    body = yaml.safe_dump({"node_path": plan.node_path, "changes": controls},
                          sort_keys=False, default_flow_style=False, width=88)
    return TEMPLATE_HEADER + "\n" + body


def load_values(path: str | Path) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if isinstance(data, list):
        data = {"changes": data}
    if not isinstance(data, dict):
        raise ValueError("values file must be a mapping or a list of changes")
    return data


def apply_values(plan: RemediationPlan, data: dict, *,
                 env: dict[str, str] | None = None,
                 today: date | None = None) -> ApplyReport:
    """Apply a loaded values file to ``plan``. Never raises on bad input."""
    env = os.environ if env is None else env
    today = today or date.today()
    report = ApplyReport()

    # Managed nodes on one Mobility Master run different configs, so answers
    # gathered against one node describe a change set that does not exist on
    # another. Applying them anyway would export a file the operator never
    # reviewed for that node.
    wanted = data.get("node_path")
    if wanted and str(wanted) != plan.node_path:
        report.node_mismatch = str(wanted)
        return report

    by_id = {c.control_id: c for c in plan.changes}

    for entry in data.get("changes") or []:
        if not isinstance(entry, dict):
            report.errors.append(f"not a mapping: {entry!r}")
            continue
        cid = entry.get("control_id")
        change = by_id.get(cid)
        if change is None:
            # Not an error: a values file outlives the run it was made from, and a
            # control that now passes is a good outcome, not a broken file.
            report.unknown_controls.append(str(cid))
            continue
        _apply_one(plan, change, entry, env, report)
    return report


def _apply_one(plan: RemediationPlan, c: Change, entry: dict,
               env: dict[str, str], report: ApplyReport) -> None:
    skip = entry.get("skip")
    if skip:
        _skip(c, skip if isinstance(skip, dict) else {"reason": str(skip)}, report)
        return
    if not entry.get("accept"):
        return  # undecided: not exported, and that is not an error

    _fill(plan, c, entry, env, report)
    blocked = c.blocking_reason(plan.context)
    if blocked:
        report.errors.append(f"{c.control_id}: {blocked}")
        return
    c.state = ChangeState.ACCEPTED
    c.selected = True
    report.accepted.append(c.control_id)


def _fill(plan: RemediationPlan, c: Change, entry: dict,
          env: dict[str, str], report: ApplyReport) -> None:
    values = entry.get("values") or {}
    secret_env = entry.get("secret_env") or {}
    for f in c.fields:
        key = f.placeholder.strip("<>")
        raw: str | None = None
        if f.is_secret:
            var = secret_env.get(key)
            if not var:
                report.errors.append(
                    f"{c.control_id}: {f.placeholder} is a secret — set "
                    f"secret_env.{key} to an environment variable name")
                continue
            raw = env.get(var)
            if raw is None:
                report.errors.append(
                    f"{c.control_id}: environment variable {var} is not set "
                    f"(needed for {f.placeholder})")
                continue
        else:
            if key not in values:
                continue
            raw = values[key]
            if raw is None:
                continue
            raw = str(raw)
        result = validate(f, raw, plan.context)
        if not result.ok:
            report.errors.append(f"{c.control_id}: {f.placeholder} — {result.message}")
            continue
        if result.warning:
            report.warnings.append(f"{c.control_id}: {f.placeholder} — {result.message}")
        f.value = raw


def _skip(c: Change, skip: dict, report: ApplyReport) -> None:
    reason = str(skip.get("reason") or "").strip()
    expires = skip.get("expires")
    if expires:
        if not reason:
            report.errors.append(
                f"{c.control_id}: a skip recorded as accepted risk needs a reason")
            return
        try:
            date.fromisoformat(str(expires))
        except (ValueError, TypeError):
            report.errors.append(
                f"{c.control_id}: skip expires {expires!r} is not a YYYY-MM-DD date")
            return
        c.suppress_expires = str(expires)
    c.state = ChangeState.SKIPPED
    c.selected = False
    c.skip_reason = reason or None
    report.skipped.append(c.control_id)
