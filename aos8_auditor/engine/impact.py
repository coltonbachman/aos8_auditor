"""Per-control remediation disruption ratings.

The audit is always read-only and non-disruptive. These ratings describe how
disruptive APPLYING a control's remediation is, so operators can plan change
windows: which fixes need a controller reboot (outage), which briefly reauth
wireless clients or reboot specific APs, and which are hot management-plane-only
changes. Ratings live in ``data/remediation_impact.yaml`` (one reviewable table)
and are attached to every finding.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

import yaml

from .models import RemediationImpact

_DEFAULT = RemediationImpact()


@lru_cache(maxsize=1)
def _load() -> tuple[dict[str, RemediationImpact], RemediationImpact]:
    try:
        text = resources.files("aos8_auditor.data").joinpath("remediation_impact.yaml").read_text()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return {}, _DEFAULT
    data = yaml.safe_load(text) or {}
    defaults = {**_DEFAULT.model_dump(), **(data.get("defaults") or {})}
    table: dict[str, RemediationImpact] = {}
    for cid, d in (data.get("impacts") or {}).items():
        table[cid] = RemediationImpact(**{**defaults, **(d or {})})
    return table, RemediationImpact(**defaults)


def impact_for(control_id: str) -> RemediationImpact:
    table, default = _load()
    return table.get(control_id, default)


def rated_control_ids() -> set[str]:
    return set(_load()[0])
