"""Open-port and control-plane exposure reference, annotated with this controller's facts.

Nothing here is scored and nothing here is probed — the auditor never scans. The
guide's "Controller Open Ports" (p.9-14), "Access Point Open Ports" (p.14) and
"Aruba Core Protocols & Ports" (p.30-53) tables are reference data in
``data/open_ports.yaml``; this module joins them against the audit facts so a
report can say "UDP/53 — the DNS responder is on, and the guide says it is
blockable when unused" instead of printing 43 ports flatly.

A port whose backing fact is undeterminable stays ``unknown``. That is deliberate:
telling an operator a port is safe to block on a guess is worse than silence.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

import yaml

from .models import ControlPlaneProtocol, PortEntry, PortExposure, PortGuidance, PortUsage

# Guidance values that mean "this port can be closed on THIS controller".
_ALWAYS_BLOCKABLE = {PortGuidance.SAFE_TO_BLOCK}
_CONDITIONALLY_BLOCKABLE = {PortGuidance.BLOCK_IF_UNUSED}


@lru_cache(maxsize=1)
def _load() -> tuple[list[PortEntry], list[PortEntry], list[ControlPlaneProtocol]]:
    try:
        text = resources.files("aos8_auditor.data").joinpath("open_ports.yaml").read_text()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return [], [], []
    data = yaml.safe_load(text) or {}
    ctrl = [PortEntry(**e) for e in (data.get("controller_ports") or [])]
    ap = [PortEntry(**e) for e in (data.get("access_point_ports") or [])]
    proto = [ControlPlaneProtocol(**e) for e in (data.get("control_plane_protocols") or [])]
    return ctrl, ap, proto


def _annotate(entry: PortEntry, facts: dict) -> PortEntry:
    e = entry.model_copy(deep=True)
    if e.in_use_fact:
        v = facts.get(e.in_use_fact)
        if v is True:
            e.usage = PortUsage.IN_USE
        elif v is False:
            e.usage = PortUsage.NOT_NEEDED
    if e.guidance in _ALWAYS_BLOCKABLE:
        e.blockable = True
    elif e.guidance in _CONDITIONALLY_BLOCKABLE and e.usage is PortUsage.NOT_NEEDED:
        e.blockable = True
    return e


def port_exposure(facts: dict) -> PortExposure:
    """Join the guide's port tables against this controller's facts."""
    ctrl, ap, proto = _load()
    controller = [_annotate(e, facts) for e in ctrl]
    access_points = [_annotate(e, facts) for e in ap]
    counts = {
        "controller_ports": len(controller),
        "access_point_ports": len(access_points),
        "control_plane_protocols": len(proto),
        "blockable_here": sum(1 for e in controller + access_points if e.blockable),
        "in_use": sum(1 for e in controller + access_points if e.usage is PortUsage.IN_USE),
        "not_needed": sum(1 for e in controller + access_points if e.usage is PortUsage.NOT_NEEDED),
        "unknown": sum(1 for e in controller + access_points if e.usage is PortUsage.UNKNOWN),
    }
    return PortExposure(controller_ports=controller, access_point_ports=access_points,
                        control_plane_protocols=proto, counts=counts)


def reference_facts() -> set[str]:
    """Every fact name the port tables reference (used by the catalog tests)."""
    ctrl, ap, _ = _load()
    return {e.in_use_fact for e in ctrl + ap if e.in_use_fact}
