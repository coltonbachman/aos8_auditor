"""Whole-catalog integrity: load, unique ids, valid fact refs, no runtime errors,
hardened config scores clean, weak config fails broadly."""

from pathlib import Path

import pytest

from aos8_auditor.collection.command_catalog import COMMAND_CATALOG
from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.models import Status
from aos8_auditor.parse.model_builder import build_controller_model

from support import make_collection

CONTROLS = load_controls()
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
ORG = {
    "deployment_profile": "high_security", "fips_required": True, "stp_required": False,
    "ha_required": True, "wip_required": True, "ipv6_required": False,
    "machine_auth_required": False, "require_external_only_auth": False, "require_cert_auth": False,
}
_AVAILABLE_FACTS = set(build_controller_model(make_collection("hostname x", {})).facts.keys())


def test_catalog_is_substantial_and_unique():
    ids = [c.id for c in CONTROLS]
    assert len(CONTROLS) >= 149
    assert len(ids) == len(set(ids)), "duplicate control ids"


def test_every_evidence_key_is_collectable():
    # A key the collector never fetches resolves to "not collected", which
    # silently degrades the control to manual instead of failing loudly.
    known = {s.key for s in COMMAND_CATALOG}
    bad = [(c.id, e.key) for c in CONTROLS for e in (c.evidence or []) if e.key not in known]
    assert not bad, f"controls reference evidence keys the collector never gathers: {bad}"


def test_every_fact_reference_exists():
    bad = []
    for c in CONTROLS:
        if not c.logic:
            continue
        for cl in c.logic.clauses:
            w = cl.when or {}
            if str(w.get("predicate", "")).startswith("fact_"):
                arg = w.get("arg")
                path = arg.get("path") if isinstance(arg, dict) else arg
                if path is not None and path not in _AVAILABLE_FACTS:
                    bad.append((c.id, path))
    assert not bad, f"controls reference non-existent facts: {bad}"


def test_every_control_has_evidence_or_is_manual():
    # A machine control must declare evidence; manual controls may omit logic.
    for c in CONTROLS:
        if c.logic is not None:
            assert c.evidence, f"{c.id} has logic but no evidence"


def _audit(rc, outputs=None):
    return audit(make_collection(rc, outputs or {}), CONTROLS, tool_version="t",
                 active_profile="high_security", org_profile=ORG)


def test_full_catalog_no_runtime_errors_on_hardened():
    rc = (FIXTURES / "hardened_running_config.txt").read_text()
    outputs = {
        "show fips": "Mode    Enabled\n", "show controller-ip": "VLAN Interface: 10\n",
        "show license summary": "AP 100 50 50\nPEFNG 100 50 50\nRFProtect 100 50 50\n",
        "show ap database": "Name Group Status\nap01 HQ Up\n",
    }
    r = _audit(rc, outputs)
    errors = [f.control_id for f in r.results if f.status == Status.ERROR]
    assert not errors, f"controls errored at runtime: {errors}"
    assert r.summary.counts.get("fail", 0) == 0
    assert r.summary.posture_score == 100.0


def test_weak_config_fails_broadly():
    r = _audit("hostname Aruba7240\nsnmp-server community public\nspanning-tree\n",
               {"show fips": "Mode    Disabled\n"})
    assert r.summary.counts.get("fail", 0) >= 8
    assert r.summary.posture_score < 70.0
