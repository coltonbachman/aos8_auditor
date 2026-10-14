"""Compliance crosswalk engine: roll-up logic, validation, and report.

The most important test is the integrity one: every control id referenced by
every shipped pack must exist in the catalog (no dangling crosswalk).
"""

import pytest

from aos8_auditor.engine.compliance import (
    CompliancePack,
    Requirement,
    ReqStatus,
    evaluate_compliance,
    list_packs,
    load_pack,
    validate_pack_controls,
)
from aos8_auditor.engine.loader import load_controls
from aos8_auditor.engine.models import Finding, Severity, Status

CONTROLS = load_controls()
VALID_IDS = {c.id for c in CONTROLS}


def _f(cid, status, suppressed=False):
    return Finding(control_id=cid, title=cid, category="c", status=status,
                   severity=Severity.HIGH, suppressed=suppressed)


def _pack(reqs):
    return CompliancePack(name="t", framework="Test", requirements=reqs)


def test_rollup_statuses():
    findings = [
        _f("A", Status.PASS), _f("B", Status.FAIL), _f("C", Status.WARN),
        _f("D", Status.MANUAL), _f("E", Status.NOT_APPLICABLE), _f("F", Status.PASS, suppressed=True),
    ]
    pack = _pack([
        Requirement("R-met", "all pass", ["A"]),
        Requirement("R-gap", "a fail", ["A", "B"]),
        Requirement("R-partial", "a warn, no fail", ["A", "C"]),
        Requirement("R-review", "manual only", ["A", "D"]),
        Requirement("R-na", "all NA", ["E"]),
        Requirement("R-missing", "no such control", ["NOPE-001"]),
        Requirement("R-accepted", "only blocker suppressed", ["F"]),
    ])
    res = {r.requirement.id: r.status for r in evaluate_compliance(pack, findings).requirements}
    assert res["R-met"] == ReqStatus.MET
    assert res["R-gap"] == ReqStatus.GAP
    assert res["R-partial"] == ReqStatus.PARTIAL
    assert res["R-review"] == ReqStatus.REVIEW
    assert res["R-na"] == ReqStatus.NOT_APPLICABLE
    assert res["R-missing"] == ReqStatus.NOT_ASSESSED
    assert res["R-accepted"] == ReqStatus.ACCEPTED


def test_coverage_excludes_na_and_not_assessed():
    findings = [_f("A", Status.PASS), _f("B", Status.FAIL)]
    pack = _pack([
        Requirement("R1", "met", ["A"]),
        Requirement("R2", "gap", ["B"]),
        Requirement("R3", "na", ["NOPE"]),  # not assessed -> excluded from denominator
    ])
    cr = evaluate_compliance(pack, findings)
    assert cr.coverage_pct == 50.0  # 1 met of 2 assessable (R3 excluded)


def test_missing_controls_flagged():
    pack = _pack([Requirement("R", "x", ["A", "NOPE-001"])])
    cr = evaluate_compliance(pack, [_f("A", Status.PASS)])
    assert cr.requirements[0].missing_controls == ["NOPE-001"]


# --- shipped packs ---------------------------------------------------------
def test_packs_exist():
    assert "pci_dss" in list_packs()


@pytest.mark.parametrize("name", list_packs())
def test_pack_loads_and_has_no_dangling_control_refs(name):
    pack = load_pack(name)
    assert pack.requirements, f"{name} has no requirements"
    assert pack.disclaimer, f"{name} must carry a disclaimer"
    dangling = validate_pack_controls(pack, VALID_IDS)
    assert not dangling, f"{name} references unknown control ids: {dangling}"


@pytest.mark.parametrize("name", list_packs())
def test_pack_profile_is_valid(name):
    pack = load_pack(name)
    assert pack.profile in (None, "baseline", "high_security", "fips")


def test_gap_change_impact_surfaces_reboot_controls():
    from aos8_auditor.engine.compliance import CompliancePack, Requirement, evaluate_compliance
    from aos8_auditor.engine.models import (
        DisruptionLevel, Finding, RemediationImpact, Report, RunMetadata, Status,
    )
    from aos8_auditor.reporting.compliance_report import gap_change_impact

    findings = [
        Finding(control_id="A", title="A", category="c", status=Status.FAIL, severity=Severity.HIGH,
                impact=RemediationImpact(level=DisruptionLevel.HIGH, reboot_required=True, client_impact=True)),
        Finding(control_id="B", title="B", category="c", status=Status.PASS, severity=Severity.LOW),
    ]
    pack = CompliancePack(name="t", framework="T", requirements=[Requirement("R1", "x", ["A", "B"])])
    cr = evaluate_compliance(pack, findings)
    report = Report(run_metadata=RunMetadata(tool_version="t", run_id="r"), results=findings)
    gi = gap_change_impact(cr, report)
    assert gi["reboot_required"] == ["A"] and gi["client_impact"] == ["A"]
    assert gi["by_level"].get("high") == 1
