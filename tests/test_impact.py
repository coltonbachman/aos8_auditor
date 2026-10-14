"""Remediation disruption ratings: loader, finding attachment, rollup, coverage."""

from aos8_auditor.engine.impact import impact_for, rated_control_ids
from aos8_auditor.engine.loader import load_controls
from aos8_auditor.engine.models import DisruptionLevel, Finding, RemediationImpact, Severity, Status
from aos8_auditor.reporting.report import impact_rollup

_LEVELS = {l.value for l in DisruptionLevel}


def test_impact_for_returns_valid_rating():
    imp = impact_for("AOS8-GLOBAL-FIPS-001")
    assert imp.level.value in _LEVELS
    # FIPS enable requires a reboot — must not be understated.
    assert imp.reboot_required is True and imp.level == DisruptionLevel.HIGH


def test_unknown_control_gets_default():
    imp = impact_for("NOPE-999")
    assert isinstance(imp, RemediationImpact) and imp.level.value in _LEVELS


def test_every_control_has_an_explicit_rating():
    ids = {c.id for c in load_controls()}
    missing = ids - rated_control_ids()
    assert not missing, f"{len(missing)} controls lack a remediation rating: {sorted(missing)[:25]}"


def test_no_rating_for_unknown_control_ids():
    # The impact catalog should not reference controls that don't exist. Valid IDs
    # are the hardening controls PLUS the generated advisory (PSIRT) controls.
    from aos8_auditor.engine import build_advisory_controls

    ids = {c.id for c in load_controls()}
    ids |= {c.id for c in build_advisory_controls()[0]}
    stray = rated_control_ids() - ids
    assert not stray, f"impact catalog rates unknown control ids: {sorted(stray)}"


def _f(cid, status, imp):
    return Finding(control_id=cid, title=cid, category="c", status=status,
                   severity=Severity.HIGH, impact=imp)


def test_rollup_counts_reboot_client_ap():
    findings = [
        _f("A", Status.FAIL, RemediationImpact(level=DisruptionLevel.HIGH, reboot_required=True)),
        _f("B", Status.WARN, RemediationImpact(level=DisruptionLevel.MEDIUM, client_impact=True, ap_impact=True)),
        _f("C", Status.PASS, RemediationImpact(level=DisruptionLevel.HIGH, reboot_required=True)),  # pass: excluded
        _f("D", Status.FAIL, RemediationImpact(level=DisruptionLevel.NONE)),
    ]
    roll = impact_rollup(findings)
    assert roll["actionable"] == 3
    assert roll["reboot_required"] == ["A"]      # C is PASS -> not actionable
    assert roll["client_impact"] == ["B"]
    assert roll["ap_impact"] == ["B"]
    assert roll["by_level"].get("high") == 1 and roll["by_level"].get("none") == 1


def test_rollup_surfaces_high_level_without_flags():
    # A high-disruption fix that sets NO granular flag (e.g. physical power-down,
    # or an L2-loop risk) must still be surfaced by level, not silently dropped.
    findings = [
        _f("E", Status.FAIL, RemediationImpact(level=DisruptionLevel.HIGH)),          # no flags
        _f("F", Status.FAIL, RemediationImpact(level=DisruptionLevel.HIGH, reboot_required=True)),
        _f("G", Status.PASS, RemediationImpact(level=DisruptionLevel.HIGH)),           # pass: excluded
    ]
    roll = impact_rollup(findings)
    assert roll["high_impact"] == ["E", "F"]     # both actionable highs, flags or not
    assert "E" not in roll["reboot_required"]    # E carries no reboot flag...
    assert "E" in roll["high_impact"]            # ...but is still surfaced by level


def test_rating_table_is_internally_consistent():
    # Guard the ratings table against contradictions that would UNDERSTATE
    # disruption (the dangerous direction): a fix that reboots/deauths must not
    # be labeled harmless. Over-warning (e.g. client_impact at level low for a
    # single-user action) is the safe direction and is allowed.
    bad = []
    for cid in sorted(rated_control_ids()):
        imp = impact_for(cid)
        lvl = imp.level
        if imp.reboot_required and lvl != DisruptionLevel.HIGH:
            bad.append(f"{cid}: reboot_required but level={lvl.value} (expected high)")
        if imp.reboot_required and not (imp.client_impact and imp.ap_impact):
            bad.append(f"{cid}: reboot_required (full outage) but client/ap impact not both set")
        if lvl == DisruptionLevel.NONE and (imp.reboot_required or imp.client_impact or imp.ap_impact):
            bad.append(f"{cid}: level=none but a disruption flag is set")
        if (imp.client_impact or imp.ap_impact) and lvl == DisruptionLevel.NONE:
            bad.append(f"{cid}: client/ap impact but level=none")
    assert not bad, "impact rating contradictions:\n  " + "\n  ".join(bad)


def test_high_impact_controls_are_flagged_reboot():
    # Sanity: the known reboot-gated controls are rated reboot_required.
    for cid in ("AOS8-GLOBAL-FIPS-001", "AOS8-NET-CTRLIP-001"):
        assert impact_for(cid).reboot_required is True, f"{cid} should require a reboot"
