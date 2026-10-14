"""Plan construction: which findings become changes, in what order, in which band."""

from pathlib import Path

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.models import Status
from aos8_auditor.remediate import build_plan, context_from_config
from aos8_auditor.remediate.plan import ChangeState, ImpactBand, band_for, build_change
from aos8_auditor.remediate.recipes import recipe_ids
from support import make_collection

CONFIG = Path(__file__).parent.parent / "fixtures" / "sample_running_config.txt"
CONTROLS = load_controls()


def _plan():
    rc = CONFIG.read_text()
    report = audit(make_collection(rc), CONTROLS, tool_version="test")
    return build_plan(report, context_from_config(rc, host="10.0.0.1")), report


def test_only_failing_and_warning_findings_become_changes():
    plan, report = _plan()
    ids = {c.control_id for c in plan.changes}
    for f in report.results:
        if f.status in (Status.FAIL, Status.WARN) and not f.suppressed:
            assert f.control_id in ids
        else:
            assert f.control_id not in ids


def test_suppressed_findings_are_not_offered():
    plan, report = _plan()
    report.results[0].status = Status.FAIL
    report.results[0].suppressed = True
    replan = build_plan(report, plan.context)
    assert report.results[0].control_id not in {c.control_id for c in replan.changes}


def test_changes_are_emitted_in_dependency_order():
    plan, _ = _plan()
    orders = [c.order for c in plan.ordered(plan.actionable)]
    assert orders == sorted(orders)


def test_lockout_changes_sort_after_everything_else():
    """The whole point of the ordering hint: central auth is configured and
    verified before the local fallback that depends on it is removed."""
    plan, _ = _plan()
    from aos8_auditor.remediate.recipes import recipe_for
    assert recipe_for("AOS8-MGMT-CENTRALAUTH-001").order < \
        recipe_for("AOS8-MGMT-LOCALAUTH-001").order
    assert recipe_for("AOS8-MGMT-LOCALAUTH-001").order < \
        recipe_for("AOS8-MGMT-CONSOLE-BLOCK-001").order


def test_band_is_derived_from_the_impact_rating():
    from aos8_auditor.engine.impact import impact_for
    assert band_for(impact_for("AOS8-GLOBAL-FIPS-001")) is ImpactBand.CONTROLLER
    assert band_for(impact_for("AOS8-GLOBAL-LCD-001")) is ImpactBand.NONE
    assert band_for(impact_for("AOS8-FW-ARPSPOOF-001")) is ImpactBand.CLIENT
    assert band_for(None) is ImpactBand.NONE


def test_zero_impact_changes_are_preselected():
    plan, _ = _plan()
    for c in plan.actionable:
        assert c.selected is (c.band is ImpactBand.NONE)


def test_non_actionable_findings_are_kept_as_manual():
    """Prose-only remediation still belongs in the change ticket; dropping it
    would make the export look like the whole gap."""
    plan, _ = _plan()
    assert plan.manual
    for c in plan.manual:
        assert not c.commands and c.finding.remediation_hint


def test_projected_score_rises_only_for_accepted_changes():
    plan, report = _plan()
    assert plan.projected_score() == report.summary.posture_score
    for c in plan.actionable:
        c.state = ChangeState.ACCEPTED
    assert plan.projected_score() > report.summary.posture_score


def test_projected_score_ignores_advisory_changes():
    """Advisories are not scored by the auditor, so they cannot move the score."""
    plan, report = _plan()
    for c in plan.actionable:
        c.advisory = True
        c.state = ChangeState.ACCEPTED
    assert plan.projected_score() == report.summary.posture_score


def test_needs_window_reflects_reboot_and_ap_impact():
    plan, _ = _plan()
    assert not plan.needs_window()
    for c in plan.actionable:
        if c.band is ImpactBand.CONTROLLER:
            c.state = ChangeState.ACCEPTED
    assert plan.needs_window()


# -- rollback -------------------------------------------------------------

def _change(control_id):
    finding = next(c for c in CONTROLS if c.id == control_id)
    from aos8_auditor.engine.models import Finding, Severity
    return build_change(Finding(control_id=control_id, title=finding.title,
                                category=finding.category, status=Status.FAIL,
                                severity=Severity.MEDIUM,
                                remediation_hint=finding.remediation_hint))


def test_reviewed_rollback_wins_over_derivation():
    c = _change("AOS8-FW-ARPSPOOF-001")
    cmds, note = c.rollback()
    assert cmds == ["firewall", "no prohibit-arp-spoofing"] and note is None


def test_no_inverse_yields_guidance_not_a_partial_rollback():
    c = _change("AOS8-CRYPTO-TLS-001")
    cmds, note = c.rollback()
    assert cmds == [] and "recorded below" in note


def test_single_negation_inverts_automatically():
    from aos8_auditor.engine.models import Finding, Severity
    c = build_change(Finding(control_id="X", title="t", category="c",
                             status=Status.FAIL, severity=Severity.LOW,
                             remediation_hint="no telnet cli"))
    assert c.rollback()[0] == ["telnet cli"]


def test_hand_edited_block_gets_no_derived_rollback():
    """Once the operator rewrites a line, the guide no longer describes what was
    sent, so an inferred inverse would be reversing the wrong thing."""
    from aos8_auditor.engine.models import Finding, Severity
    c = build_change(Finding(control_id="X", title="t", category="c",
                             status=Status.FAIL, severity=Severity.LOW,
                             remediation_hint="no telnet cli"))
    c.hand_edited[0] = "no telnet soe"
    cmds, note = c.rollback()
    assert cmds == [] and note


def test_every_recipe_names_a_real_control():
    unknown = recipe_ids() - {c.id for c in CONTROLS}
    assert not unknown, f"recipes reference unknown control ids: {sorted(unknown)}"


def test_notes_do_not_repeat_themselves():
    plan, _ = _plan()
    for c in plan.changes:
        assert len(c.notes) == len(set(c.notes))
