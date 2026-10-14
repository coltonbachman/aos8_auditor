"""Phase 2 reporting: suppressions, HTML render, run-over-run diffing."""

from datetime import date
from pathlib import Path

import pytest

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.models import Finding, Report, RunMetadata, ScoreSummary, Severity, Status
from aos8_auditor.engine.suppressions import Suppression, apply_suppressions, load_suppressions
from aos8_auditor.reporting.diff import diff_reports, render_diff_text
from aos8_auditor.reporting.html import render_html
from aos8_auditor.reporting.report import write_report

from support import make_collection

CONTROLS = load_controls()
ORG = {"deployment_profile": "high_security", "stp_required": False, "ha_required": True, "wip_required": True}


def _f(cid, status, sev=Severity.HIGH):
    return Finding(control_id=cid, title=cid, category="c", status=status, severity=sev)


# --- suppressions ---------------------------------------------------------
def test_suppression_excludes_from_score_but_keeps_finding():
    findings = [_f("A", Status.FAIL), _f("B", Status.PASS)]
    sups = [Suppression(control_id="A", justification="accepted", expires="2999-01-01")]
    warnings = apply_suppressions(findings, sups, host="h", today=date(2026, 5, 29))
    assert findings[0].suppressed is True and findings[0].suppression_reason == "accepted"
    assert warnings == []
    from aos8_auditor.engine.scoring import score
    s = score(findings)
    assert s.posture_score == 100.0  # the suppressed fail is excluded
    assert s.counts.get("suppressed") == 1


def test_expired_suppression_does_not_suppress_and_warns():
    findings = [_f("A", Status.FAIL)]
    sups = [Suppression(control_id="A", justification="x", expires="2020-01-01")]
    warnings = apply_suppressions(findings, sups, host="h", today=date(2026, 5, 29))
    assert findings[0].suppressed is False
    assert any("EXPIRED" in w for w in warnings)


def test_stale_suppression_warns():
    findings = [_f("A", Status.FAIL)]
    sups = [Suppression(control_id="ZZZ-NOPE", justification="x", expires="2999-01-01")]
    warnings = apply_suppressions(findings, sups, host="h", today=date(2026, 5, 29))
    assert any("stale" in w for w in warnings)


def test_suppression_requires_justification(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("- control_id: AOS8-GLOBAL-FIPS-001\n")
    with pytest.raises(ValueError):
        load_suppressions(p)


def test_host_narrowing():
    findings = [_f("A", Status.FAIL)]
    sups = [Suppression(control_id="A", justification="x", host="other-host")]
    apply_suppressions(findings, sups, host="this-host", today=date(2026, 5, 29))
    assert findings[0].suppressed is False


# --- HTML -----------------------------------------------------------------
def _report():
    rc = "snmp-server community public\nhostname Aruba7240\n"
    return audit(make_collection(rc, {"show fips": "Mode Disabled\n"}),
                 CONTROLS, tool_version="t", active_profile="high_security", org_profile=ORG)


def test_html_renders_and_escapes(tmp_path):
    rep = _report()
    html = render_html(rep)
    assert html.startswith("<!doctype html>") and "ArubaOS 8 Hardening Audit" in html
    # device-derived text is escaped (no raw injection)
    assert "<script>" not in html


def test_write_report_emits_all_three(tmp_path):
    paths = write_report(_report(), tmp_path)
    for k in ("json", "markdown", "html"):
        assert paths[k].exists()


# --- diffing --------------------------------------------------------------
def _mk_report(run_id, statuses, score):
    res = [_f(cid, st) for cid, st in statuses.items()]
    return Report(run_metadata=RunMetadata(tool_version="t", run_id=run_id),
                  summary=ScoreSummary(posture_score=score), results=res)


def test_diff_detects_regression_and_fix():
    old = _mk_report("r1", {"A": Status.PASS, "B": Status.FAIL, "C": Status.PASS}, 80.0)
    new = _mk_report("r2", {"A": Status.FAIL, "B": Status.PASS, "D": Status.WARN}, 75.0)
    d = diff_reports(old, new)
    assert [c.control_id for c in d.regressed] == ["A"]
    assert [c.control_id for c in d.fixed] == ["B"]
    assert [c.control_id for c in d.added] == ["D"]
    assert [c.control_id for c in d.removed] == ["C"]
    assert d.has_regressions is True
    assert "REGRESSED" in render_diff_text(d)


def test_diff_no_changes():
    rep = _mk_report("r1", {"A": Status.PASS}, 100.0)
    rep2 = _mk_report("r2", {"A": Status.PASS}, 100.0)
    d = diff_reports(rep, rep2)
    assert not d.has_regressions and not d.fixed and not d.changed
