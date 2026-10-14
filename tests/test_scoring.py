"""Severity rollup & posture score: exclusions, weighting, fips gate."""

from aos8_auditor.engine.models import (
    ClassificationBasis,
    Finding,
    Severity,
    Status,
)
from aos8_auditor.engine.scoring import score


def _f(cid, status, severity):
    return Finding(control_id=cid, title=cid, category="x", status=status, severity=severity)


def test_all_pass_is_100():
    findings = [_f("A", Status.PASS, Severity.HIGH), _f("B", Status.PASS, Severity.LOW)]
    assert score(findings).posture_score == 100.0


def test_manual_na_error_excluded_from_denominator():
    # Only one scored control (a passing high); everything else is excluded.
    findings = [
        _f("A", Status.PASS, Severity.HIGH),
        _f("B", Status.MANUAL, Severity.HIGH),
        _f("C", Status.NOT_APPLICABLE, Severity.CRITICAL),
        _f("D", Status.ERROR, Severity.CRITICAL),
    ]
    s = score(findings)
    assert s.posture_score == 100.0  # the manual/na/error do not drag it down


def test_weighted_deduction():
    # one passing high (10) + one failing high (10): deduction 10 / denom 20 -> 50.0
    findings = [_f("A", Status.PASS, Severity.HIGH), _f("B", Status.FAIL, Severity.HIGH)]
    assert score(findings).posture_score == 50.0


def test_warn_is_half_weight():
    # passing high (10) + warn high (10*0.5=5 deduction) -> 1 - 5/20 = 0.75 -> 75.0
    findings = [_f("A", Status.PASS, Severity.HIGH), _f("B", Status.WARN, Severity.HIGH)]
    assert score(findings).posture_score == 75.0


def test_worst_severity_failed():
    findings = [_f("A", Status.FAIL, Severity.MEDIUM), _f("B", Status.FAIL, Severity.CRITICAL)]
    assert score(findings).worst_severity_failed == Severity.CRITICAL


def test_fips_gate():
    findings = [_f("AOS8-GLOBAL-FIPS-001", Status.FAIL, Severity.CRITICAL)]
    s = score(findings, active_profile="fips")
    assert s.fips_gate is True and s.fips_gate_failed is True
    s2 = score(findings, active_profile="high_security")
    assert s2.fips_gate is False


def test_fail_on_manual_severity_still_scores():
    # An attested FAIL on a manual-severity control (e.g. default admin password)
    # must NOT vanish from the headline — it floors to medium and counts.
    findings = [_f("AOS8-INIT-001", Status.FAIL, Severity.MANUAL)]
    s = score(findings)
    assert s.posture_score == 0.0  # the lone scored control failed
    assert s.worst_severity_failed == Severity.MEDIUM


def test_matrix_counts():
    findings = [_f("A", Status.FAIL, Severity.HIGH), _f("B", Status.PASS, Severity.HIGH)]
    s = score(findings)
    assert s.matrix["high"]["fail"] == 1 and s.matrix["high"]["pass"] == 1
    assert s.counts["fail"] == 1 and s.counts["pass"] == 1
