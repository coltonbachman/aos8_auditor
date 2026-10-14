"""Severity rollup and posture score.

Transparent and explainable: a status x severity matrix plus a single 0-100
posture score. ``manual``, ``not_applicable``, and ``error`` are EXCLUDED from the
denominator so attestation-only controls (lots of physical/TEL ones) do not drag
the number down. ``warn`` deducts a configurable fraction of its severity weight.
The weight table is returned in the summary so the score is reproducible.
"""

from __future__ import annotations

from collections import defaultdict

from .models import Finding, ScoreSummary, Severity, Status

DEFAULT_WEIGHTS: dict[str, float] = {
    Severity.CRITICAL.value: 40.0,
    Severity.HIGH.value: 10.0,
    Severity.MEDIUM.value: 3.0,
    Severity.LOW.value: 1.0,
}
DEFAULT_WARN_FRACTION = 0.5

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
_SCORED = {Status.PASS, Status.FAIL, Status.WARN}
# A fail/warn on a control whose declared severity is a non-scoring bucket
# (manual/informational) — e.g. an operator attesting AOS8-INIT-001 to 'fail' —
# must still count, not vanish from the headline. Floor it to this severity.
_FAIL_FLOOR = Severity.MEDIUM


def _scoring_severity(f: Finding) -> Severity:
    if f.status in (Status.FAIL, Status.WARN) and f.severity not in _SEVERITY_ORDER:
        return _FAIL_FLOOR
    return f.severity


def score(
    findings: list[Finding],
    *,
    active_profile: str = "high_security",
    weights: dict[str, float] | None = None,
    warn_fraction: float = DEFAULT_WARN_FRACTION,
) -> ScoreSummary:
    weights = weights or dict(DEFAULT_WEIGHTS)

    counts: dict[str, int] = defaultdict(int)
    matrix: dict[str, dict[str, int]] = {s.value: defaultdict(int) for s in _SEVERITY_ORDER}
    matrix["manual"] = defaultdict(int)
    matrix["informational"] = defaultdict(int)

    denom = 0.0
    deduction = 0.0
    worst: Severity | None = None
    fips_gate_failed = False

    for f in findings:
        counts[f.status.value] += 1
        matrix.setdefault(f.severity.value, defaultdict(int))
        matrix[f.severity.value][f.status.value] += 1  # matrix uses the DECLARED severity

        if f.suppressed:
            counts["suppressed"] = counts.get("suppressed", 0) + 1
            continue  # documented, time-boxed risk: excluded from the score

        eff = _scoring_severity(f)  # fail/warn floored off non-scoring buckets
        w = weights.get(eff.value, 0.0)
        if f.status in _SCORED and w > 0:
            denom += w
            if f.status == Status.FAIL:
                deduction += w
            elif f.status == Status.WARN:
                deduction += w * warn_fraction

        if f.status == Status.FAIL and eff in _SEVERITY_ORDER:
            if worst is None or _SEVERITY_ORDER.index(eff) < _SEVERITY_ORDER.index(worst):
                worst = eff
            if eff == Severity.CRITICAL and "fips" in f.control_id.lower():
                fips_gate_failed = True

    posture = round(100.0 * (1.0 - deduction / denom), 1) if denom > 0 else None

    return ScoreSummary(
        posture_score=posture,
        worst_severity_failed=worst,
        fips_gate=(active_profile == "fips"),
        fips_gate_failed=(active_profile == "fips" and fips_gate_failed),
        weights={**weights, "warn_fraction": warn_fraction},
        counts=dict(counts),
        matrix={k: dict(v) for k, v in matrix.items() if v},
    )
