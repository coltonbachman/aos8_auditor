"""Ordered applicability resolution — the false-positive backbone.

Each control passes through profile -> platform -> condition -> evidence gates
*before* any pass/fail logic runs. Crucially, evidence that was DENIED to the
read-only role or UNSUPPORTED on this train resolves to ``manual`` (never
``fail``), and an unknown condition resolves to ``manual`` rather than a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..model.evidence import ExitKind
from .models import ClassificationBasis, ControlDef, Status


@dataclass
class Gate:
    status: Status
    reason: str
    basis: ClassificationBasis = ClassificationBasis.MACHINE


_TRUE = {"true", "yes", "1", "on", "enabled"}
_FALSE = {"false", "no", "0", "off", "disabled"}


def _coerce(token: str):
    t = token.strip().strip('"').strip("'")
    low = t.lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    return t


def eval_condition(expr: str, facts: dict) -> bool | None:
    """Evaluate a tiny condition expression against ``facts``.

    Supported forms (no general eval): ``key``, ``not key``,
    ``key == value``, ``key != value``, ``key >= n``, ``key <= n``.
    Returns ``None`` when the referenced fact is unknown (absent or None).
    """
    expr = expr.strip()
    m = re.fullmatch(r"(not\s+)?([\w.]+)", expr)
    if m:
        key = m.group(2)
        if key not in facts or facts[key] is None:
            return None
        val = bool(facts[key])
        return (not val) if m.group(1) else val

    m = re.fullmatch(r"([\w.]+)\s*(==|!=|>=|<=)\s*(\S+)", expr)
    if not m:
        raise ValueError(f"unparseable condition: {expr!r}")
    key, op, rhs = m.group(1), m.group(2), _coerce(m.group(3))
    if key not in facts or facts[key] is None:
        return None
    lhs = facts[key]
    # Dispatch lazily: equality always yields a real bool (str-vs-bool/int just
    # compares unequal); only ordering against non-orderable types degrades to None.
    if op == "==":
        return lhs == rhs
    if op == "!=":
        return lhs != rhs
    try:
        return (lhs >= rhs) if op == ">=" else (lhs <= rhs)
    except TypeError:
        return None


def resolve(control: ControlDef, model, facts: dict, active_profile: str) -> Gate | None:
    """Return a :class:`Gate` if the control is gated, else ``None`` to proceed."""
    ap = control.applicability

    # 1. profile gate
    if ap.profiles and active_profile not in ap.profiles:
        return Gate(Status.NOT_APPLICABLE, f"profile '{active_profile}' not in {ap.profiles}")

    # 2. platform gate
    if ap.platforms:
        plat = model.identity.platform_family
        if not plat:
            return Gate(Status.MANUAL, "platform unknown; cannot evaluate platform applicability")
        if plat not in ap.platforms:
            return Gate(Status.NOT_APPLICABLE, f"platform '{plat}' not in {ap.platforms}")

    # 3. condition gate
    if ap.condition:
        cond = eval_condition(ap.condition, facts)
        if cond is None:
            return Gate(Status.MANUAL, f"condition '{ap.condition}' is unknown (declare it in org_profile)",
                        ClassificationBasis.ATTESTATION)
        if cond is False:
            return Gate(Status.NOT_APPLICABLE, f"condition '{ap.condition}' not met")

    # 4. evidence gate
    for key in ap.requires_evidence:
        ek = model.exit_kind_for(key)
        if ek is None:
            return Gate(Status.MANUAL, f"evidence '{key}' was not collected",
                        ClassificationBasis.CAPABILITY_GATED)
        if ek == ExitKind.DENIED:
            return Gate(Status.MANUAL, f"evidence '{key}' denied to the read-only role",
                        ClassificationBasis.CAPABILITY_GATED)
        if ek == ExitKind.UNSUPPORTED:
            return Gate(Status.MANUAL, f"evidence '{key}' unsupported on this train",
                        ClassificationBasis.CAPABILITY_GATED)
        if ek == ExitKind.SKIPPED:
            return Gate(Status.MANUAL, f"evidence '{key}' skipped (collection incomplete)",
                        ClassificationBasis.CAPABILITY_GATED)
        if ek in (ExitKind.ERROR, ExitKind.TIMEOUT):
            return Gate(Status.ERROR, f"evidence '{key}' errored ({ek.value})",
                        ClassificationBasis.CAPABILITY_GATED)

    return None
