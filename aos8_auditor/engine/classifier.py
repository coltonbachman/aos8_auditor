"""Evaluate one :class:`ControlDef` against a ``ControllerModel`` -> ``Finding``.

Order: applicability gate (may short-circuit to NA/manual/error) -> logic
evaluation via the predicate DSL -> operator attestation -> profile overlay.
The classifier itself runs against the (in-memory) model; persistence/display of
the evidence it cites is already redacted.
"""

from __future__ import annotations

from ..model.evidence import Evidence
from . import applicability
from .models import (
    ClassificationBasis,
    ControlDef,
    Finding,
    Logic,
    Status,
)
from .predicates import Ctx, evaluate
from .profiles import ProfileOverlay, apply_overlay


def _evaluate_logic(logic: Logic, ctx: Ctx) -> tuple[Status, list[str]]:
    when_clauses = [c for c in logic.clauses if c.when is not None]
    else_clause = next((c for c in logic.clauses if c.when is None), None)
    fallback = (else_clause.else_ or else_clause.then) if else_clause else Status.FAIL
    matched: list[str] = []

    if logic.type == "all_of":
        if not when_clauses:
            return fallback, matched  # nothing to satisfy -> honor the else
        for c in when_clauses:
            ok, m = evaluate(c.when, ctx)
            matched += m
            if not ok:
                return fallback, matched
        return (when_clauses[-1].then or Status.PASS), matched

    # first_match (and 'any_of', which for the typical all-pass-clauses + else-fail
    # pattern is equivalent: the first matching clause's `then` is returned).
    for c in when_clauses:
        ok, m = evaluate(c.when, ctx)
        if ok:
            return (c.then or Status.PASS), m
        matched += m
    return fallback, matched


def _evidence(control: ControlDef, model) -> tuple[Evidence, dict[str, str]]:
    ev_map = {spec.key: spec.command for spec in control.evidence}
    commands = [spec.command for spec in control.evidence]
    results = [model.result_for_command(c) for c in commands]
    raw_refs = [r.raw_ref for r in results if r and r.raw_ref]
    masked = any(bool(r and r.redaction_count) for r in results)
    node_ctx = model.identity.role.value if model.identity and model.identity.role else None
    return (
        Evidence(commands=commands, matched=[], raw_refs=raw_refs, masked=masked, node_context=node_ctx),
        ev_map,
    )


def classify(
    control: ControlDef,
    model,
    facts: dict,
    *,
    active_profile: str = "high_security",
    attestations: dict | None = None,
    overlay: ProfileOverlay | None = None,
) -> Finding:
    attestations = attestations or {}
    overlay = overlay or ProfileOverlay(name=active_profile)
    evidence, ev_map = _evidence(control, model)

    def _finalize(f: Finding) -> Finding:
        return apply_overlay(f, overlay)

    def _base(status: Status, basis: ClassificationBasis, **kw) -> Finding:
        return Finding(
            control_id=control.id,
            title=control.title,
            category=control.category,
            status=status,
            severity=control.severity,
            source=control.source,
            classification_basis=basis,
            evidence=evidence,
            remediation_hint=control.remediation_hint,
            references=control.references,
            **kw,
        )

    # 1. applicability gate
    gate = applicability.resolve(control, model, facts, active_profile)
    if gate is not None:
        f = _base(gate.status, gate.basis, reason=gate.reason,
                  applicability_resolved=(gate.status != Status.NOT_APPLICABLE))
        return _finalize(f)

    # 2. attestation-only control (no machine logic)
    if control.logic is None:
        att = attestations.get(control.id)
        if att:
            f = _base(Status(att.get("status", "manual")), ClassificationBasis.ATTESTATION,
                      notes=att.get("justification"))
        else:
            f = _base(Status.MANUAL, ClassificationBasis.ATTESTATION,
                      reason="requires operator attestation")
        return _finalize(f)

    # 3. machine logic
    def source_text(name: str) -> str:
        if name == "fact":
            return ""
        if name == "running_config":
            return model.running_config_text  # sanitized: banner bodies collapsed
        if name in ev_map:
            r = model.result_for_command(ev_map[name])
            if r and r.usable:
                return r.redacted_output
        return model.text_for(name)

    # Isolate a malformed control (bad regex / predicate arg) to a Status.ERROR
    # finding so one bad control never aborts the whole audit.
    try:
        status, matched = _evaluate_logic(control.logic, Ctx(source_text=source_text, facts=facts))
    except Exception as e:  # noqa: BLE001 - intentional containment boundary
        return _finalize(_base(Status.ERROR, ClassificationBasis.MACHINE,
                               reason=f"control logic error: {type(e).__name__}: {e}"))
    evidence.matched = matched[:8]
    f = _base(status, ClassificationBasis.MACHINE,
              observed=("; ".join(matched[:5]) if matched else None))

    # An operator attestation can resolve a machine-MANUAL outcome.
    if status == Status.MANUAL and control.id in attestations:
        att = attestations[control.id]
        f.status = Status(att.get("status", "manual"))
        f.classification_basis = ClassificationBasis.ATTESTATION
        f.notes = att.get("justification")

    return _finalize(f)
