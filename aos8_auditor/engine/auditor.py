"""Audit orchestration: CollectionResult -> ControllerModel -> Findings -> Report.

This is the single seam the CLI and the advisory module call. It
is pure with respect to its inputs — given the same collection + controls +
profile + org_profile + attestations it produces the same Report, so a captured
bundle can be re-classified offline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from ..model.evidence import CollectionResult, ControllerIdentity, utcnow_iso
from ..parse.model_builder import build_controller_model
from .classifier import classify
from .loader import controls_content_version
from .models import AdvisoryPrevents, ControlDef, Report, RunMetadata
from .profiles import resolve_overlay
from .scoring import score
from .suppressions import Suppression, apply_suppressions


def audit(
    collection: CollectionResult,
    controls: list[ControlDef],
    *,
    tool_version: str,
    active_profile: str = "high_security",
    org_profile: dict | None = None,
    attestations: dict | None = None,
    suppressions: list[Suppression] | None = None,
    today: date | None = None,
    operator: str | None = None,
    node_path: str = "/",
    identity: ControllerIdentity | None = None,
    advisory_controls: list[ControlDef] | None = None,
    advisory_prevents: dict[str, AdvisoryPrevents] | None = None,
    advisory_catalog_version: str | None = None,
    scanner_findings: list[str] | None = None,
) -> Report:
    model = build_controller_model(collection, node_path=node_path, identity=identity)

    # Conditions read operator-declared intent (fips_required, stp_required, ...);
    # predicates read measured facts. Merge with org_profile intent taking
    # precedence so a declared intent is never shadowed by a measured fact.
    facts = {**model.facts, **(org_profile or {})}

    from .impact import impact_for

    overlay = resolve_overlay(active_profile)
    findings = []
    for c in controls:
        f = classify(c, model, facts, active_profile=active_profile,
                     attestations=attestations, overlay=overlay)
        f.impact = impact_for(c.id)  # remediation disruption rating
        findings.append(f)

    # Advisory (PSIRT) workaround controls evaluate into a SEPARATE result list and
    # never enter the hardening posture score. Each advisory finding carries the
    # `advisory` block (CVE count / years / advisories the workaround prevents).
    advisory_findings = []
    advisory_prevents = advisory_prevents or {}
    for c in advisory_controls or []:
        f = classify(c, model, facts, active_profile=active_profile,
                     attestations=attestations, overlay=overlay)
        f.impact = impact_for(c.id)
        f.advisory = advisory_prevents.get(c.id)
        advisory_findings.append(f)

    # Apply suppressions before scoring (suppressed findings are excluded).
    suppression_warnings: list[str] = []
    if suppressions:
        suppression_warnings = apply_suppressions(
            findings, suppressions, host=model.identity.host, today=today or date.today())

    summary = score(findings, active_profile=active_profile)
    ident = model.identity
    meta = RunMetadata(
        tool_version=tool_version,
        controls_content_version=controls_content_version(controls),
        run_id=collection.run_id,
        operator=operator,
        profile=active_profile,
        target={
            "host": ident.host,
            "model": ident.model,
            "platform_family": ident.platform_family,
            "aos_version": ident.aos_version,
            "serial": ident.serial,
            "role": ident.role.value if ident.role else None,
            "node_path": node_path,
        },
        commands_run=[r.command for r in collection.results],
        redaction_applied=collection.redaction_applied,
        suppression_warnings=suppression_warnings,
        advisory_catalog_version=advisory_catalog_version,
        finished_at=utcnow_iso(),
    )
    # Reference sections, neither of them scored: the guide's documented open
    # ports joined against this controller's facts (nothing is probed), and the
    # scanner false-positive corpus, triaging operator-supplied findings when
    # any were passed.
    from .open_ports import port_exposure
    from .scanner_fp import triage

    return Report(run_metadata=meta, summary=summary, results=findings,
                  advisory_results=advisory_findings,
                  port_exposure=port_exposure(facts),
                  scanner_triage=triage(scanner_findings, results=findings))


@dataclass
class NodeReport:
    node_path: str
    report: Report


def _node_identity(collection: CollectionResult, node_path: str, hint=None) -> ControllerIdentity:
    from ..transport.topology import detect_identity
    vr = next((r for r in collection.results
               if r.command == "show version" and r.node_path == node_path), None)
    vtext = vr.redacted_output if vr else ""
    host = collection.controller.host + ("" if node_path == "/" else f"{node_path}")
    ident = detect_identity(host=host, version_text=vtext, switchinfo_text="")
    if hint is not None:
        if not ident.model and hint.platform_hint:
            ident.model = hint.platform_hint
        if hint.role and hint.role.value != "unknown":
            ident.role = hint.role
    return ident


def audit_topology(collection: CollectionResult, controls: list[ControlDef], **kw) -> list[NodeReport]:
    """Audit every node present in the collection.

    Standalone / Master-Local collections have a single node ("/") and yield one
    report. A Mobility Master collection (results tagged with /md/<group>/<device>
    node paths) yields one report per managed node — each built from that node's
    effective config, with MM-global outputs (version, license) shared.
    """
    node_paths = sorted({r.node_path for r in collection.results if r.node_path})
    managed = [n for n in node_paths if n != "/"]
    if not managed:
        return [NodeReport("/", audit(collection, controls, **kw))]

    hint_by = {n.node_path: n for n in collection.nodes}
    reports: list[NodeReport] = []
    for np in managed:
        ident = _node_identity(collection, np, hint_by.get(np))
        reports.append(NodeReport(np, audit(collection, controls, node_path=np, identity=ident, **kw)))
    return reports
