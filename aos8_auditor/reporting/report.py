"""Render and persist a :class:`Report` as JSON (source of truth) + Markdown.

JSON is deterministic (stable key order) so two runs over identical evidence diff
cleanly. Markdown groups findings by category, fails-first, and quarantines
manual/not_applicable/error so the reader's eye goes to what's actionable.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..engine.models import DisruptionLevel, Report, Severity, Status

_BACKTICKS = re.compile(r"`+")


def _md_code(value) -> str:
    """A markdown code span that untrusted text cannot break out of.

    A span ends at the next run of exactly as many backticks as opened it, so
    fencing with one more than the longest run inside the value contains any
    number of them. The padding spaces are stripped by the renderer and are
    only needed when the value itself starts or ends with a backtick; newlines
    would end the span outright, so whitespace is collapsed first.
    """
    text = " ".join(str(value).split())
    fence = "`" * (max((len(m) for m in _BACKTICKS.findall(text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _md_text(value) -> str:
    """Escape untrusted text rendered outside a code span.

    Device output reaches the report verbatim (post-redaction), and markdown
    passes raw inline HTML through to any renderer that allows it — so a config
    value containing a tag would execute when report.md is published to a wiki.
    Neutralising '<' and '&' closes that; markdown's emphasis characters are
    left alone, since mangling them corrupts real config text for no gain.
    """
    return str(value).replace("&", "&amp;").replace("<", "&lt;")


_STATUS_ORDER = {
    Status.FAIL: 0, Status.WARN: 1, Status.PASS: 2,
    Status.ERROR: 3, Status.MANUAL: 4, Status.NOT_APPLICABLE: 5,
}
_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
              Severity.LOW: 3, Severity.MANUAL: 4, Severity.INFORMATIONAL: 5}
_BADGE = {
    Status.PASS: "PASS", Status.FAIL: "FAIL", Status.WARN: "WARN",
    Status.MANUAL: "MANUAL", Status.NOT_APPLICABLE: "N/A", Status.ERROR: "ERROR",
}


def _impact_label(impact) -> str:
    if impact is None:
        return ""
    tags = []
    if impact.reboot_required:
        tags.append("REBOOT/outage")
    if impact.client_impact:
        tags.append("wireless clients reauth")
    if impact.ap_impact:
        tags.append("AP reboot")
    tag = f" ({'; '.join(tags)})" if tags else ""
    return f"{impact.level.value}{tag}" + (f" — {impact.detail}" if impact.detail else "")


_SEV_LABEL_ORDER = ["critical", "high", "medium", "low"]


def _sev_phrase(severity_counts: dict) -> str:
    """'14 critical, 13 high (heuristic)' from a severity_counts map; '' if empty."""
    parts = [f"{severity_counts[s]} {s}" for s in _SEV_LABEL_ORDER if severity_counts.get(s)]
    return (", ".join(parts) + " — severity heuristic") if parts else ""


def advisory_justification(adv) -> str:
    """The 'applying this prevents N vulnerabilities since YYYY' line for an
    advisory finding (computed wholly from the corpus counts on `adv`)."""
    if adv is None or adv.cve_count == 0:
        return ""
    span = (f"since {adv.year_min}" if adv.year_min == adv.year_max
            else f"{adv.year_min}–{adv.year_max}") if adv.year_min else ""
    sev = _sev_phrase(adv.severity_counts)
    bits = [f"prevents exploitation of **{adv.cve_count} CVE(s)**"]
    if sev:
        bits.append(f"({sev})")
    bits.append(f"across {len(adv.advisories)} advisor{'y' if len(adv.advisories) == 1 else 'ies'}")
    if span:
        bits.append(span)
    return " ".join(bits)


def advisory_rollup(advisory_findings) -> dict:
    """Aggregate, de-duplicated CVE coverage across advisory findings.

    A CVE mitigated by any APPLIED (pass) config workaround is counted as
    mitigated and never double-counted as exposed. `exposed` is the set whose
    workaround is not applied on this device (the actionable population)."""
    mitigated: set[str] = set()
    exposed: set[str] = set()
    needs_verify: set[str] = set()
    patch_only: set[str] = set()
    all_cves: set[str] = set()
    for f in advisory_findings:
        adv = f.advisory
        if not adv:
            continue
        cves = set(adv.cves)
        all_cves |= cves
        if f.control_id == "ADV-PATCH-ONLY":
            patch_only |= cves
            continue
        if not adv.config_workaround:
            needs_verify |= cves
        elif f.status == Status.PASS:
            mitigated |= cves
        elif f.status in (Status.FAIL, Status.WARN):
            exposed |= cves
        else:  # manual / not_applicable / error
            needs_verify |= cves
    exposed -= mitigated
    needs_verify -= (mitigated | exposed)
    config_universe = all_cves - patch_only
    return {
        "total_cves": len(all_cves),
        "config_mitigable": len(config_universe),
        "mitigated": len(mitigated),
        "exposed": len(exposed),
        "needs_verify": len(needs_verify),
        "patch_only": len(patch_only),
        "exposed_cves": sorted(exposed),
    }


def render_advisory_section(report) -> list[str]:
    """Markdown lines for the advisory (vulnerability-exploitation-prevention)
    block; empty when the run had no advisory checks."""
    findings = report.advisory_results
    if not findings:
        return []
    o: list[str] = []
    cat = report.run_metadata.advisory_catalog_version
    o.append("## Vulnerability exploitation prevention (PSIRT advisories)")
    o.append("")
    o.append("Configuration workarounds from published HPE Aruba Networking security advisories, "
             "clustered by mitigation. Each is framed as *what enabling it prevents*. CVE counts and "
             "year ranges are taken from the advisory corpus; **severity is a heuristic** derived from "
             "each vulnerability's title (the corpus carries no CVSS).")
    if cat:
        o.append(f"> Advisory catalog: `{cat}`")
    o.append("")

    roll = advisory_rollup(findings)
    o.append(f"**Coverage:** {roll['total_cves']} CVEs in scope — "
             f"{roll['config_mitigable']} have a configuration workaround "
             f"({roll['patch_only']} are patch/upgrade-only). "
             f"On this device: **{roll['exposed']} exposed** (workaround not applied), "
             f"{roll['mitigated']} already mitigated, {roll['needs_verify']} need manual verification.")
    o.append("")

    # Actionable advisory items first (workaround not applied), then applied/manual.
    actionable = [f for f in findings
                  if f.status in (Status.FAIL, Status.WARN) and not f.suppressed]
    other = [f for f in findings if f not in actionable]

    def _emit_adv(items, title):
        if not items:
            return
        o.append(f"### {title}")
        items = sorted(items, key=lambda f: (
            -(f.advisory.cve_count if f.advisory else 0), f.control_id))
        for f in items:
            just = advisory_justification(f.advisory)
            o.append(f"- **[{_BADGE[f.status]}]** `{f.control_id}` — {f.title}")
            if just:
                verb = "Applying this" if f.status in (Status.FAIL, Status.WARN, Status.MANUAL) else "This"
                o.append(f"  - {verb} {just}.")
            if f.status in (Status.FAIL, Status.WARN, Status.MANUAL) and f.remediation_hint:
                o.append(f"  - remediation: {f.remediation_hint}")
            if f.status in (Status.FAIL, Status.WARN) and f.impact:
                o.append(f"  - change impact: {_impact_label(f.impact)}")
            if f.reason:
                o.append(f"  - reason: {_md_text(f.reason)}")
            if f.advisory and f.advisory.cves:
                shown = ", ".join(f.advisory.cves[:12])
                more = f" … (+{len(f.advisory.cves) - 12} more)" if len(f.advisory.cves) > 12 else ""
                o.append(f"  - CVEs: {shown}{more}")
            if f.advisory and f.advisory.advisories:
                o.append(f"  - advisories: {', '.join(f.advisory.advisories)}")
        o.append("")

    _emit_adv(actionable, "Workarounds not yet applied (actionable)")
    _emit_adv(other, "Already applied / manual verification")
    return o


_USAGE_LABEL = {"in_use": "in use", "not_needed": "not needed here", "unknown": "unknown"}
_GUIDANCE_LABEL = {
    "do_not_block": "do NOT block",
    "restrict": "restrict source",
    "block_if_unused": "block if unused",
    "safe_to_block": "safe to block",
    "see_notes": "see notes",
}


def _port_row(e) -> str:
    purpose = (e.purpose or "").replace("|", "/").replace("\n", " ")
    if len(purpose) > 110:
        purpose = purpose[:107].rstrip() + "…"
    mark = " **✓**" if e.blockable else ""
    return (f"| {e.port} | {e.transport or '—'} | {_GUIDANCE_LABEL.get(e.guidance.value, e.guidance.value)}{mark} "
            f"| {_USAGE_LABEL.get(e.usage.value, e.usage.value)} | {purpose} |")


def render_port_section(report: Report) -> list[str]:
    """Markdown for the open-port / control-plane reference; empty when absent.

    This section is REFERENCE DATA and is never scored. No port is probed — the
    auditor only ever runs ``show`` commands. "not needed here" means the audit
    facts say the service behind the port is not configured on this controller,
    so the guide's conditional "may be blocked if X is not in use" resolves.
    """
    pe = report.port_exposure
    if pe is None or not (pe.controller_ports or pe.access_point_ports):
        return []
    c = pe.counts
    o: list[str] = []
    o.append("## Open ports and control-plane exposure (reference)")
    o.append("")
    o.append("Documented open ports from the ArubaOS 8 Controller Hardening Guide "
             "(*Controller Open Ports* p.9-14, *Access Point Open Ports* p.14, *Aruba Core "
             "Protocols & Ports* p.30-53), joined against this controller's configuration. "
             "**Nothing here is scored and nothing is probed** — the auditor never scans; "
             "\"not needed here\" means the config shows the service behind the port is unused, "
             "so the guide's conditional advice resolves to *blockable*.")
    o.append("")
    o.append(f"**Documented:** {c.get('controller_ports', 0)} controller ports · "
             f"{c.get('access_point_ports', 0)} AP ports · "
             f"{c.get('control_plane_protocols', 0)} control-plane protocols.  "
             f"**Closeable on this controller (✓): {c.get('blockable_here', 0)}**  "
             f"(in use: {c.get('in_use', 0)} · not needed: {c.get('not_needed', 0)} · "
             f"undeterminable: {c.get('unknown', 0)})")
    o.append("")

    blockable = [e for e in pe.controller_ports + pe.access_point_ports if e.blockable]
    if blockable:
        o.append("### Closeable here — the guide permits blocking these given this configuration")
        o.append("")
        o.append("| Port | Proto | Guidance | Service state | Purpose |")
        o.append("|---|---|---|---|---|")
        o += [_port_row(e) for e in blockable]
        o.append("")
        o.append("> Verify against your own deployment before writing firewall rules: the audit "
                 "reads this controller's config only, and an upstream device or a feature enabled "
                 "elsewhere in the cluster can still need a port this controller does not.")
        o.append("")

    for entries, title in ((pe.controller_ports, "All documented controller ports"),
                           (pe.access_point_ports, "All documented AP ports")):
        if not entries:
            continue
        o.append(f"### {title}")
        o.append("")
        o.append("| Port | Proto | Guidance | Service state | Purpose |")
        o.append("|---|---|---|---|---|")
        o += [_port_row(e) for e in entries]
        o.append("")

    if pe.control_plane_protocols:
        o.append("### Control-plane firewall protocols")
        o.append("")
        o.append("Traffic terminating on the controller itself, governed by `firewall cp`. "
                 "The guide's default and example rules for each are in `report.json`.")
        o.append("")
        o.append("| Protocol | Proto | Ports | Flows | Guidance |")
        o.append("|---|---|---|---|---|")
        for p in pe.control_plane_protocols:
            ports = "–".join(str(x) for x in dict.fromkeys(p.ports)) or "—"
            o.append(f"| {p.name} | {p.transport or '—'} | {ports} | {p.flows or '—'} "
                     f"| {_GUIDANCE_LABEL.get(p.guidance.value, p.guidance.value)} |")
        o.append("")
    return o


_VERDICT_LABEL = {
    "false_positive": "FALSE POSITIVE — does not apply to ArubaOS",
    "action_required": "**ACTION REQUIRED — this finding is real**",
    "accepted_risk": "ACCEPTED RISK — unfixable; vendor judged the risk low",
    "by_design": "BY DESIGN — intentional tradeoff or standards mandate",
    "unknown": "**NOT IN THE CORPUS — triage this yourself**",
}


def render_scanner_section(report: Report) -> list[str]:
    """Markdown for the scanner false-positive corpus and any submitted findings.

    Reference data: nothing here is scored and nothing here suppresses a control.
    """
    st = report.scanner_triage
    if st is None or not st.corpus:
        return []
    o: list[str] = []
    o.append("## Vulnerability-scanner findings (reference)")
    o.append("")
    o.append("The ArubaOS 8 Controller Hardening Guide's *Common False Positives* table "
             "(rev 10, p.15-18), with the vendor's own position on each. "
             "**Nothing here is scored and nothing here suppresses a control** — a match "
             "is context for a triage conversation, not a clean bill of health: the "
             "vendor's position is about ArubaOS as shipped, and this controller's "
             "version, licensed features and configuration still matter.")
    o.append("")
    if st.preamble:
        o.append(f"> {st.preamble}")
        o.append("")
    c = st.counts
    o.append(f"**Corpus:** {c.get('corpus_entries', 0)} services · "
             f"{c.get('corpus_cves', 0)} CVEs"
             + (f" · catalog `{st.version}`" if st.version else ""))
    o.append("")

    if st.items:
        o.append(f"### Submitted findings ({len(st.items)})")
        o.append("")
        # Anything that is NOT a dismissible false positive goes first.
        rank = {"action_required": 0, "unknown": 1, "accepted_risk": 2,
                "by_design": 3, "false_positive": 4}
        for i in sorted(st.items, key=lambda x: (rank.get(x.verdict.value, 9), x.finding)):
            label = _VERDICT_LABEL.get(i.verdict.value, i.verdict.value)
            svc = f" — {i.service}" if i.service else ""
            o.append(f"- {_md_code(i.finding)}{svc} → {label}")
            if i.verdict.value == "unknown":
                o.append("  - not covered by the guide's table. Check the current PSIRT "
                         "advisories and the release notes for your ArubaOS train.")
            verb = "fixes" if i.verdict.value == "action_required" else "closes"
            for cid in i.controls:
                status = i.control_status.get(cid)
                o.append(f"  - {verb} the finding: `{cid}`"
                         + (f" — **this run: {status}**" if status else ""))
        o.append("")

    o.append("### Corpus")
    o.append("")
    for n in st.corpus:
        label = _VERDICT_LABEL.get(n.verdict.value, n.verdict.value)
        o.append(f"- **{n.service}** (p.{n.page}) — {label}")
        if n.cves:
            shown = ", ".join(n.cves[:12])
            more = f" … (+{len(n.cves) - 12} more)" if len(n.cves) > 12 else ""
            o.append(f"  - CVEs: {shown}{more}")
        if n.vendor_position:
            o.append(f"  - vendor position: {n.vendor_position}")
        for cid in n.remediating_controls:
            o.append(f"  - fixed by: `{cid}`")
        for cid in n.mitigating_controls:
            o.append(f"  - closed by: `{cid}`")
    o.append("")
    return o


def impact_rollup(findings) -> dict:
    """Aggregate remediation disruption across the actionable (fail/warn) findings."""
    actionable = [f for f in findings if f.status in (Status.FAIL, Status.WARN) and not f.suppressed]
    by_level: dict[str, int] = {}
    reboot, client, ap, high = [], [], [], []
    for f in actionable:
        imp = f.impact
        if imp is None:
            continue
        by_level[imp.level.value] = by_level.get(imp.level.value, 0) + 1
        if imp.reboot_required:
            reboot.append(f.control_id)
        if imp.client_impact:
            client.append(f.control_id)
        if imp.ap_impact:
            ap.append(f.control_id)
        # Surface every HIGH-disruption fix by LEVEL, not just by the granular
        # flags: some high-impact controls (e.g. physical install/mount, or an
        # L2-loop risk) cause a full outage without setting reboot/client/ap, so
        # keying only off the flags would hide them from the summary.
        if imp.level == DisruptionLevel.HIGH:
            high.append(f.control_id)
    return {"by_level": by_level, "reboot_required": reboot,
            "client_impact": client, "ap_impact": ap, "high_impact": high,
            "actionable": len(actionable)}


def render_markdown(report: Report) -> str:
    m = report.run_metadata
    s = report.summary
    out: list[str] = []
    out.append(f"# ArubaOS 8 Hardening Audit — {_md_text(m.target.get('host', 'unknown'))}")
    out.append("")
    out.append(f"- **Run:** `{m.run_id}`  ·  **Profile:** `{m.profile}`  ·  **Tool:** {m.tool_version}")
    out.append(f"- **Target:** {_md_text(m.target.get('model'))} "
               f"/ AOS {_md_text(m.target.get('aos_version'))} "
               f"/ role {_md_code(m.target.get('role'))}")
    out.append(f"- **Controls content:** `{m.controls_content_version}`  ·  **Redaction:** "
               f"{'on' if m.redaction_applied else 'OFF'}")
    if s.posture_score is not None:
        out.append(f"- **Posture score:** **{s.posture_score}/100**  "
                   f"(worst failed severity: {s.worst_severity_failed.value if s.worst_severity_failed else 'none'})")
    if s.fips_gate:
        out.append(f"- **FIPS gate:** {'FAILED' if s.fips_gate_failed else 'passed'}")
    out.append("")

    # counts line
    counts = s.counts
    out.append("**Results:** " + "  ".join(
        f"{k}={counts.get(k, 0)}" for k in ("fail", "warn", "pass", "manual", "not_applicable", "error")
    ))
    out.append("")

    # severity x status matrix
    out.append("| Severity | fail | warn | pass | manual | n/a | error |")
    out.append("|---|---|---|---|---|---|---|")
    for sev in ("critical", "high", "medium", "low", "manual", "informational"):
        row = s.matrix.get(sev)
        if not row:
            continue
        out.append(f"| {sev} | {row.get('fail',0)} | {row.get('warn',0)} | {row.get('pass',0)} "
                   f"| {row.get('manual',0)} | {row.get('not_applicable',0)} | {row.get('error',0)} |")
    out.append("")

    # Remediation change-impact rollup (how disruptive is fixing the findings).
    roll = impact_rollup(report.results)
    if roll["actionable"]:
        out.append("**Remediation change impact** (applying fixes for the "
                   f"{roll['actionable']} fail/warn findings — the audit itself is read-only):")
        out.append("  " + "  ".join(f"{k}={v}" for k, v in sorted(roll["by_level"].items())))
        if roll["reboot_required"]:
            out.append(f"  - ⚠ **controller reboot / outage required:** {', '.join(roll['reboot_required'])}")
        # High-disruption fixes that DON'T set reboot_required (e.g. physical
        # power-down, or an L2-loop risk) would otherwise be invisible here.
        other_high = [cid for cid in roll["high_impact"] if cid not in roll["reboot_required"]]
        if other_high:
            out.append(f"  - ⚠ **high disruption — full outage possible (plan a maintenance window):** {', '.join(other_high)}")
        if roll["client_impact"]:
            out.append(f"  - wireless clients reauthenticate: {', '.join(roll['client_impact'])}")
        if roll["ap_impact"]:
            out.append(f"  - AP reboot(s): {', '.join(roll['ap_impact'])}")
        out.append("")

    actionable = [f for f in report.results
                  if f.status in (Status.FAIL, Status.WARN) and not f.suppressed]
    informational = [f for f in report.results if f not in actionable]
    for w in report.run_metadata.suppression_warnings:
        out.append(f"> ⚠ {w}")
    if report.run_metadata.suppression_warnings:
        out.append("")

    def _emit(findings, title):
        if not findings:
            return
        out.append(f"## {title}")
        out.append("")
        findings = sorted(findings, key=lambda f: (
            _STATUS_ORDER.get(f.status, 9), _SEV_ORDER.get(f.severity, 9), f.control_id))
        cat = None
        for f in findings:
            if f.category != cat:
                cat = f.category
                out.append(f"### {cat}")
            out.append(f"- **[{_BADGE[f.status]}]** `{f.control_id}` ({f.severity.value}) — {f.title}")
            if f.reason:
                out.append(f"  - reason: {_md_text(f.reason)}")
            if f.observed:
                out.append(f"  - observed: {_md_text(f.observed)}")
            if f.notes:
                out.append(f"  - notes: {_md_text(f.notes)}")
            if f.status in (Status.FAIL, Status.WARN) and f.remediation_hint:
                out.append(f"  - remediation: {f.remediation_hint}")
            if f.status in (Status.FAIL, Status.WARN) and f.impact:
                out.append(f"  - change impact: {_impact_label(f.impact)}")
            if f.evidence and f.evidence.commands:
                masked = " (redacted)" if f.evidence.masked else ""
                out.append(f"  - evidence: {', '.join(f'`{c}`' for c in f.evidence.commands)}{masked}")
        out.append("")

    _emit(actionable, "Actionable findings (fail / warn)")
    _emit(informational, "Manual review / not-applicable / informational")
    out += render_advisory_section(report)
    out += render_port_section(report)
    out += render_scanner_section(report)
    return "\n".join(out)


def write_report(report: Report, out_dir: str | Path) -> dict[str, Path]:
    from .html import render_html

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    html_path = out_dir / "report.html"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")
    return {"json": json_path, "markdown": md_path, "html": html_path}
