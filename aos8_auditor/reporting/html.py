"""Self-contained HTML report (single portable file, inline CSS, no JS).

Built by hand with ``html.escape`` on every device-derived string — device
output is untrusted, so nothing is ever marked safe. Derived strictly from the
same :class:`Report` as the JSON/Markdown so the formats cannot disagree.
"""

from __future__ import annotations

from html import escape

from ..engine.models import Report, Severity, Status

_STATUS_ORDER = {
    Status.FAIL: 0, Status.WARN: 1, Status.PASS: 2,
    Status.ERROR: 3, Status.MANUAL: 4, Status.NOT_APPLICABLE: 5,
}
_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
              Severity.LOW: 3, Severity.MANUAL: 4, Severity.INFORMATIONAL: 5}
_COLOR = {
    Status.FAIL: "#c0392b", Status.WARN: "#d68910", Status.PASS: "#1e8449",
    Status.ERROR: "#8e44ad", Status.MANUAL: "#555", Status.NOT_APPLICABLE: "#999",
}
_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#222;line-height:1.45}
h1{margin-bottom:.2rem} .meta{color:#555;font-size:.9rem}
table{border-collapse:collapse;margin:1rem 0} td,th{border:1px solid #ccc;padding:4px 10px;text-align:center}
.badge{color:#fff;border-radius:3px;padding:1px 7px;font-size:.78rem;font-weight:600}
.score{font-size:2rem;font-weight:700}
.finding{margin:.35rem 0;padding:.4rem .6rem;border-left:4px solid #ccc;background:#fafafa}
.finding code{background:#eee;padding:0 4px;border-radius:3px}
.sub{color:#555;font-size:.86rem;margin-left:1.5rem}
.supp{opacity:.6;text-decoration:line-through}
details{margin-top:1rem} summary{cursor:pointer;font-weight:600}
"""


def _badge(status: Status) -> str:
    return f'<span class="badge" style="background:{_COLOR[status]}">{escape(status.value.upper())}</span>'


def _finding_html(f) -> str:
    cls = "finding supp" if f.suppressed else "finding"
    parts = [f'<div class="{cls}" style="border-left-color:{_COLOR[f.status]}">']
    parts.append(f'{_badge(f.status)} <code>{escape(f.control_id)}</code> '
                 f'<b>{escape(f.title)}</b> <span class="meta">({escape(f.severity.value)})</span>')
    for label, val in (("reason", f.reason), ("observed", f.observed),
                       ("notes", f.notes), ("suppressed", f.suppression_reason)):
        if val:
            parts.append(f'<div class="sub">{label}: {escape(str(val))}</div>')
    if f.status in (Status.FAIL, Status.WARN) and f.remediation_hint:
        parts.append(f'<div class="sub">remediation: {escape(f.remediation_hint)}</div>')
    if f.status in (Status.FAIL, Status.WARN) and f.impact:
        imp = f.impact
        tags = []
        if imp.reboot_required:
            tags.append("REBOOT/outage")
        if imp.client_impact:
            tags.append("clients reauth")
        if imp.ap_impact:
            tags.append("AP reboot")
        tag = f" ({'; '.join(tags)})" if tags else ""
        parts.append(f'<div class="sub">change impact: <b>{escape(imp.level.value)}</b>{escape(tag)}'
                     + (f' — {escape(imp.detail)}' if imp.detail else "") + "</div>")
    if f.evidence and f.evidence.commands:
        cmds = ", ".join(escape(c) for c in f.evidence.commands)
        masked = " (redacted)" if f.evidence.masked else ""
        parts.append(f'<div class="sub">evidence: {cmds}{escape(masked)}</div>')
    parts.append("</div>")
    return "".join(parts)


_USAGE_LABEL = {"in_use": "in use", "not_needed": "not needed here", "unknown": "unknown"}
_GUIDANCE_LABEL = {
    "do_not_block": "do NOT block",
    "restrict": "restrict source",
    "block_if_unused": "block if unused",
    "safe_to_block": "safe to block",
    "see_notes": "see notes",
}
_PORT_HEAD = ("<table><tr><th>Port</th><th>Proto</th><th>Guidance</th>"
              "<th>Service state</th><th>Purpose</th></tr>")


def _port_row_html(e) -> str:
    guidance = _GUIDANCE_LABEL.get(e.guidance.value, e.guidance.value)
    if e.blockable:
        guidance = f"<b>{escape(guidance)} ✓</b>"
    else:
        guidance = escape(guidance)
    return ("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td style='text-align:left'>{}</td></tr>".format(
        escape(e.port), escape(e.transport or "—"), guidance,
        escape(_USAGE_LABEL.get(e.usage.value, e.usage.value)), escape(e.purpose or "")))


def _port_exposure_html(report: Report) -> list[str]:
    """Open-port reference section. Reference data only — never scored, never probed."""
    pe = report.port_exposure
    if pe is None or not (pe.controller_ports or pe.access_point_ports):
        return []
    c = pe.counts
    h = ["<details><summary>Open ports and control-plane exposure — reference "
         f"({c.get('controller_ports', 0)} controller · {c.get('access_point_ports', 0)} AP · "
         f"{c.get('control_plane_protocols', 0)} protocols)</summary>"]
    h.append("<div class='meta'>Documented open ports from the ArubaOS 8 Controller Hardening Guide "
             "(p.9-14, p.14, p.30-53), joined against this controller's configuration. "
             "<b>Nothing here is scored and no port is probed</b> — the auditor never scans. "
             "&ldquo;not needed here&rdquo; means the config shows the service behind the port is "
             "unused, so the guide&rsquo;s conditional advice resolves to blockable (&check;). "
             "Verify against your own deployment before writing firewall rules.</div>")
    h.append(f"<p><b>Closeable on this controller: {c.get('blockable_here', 0)}</b> "
             f"<span class='meta'>(in use {c.get('in_use', 0)} · not needed {c.get('not_needed', 0)} "
             f"· undeterminable {c.get('unknown', 0)})</span></p>")
    blockable = [e for e in pe.controller_ports + pe.access_point_ports if e.blockable]
    for entries, title in ((blockable, "Closeable here"),
                           (pe.controller_ports, "All documented controller ports"),
                           (pe.access_point_ports, "All documented AP ports")):
        if not entries:
            continue
        h.append(f"<h4>{escape(title)}</h4>")
        h.append(_PORT_HEAD)
        h += [_port_row_html(e) for e in entries]
        h.append("</table>")
    if pe.control_plane_protocols:
        h.append("<h4>Control-plane firewall protocols</h4>")
        h.append("<div class='meta'>Traffic terminating on the controller itself, governed by "
                 "<code>firewall cp</code>. Default and example rules are in report.json.</div>")
        h.append("<table><tr><th>Protocol</th><th>Proto</th><th>Ports</th><th>Flows</th>"
                 "<th>Guidance</th></tr>")
        for p in pe.control_plane_protocols:
            ports = "–".join(str(x) for x in dict.fromkeys(p.ports)) or "—"
            h.append("<tr><td style='text-align:left'>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                escape(p.name), escape(str(p.transport or "—")), escape(ports),
                escape(p.flows or "—"), escape(_GUIDANCE_LABEL.get(p.guidance.value, p.guidance.value))))
        h.append("</table>")
    h.append("</details>")
    return h


_VERDICT_LABEL = {
    "false_positive": ("false positive — does not apply to ArubaOS", "#1e8449"),
    "action_required": ("ACTION REQUIRED — this finding is real", "#c0392b"),
    "accepted_risk": ("accepted risk — unfixable; vendor judged the risk low", "#d68910"),
    "by_design": ("by design — intentional tradeoff or standards mandate", "#555"),
    "unknown": ("NOT IN THE CORPUS — triage this yourself", "#8e44ad"),
}


def _verdict_html(verdict: str) -> str:
    label, color = _VERDICT_LABEL.get(verdict, (verdict, "#555"))
    return f'<span class="badge" style="background:{color}">{escape(label)}</span>'


def _scanner_html(report: Report) -> list[str]:
    """Scanner false-positive corpus. Reference data — never scored, never suppresses."""
    st = report.scanner_triage
    if st is None or not st.corpus:
        return []
    c = st.counts
    h = ["<details><summary>Vulnerability-scanner findings — reference "
         f"({c.get('corpus_entries', 0)} services · {c.get('corpus_cves', 0)} CVEs)</summary>"]
    h.append("<div class='meta'>The ArubaOS 8 Controller Hardening Guide&rsquo;s "
             "<i>Common False Positives</i> table (rev 10, p.15-18), with the vendor&rsquo;s own "
             "position on each. <b>Nothing here is scored and nothing here suppresses a "
             "control</b> — a match is context for a triage conversation, not a clean bill of "
             "health: the vendor&rsquo;s position is about ArubaOS as shipped, and this "
             "controller&rsquo;s version, licensed features and configuration still matter.</div>")
    if st.preamble:
        h.append(f"<div class='meta'>{escape(st.preamble)}</div>")

    if st.items:
        rank = {"action_required": 0, "unknown": 1, "accepted_risk": 2,
                "by_design": 3, "false_positive": 4}
        h.append(f"<h4>Submitted findings ({len(st.items)})</h4>")
        for i in sorted(st.items, key=lambda x: (rank.get(x.verdict.value, 9), x.finding)):
            h.append("<div class='finding'>")
            svc = f" <span class='meta'>({escape(i.service)})</span>" if i.service else ""
            h.append(f"<code>{escape(i.finding)}</code>{svc} {_verdict_html(i.verdict.value)}")
            if i.verdict.value == "unknown":
                h.append("<div class='sub'>not covered by the guide&rsquo;s table. Check the "
                         "current PSIRT advisories and the release notes for your ArubaOS train.</div>")
            verb = "fixes" if i.verdict.value == "action_required" else "closes"
            for cid in i.controls:
                status = i.control_status.get(cid)
                extra = f" — <b>this run: {escape(status)}</b>" if status else ""
                h.append(f"<div class='sub'>{verb} the finding: <code>{escape(cid)}</code>{extra}</div>")
            h.append("</div>")

    h.append("<h4>Corpus</h4>")
    for n in st.corpus:
        h.append("<div class='finding'>")
        h.append(f"<b>{escape(n.service)}</b> <span class='meta'>(p.{n.page})</span> "
                 f"{_verdict_html(n.verdict.value)}")
        if n.cves:
            h.append(f"<div class='sub'>CVEs: {escape(', '.join(n.cves))}</div>")
        if n.vendor_position:
            h.append(f"<div class='sub'>vendor position: {escape(n.vendor_position)}</div>")
        for cid in n.remediating_controls:
            h.append(f"<div class='sub'>fixed by: <code>{escape(cid)}</code></div>")
        for cid in n.mitigating_controls:
            h.append(f"<div class='sub'>closed by: <code>{escape(cid)}</code></div>")
        h.append("</div>")
    h.append("</details>")
    return h


def render_html(report: Report) -> str:
    m, s = report.run_metadata, report.summary
    h: list[str] = ["<!doctype html><html><head><meta charset='utf-8'>",
                    f"<title>AOS8 Audit {escape(m.target.get('host', ''))}</title>",
                    f"<style>{_CSS}</style></head><body>"]
    h.append(f"<h1>ArubaOS 8 Hardening Audit — {escape(m.target.get('host', 'unknown'))}</h1>")
    h.append(f"<div class='meta'>run {escape(m.run_id)} · profile <b>{escape(str(m.profile))}</b> · "
             f"{escape(str(m.target.get('model')))} / AOS {escape(str(m.target.get('aos_version')))} / "
             f"role {escape(str(m.target.get('role')))} · redaction {'on' if m.redaction_applied else 'OFF'}</div>")
    if s.posture_score is not None:
        h.append(f"<p class='score'>{s.posture_score}/100</p>")
    if s.fips_gate:
        h.append(f"<p><b>FIPS gate:</b> {'FAILED' if s.fips_gate_failed else 'passed'}</p>")

    h.append("<table><tr><th>Severity</th><th>fail</th><th>warn</th><th>pass</th>"
             "<th>manual</th><th>n/a</th><th>error</th></tr>")
    for sev in ("critical", "high", "medium", "low", "manual", "informational"):
        row = s.matrix.get(sev)
        if not row:
            continue
        h.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            escape(sev), row.get("fail", 0), row.get("warn", 0), row.get("pass", 0),
            row.get("manual", 0), row.get("not_applicable", 0), row.get("error", 0)))
    h.append("</table>")

    for w in m.suppression_warnings:
        h.append(f"<div class='meta'>⚠ {escape(w)}</div>")

    actionable = [f for f in report.results if f.status in (Status.FAIL, Status.WARN) and not f.suppressed]
    other = [f for f in report.results if f not in actionable]

    def _section(findings, title, open_=True):
        if not findings:
            return
        findings = sorted(findings, key=lambda f: (
            _STATUS_ORDER.get(f.status, 9), _SEV_ORDER.get(f.severity, 9), f.control_id))
        h.append(f"<details {'open' if open_ else ''}><summary>{escape(title)} ({len(findings)})</summary>")
        for f in findings:
            h.append(_finding_html(f))
        h.append("</details>")

    _section(actionable, "Actionable findings (fail / warn)", True)
    _section(other, "Manual / not-applicable / suppressed / informational", False)
    h += _port_exposure_html(report)
    h += _scanner_html(report)
    h.append("</body></html>")
    return "".join(h)
