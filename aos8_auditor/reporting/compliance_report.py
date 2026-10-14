"""Render a compliance crosswalk report (requirement -> mapped controls)."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from ..engine.compliance import ComplianceResult, ReqStatus
from ..engine.models import Report, Status
from .report import _impact_label

_BADGE = {
    ReqStatus.GAP: "GAP", ReqStatus.PARTIAL: "PARTIAL", ReqStatus.REVIEW: "REVIEW",
    ReqStatus.ACCEPTED: "ACCEPTED-RISK", ReqStatus.MET: "MET",
    ReqStatus.NOT_APPLICABLE: "N/A", ReqStatus.NOT_ASSESSED: "NOT-ASSESSED",
}
_COLOR = {
    ReqStatus.GAP: "#c0392b", ReqStatus.PARTIAL: "#d68910", ReqStatus.REVIEW: "#2471a3",
    ReqStatus.ACCEPTED: "#7d6608", ReqStatus.MET: "#1e8449",
    ReqStatus.NOT_APPLICABLE: "#999", ReqStatus.NOT_ASSESSED: "#666",
}


def _summary_line(cr: ComplianceResult) -> str:
    c = cr.counts
    return "  ".join(f"{k}={c.get(k, 0)}" for k in
                     ("gap", "partial", "review", "accepted", "met", "not_applicable", "not_assessed"))


def gap_change_impact(cr: ComplianceResult, report: Report) -> dict:
    """Aggregate remediation disruption across the distinct FAILING controls that
    must be fixed to close this framework's gaps."""
    by_id = {f.control_id: f for f in report.results}
    seen: set[str] = set()
    reboot, client, ap = [], [], []
    by_level: dict[str, int] = {}
    for r in cr.requirements:
        for cid, st in r.control_statuses.items():
            if st == Status.FAIL.value and cid not in seen:
                seen.add(cid)
                imp = getattr(by_id.get(cid), "impact", None)
                if imp is None:
                    continue
                by_level[imp.level.value] = by_level.get(imp.level.value, 0) + 1
                if imp.reboot_required:
                    reboot.append(cid)
                if imp.client_impact:
                    client.append(cid)
                if imp.ap_impact:
                    ap.append(cid)
    return {"controls": sorted(seen), "by_level": by_level, "reboot_required": sorted(reboot),
            "client_impact": sorted(client), "ap_impact": sorted(ap)}


def render_compliance_markdown(cr: ComplianceResult, report: Report) -> str:
    p = cr.pack
    by_id = {f.control_id: f for f in report.results}
    o: list[str] = []
    o.append(f"# {p.framework} — Compliance Crosswalk")
    if p.version:
        o.append(f"*Version {p.version}*")
    o.append("")
    o.append(f"- **Target:** {report.run_metadata.target.get('host')} "
             f"({report.run_metadata.target.get('model')}, AOS {report.run_metadata.target.get('aos_version')})")
    o.append(f"- **Profile:** `{report.run_metadata.profile}`  ·  **Run:** `{report.run_metadata.run_id}`")
    if cr.coverage_pct is not None:
        o.append(f"- **Coverage (controller WLAN slice):** **{cr.coverage_pct}%** of assessable requirements MET")
    o.append(f"- **Requirements:** {_summary_line(cr)}")
    o.append("")
    if p.disclaimer:
        o.append(f"> ⚠ **{p.disclaimer}**")
        o.append("")

    o.append("| Status | Requirement | Mapped controls |")
    o.append("|---|---|---|")
    for r in cr.requirements:
        ctls = ", ".join(f"`{cid}`={st}" for cid, st in r.control_statuses.items()) or "—"
        o.append(f"| **{_BADGE[r.status]}** | {r.requirement.id} — {r.requirement.title} | {ctls} |")
    o.append("")

    gaps = cr.gaps
    if gaps:
        gi = gap_change_impact(cr, report)
        o.append("## Gaps (failing controls to remediate)")
        o.append("")
        o.append(f"**Change impact to close these gaps** ({len(gi['controls'])} distinct controls): "
                 + "  ".join(f"{k}={v}" for k, v in sorted(gi["by_level"].items())))
        if gi["reboot_required"]:
            o.append(f"- ⚠ **controller reboot / outage required:** {', '.join(gi['reboot_required'])}")
        if gi["client_impact"]:
            o.append(f"- wireless clients reauthenticate: {', '.join(gi['client_impact'])}")
        if gi["ap_impact"]:
            o.append(f"- AP reboot(s): {', '.join(gi['ap_impact'])}")
        o.append("")
        for r in gaps:
            o.append(f"### {r.requirement.id} — {r.requirement.title}")
            for cid, st in r.control_statuses.items():
                if st == Status.FAIL.value:
                    f = by_id.get(cid)
                    hint = f" — {f.remediation_hint}" if (f and f.remediation_hint) else ""
                    o.append(f"- `{cid}` ({f.severity.value if f else '?'}){hint}")
                    if f and f.impact:
                        o.append(f"  - change impact: {_impact_label(f.impact)}")
            o.append("")
    missing = sorted({c for r in cr.requirements for c in r.missing_controls})
    if missing:
        o.append(f"> note: {len(missing)} mapped control id(s) not present in this run: "
                 + ", ".join(f"`{m}`" for m in missing[:20]))
    return "\n".join(o)


def render_compliance_html(cr: ComplianceResult, report: Report) -> str:
    p = cr.pack
    h = ["<!doctype html><html><head><meta charset='utf-8'>",
         f"<title>{escape(p.framework)} crosswalk</title>",
         "<style>body{font-family:-apple-system,Segoe UI,sans-serif;margin:2rem;color:#222}"
         "table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 9px}"
         ".b{color:#fff;border-radius:3px;padding:1px 6px;font-size:.78rem;font-weight:600}"
         "code{background:#eee;padding:0 3px;border-radius:3px}</style></head><body>"]
    h.append(f"<h1>{escape(p.framework)} — Compliance Crosswalk</h1>")
    if cr.coverage_pct is not None:
        h.append(f"<p><b>{cr.coverage_pct}%</b> of assessable requirements MET "
                 f"(controller WLAN slice) — profile <code>{escape(str(report.run_metadata.profile))}</code></p>")
    h.append(f"<p>{escape(_summary_line(cr))}</p>")
    if p.disclaimer:
        h.append(f"<p style='color:#7d6608'>⚠ {escape(p.disclaimer)}</p>")
    if cr.gaps:
        gi = gap_change_impact(cr, report)
        bits = "  ".join(f"{k}={v}" for k, v in sorted(gi["by_level"].items()))
        extra = []
        if gi["reboot_required"]:
            extra.append("⚠ reboot/outage: " + escape(", ".join(gi["reboot_required"])))
        if gi["client_impact"]:
            extra.append("clients reauth: " + str(len(gi["client_impact"])))
        if gi["ap_impact"]:
            extra.append("AP reboot: " + str(len(gi["ap_impact"])))
        h.append(f"<p><b>Change impact to close gaps</b> ({len(gi['controls'])} controls): {escape(bits)}"
                 + ("; " + "; ".join(extra) if extra else "") + "</p>")
    h.append("<table><tr><th>Status</th><th>Requirement</th><th>Mapped controls</th></tr>")
    for r in cr.requirements:
        badge = f"<span class='b' style='background:{_COLOR[r.status]}'>{_BADGE[r.status]}</span>"
        ctls = ", ".join(f"<code>{escape(cid)}</code>={escape(st)}" for cid, st in r.control_statuses.items()) or "—"
        h.append(f"<tr><td>{badge}</td><td>{escape(r.requirement.id)} — {escape(r.requirement.title)}</td><td>{ctls}</td></tr>")
    h.append("</table></body></html>")
    return "".join(h)


def compliance_json(cr: ComplianceResult, report: Report | None = None) -> dict:
    out = {
        "framework": cr.pack.framework,
        "version": cr.pack.version,
        "profile": cr.pack.profile,
        "disclaimer": cr.pack.disclaimer,
        "coverage_pct": cr.coverage_pct,
        "counts": cr.counts,
        "requirements": [
            {"id": r.requirement.id, "title": r.requirement.title, "status": r.status.value,
             "controls": r.control_statuses, "missing_controls": r.missing_controls}
            for r in cr.requirements
        ],
    }
    if report is not None:
        out["gap_change_impact"] = gap_change_impact(cr, report)
    return out


def write_compliance_report(cr: ComplianceResult, report: Report, out_dir: str | Path) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = f"compliance_{cr.pack.name}"
    paths = {
        "markdown": out_dir / f"{base}.md",
        "html": out_dir / f"{base}.html",
        "json": out_dir / f"{base}.json",
    }
    paths["markdown"].write_text(render_compliance_markdown(cr, report), encoding="utf-8")
    paths["html"].write_text(render_compliance_html(cr, report), encoding="utf-8")
    paths["json"].write_text(json.dumps(compliance_json(cr, report), indent=2), encoding="utf-8")
    return paths
