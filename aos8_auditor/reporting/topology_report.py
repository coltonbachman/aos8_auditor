"""Aggregate report for a Mobility Master (multi-node) audit.

Standalone / Master-Local audits write a single ``report.*`` (unchanged). A
Mobility Master audit writes one report per managed node under ``nodes/<slug>/``
plus a top-level aggregate that lists each node's posture and the controls
failing on one or more nodes.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from ..engine.auditor import NodeReport
from ..engine.models import Status
from .report import _impact_label, advisory_justification, advisory_rollup, write_report


def _slug(node_path: str) -> str:
    # Append a short hash of the FULL path so distinct node paths that normalize
    # to the same token (e.g. colon- vs dash-separated MACs) never collide.
    base = re.sub(r"[^A-Za-z0-9]+", "-", node_path).strip("-") or "root"
    h = hashlib.sha256(node_path.encode()).hexdigest()[:6]
    return f"{base}-{h}"


def _unsuppressed_counts(report) -> tuple[int, int]:
    fails = sum(1 for f in report.results if f.status == Status.FAIL and not f.suppressed)
    warns = sum(1 for f in report.results if f.status == Status.WARN and not f.suppressed)
    return fails, warns


def render_topology_markdown(node_reports: list[NodeReport]) -> str:
    host = node_reports[0].report.run_metadata.target.get("host", "Mobility Master") if node_reports else "?"
    host = re.sub(r"/md/.*$", "", host) or "Mobility Master"
    o: list[str] = [f"# ArubaOS 8 Hardening Audit — Mobility Master `{host}`", ""]
    o.append(f"{len(node_reports)} managed node(s) audited. Each node is evaluated against its own "
             "effective config (group inheritance resolved on-box); MM-global outputs are shared.")
    o.append("")
    o.append("| Node | Model | Role | Score | fail | warn | worst |")
    o.append("|---|---|---|---|---|---|---|")
    for nr in node_reports:
        t = nr.report.run_metadata.target
        s = nr.report.summary
        worst = s.worst_severity_failed.value if s.worst_severity_failed else "—"
        fails, warns = _unsuppressed_counts(nr.report)  # match the union section (excl. suppressed)
        o.append(f"| `{nr.node_path}` | {t.get('model')} | {t.get('role')} | "
                 f"{s.posture_score} | {fails} | {warns} | {worst} |")
    o.append("")

    # Union of controls failing on one or more nodes.
    union: dict[str, dict] = {}
    for nr in node_reports:
        for f in nr.report.results:
            if f.status == Status.FAIL and not f.suppressed:
                e = union.setdefault(f.control_id, {"sev": f.severity.value, "nodes": [],
                                                    "remediation": f.remediation_hint, "impact": f.impact,
                                                    "title": f.title})
                e["nodes"].append(_slug(nr.node_path))
    if union:
        o.append("## Controls failing on one or more nodes")
        o.append("")
        for cid in sorted(union, key=lambda c: (-len(union[c]["nodes"]), c)):
            e = union[cid]
            o.append(f"- **`{cid}`** ({e['sev']}) — {e['title']} — failing on {len(e['nodes'])} node(s): "
                     + ", ".join(e["nodes"]))
            if e["remediation"]:
                o.append(f"  - remediation: {e['remediation']}")
            if e["impact"]:
                o.append(f"  - change impact: {_impact_label(e['impact'])}")
        o.append("")
    else:
        o.append("No failing controls across the managed nodes.")

    o += _advisory_section(node_reports)
    o.append("> Per-node detail: see `nodes/<node>/report.md`.")
    return "\n".join(o)


def _advisory_section(node_reports: list[NodeReport]) -> list[str]:
    """Aggregate vulnerability-exploitation-prevention rollup across nodes."""
    if not any(nr.report.advisory_results for nr in node_reports):
        return []
    o: list[str] = ["", "## Vulnerability exploitation prevention (PSIRT advisories)", ""]
    o.append("| Node | exposed | mitigated | needs-verify | patch-only |")
    o.append("|---|---|---|---|---|")
    for nr in node_reports:
        r = advisory_rollup(nr.report.advisory_results)
        o.append(f"| `{nr.node_path}` | {r['exposed']} | {r['mitigated']} | "
                 f"{r['needs_verify']} | {r['patch_only']} |")
    o.append("")

    # Advisory workarounds not applied (exposed) on one or more nodes, with the
    # "applying this prevents N CVEs" justification.
    union: dict[str, dict] = {}
    for nr in node_reports:
        for f in nr.report.advisory_results:
            if f.status in (Status.FAIL, Status.WARN) and not f.suppressed:
                e = union.setdefault(f.control_id, {"title": f.title, "nodes": [],
                                                    "adv": f.advisory, "rem": f.remediation_hint})
                e["nodes"].append(_slug(nr.node_path))
    if union:
        o.append("### Advisory workarounds not applied on one or more nodes")
        o.append("")
        for cid in sorted(union, key=lambda c: (-(union[c]["adv"].cve_count if union[c]["adv"] else 0), c)):
            e = union[cid]
            o.append(f"- **`{cid}`** — {e['title']} — not applied on {len(e['nodes'])} node(s): "
                     + ", ".join(e["nodes"]))
            just = advisory_justification(e["adv"])
            if just:
                o.append(f"  - Applying this {just}.")
            if e["rem"]:
                o.append(f"  - remediation: {e['rem']}")
        o.append("")
    return o


def topology_json(node_reports: list[NodeReport]) -> dict:
    return {
        "mode": "mobility_master",
        "nodes": [
            {"node_path": nr.node_path, "slug": _slug(nr.node_path),
             "model": nr.report.run_metadata.target.get("model"),
             "posture_score": nr.report.summary.posture_score,
             "counts": nr.report.summary.counts}
            for nr in node_reports
        ],
    }


def write_topology(node_reports: list[NodeReport], out_dir: str | Path) -> dict:
    """Write reports for a (possibly multi-node) audit.

    Single node -> the normal report.* in out_dir. Multi-node -> per-node reports
    under nodes/<slug>/ plus an aggregate report.{md,json} in out_dir.
    """
    out_dir = Path(out_dir)
    if len(node_reports) == 1 and node_reports[0].node_path == "/":
        paths = write_report(node_reports[0].report, out_dir)
        return {"mode": "single", "report": node_reports[0].report,
                "node_dirs": {"/": out_dir}, "paths": paths}

    node_dirs: dict[str, Path] = {}
    for nr in node_reports:
        d = out_dir / "nodes" / _slug(nr.node_path)
        write_report(nr.report, d)
        node_dirs[nr.node_path] = d
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.md").write_text(render_topology_markdown(node_reports), encoding="utf-8")
    (out_dir / "report.json").write_text(json.dumps(topology_json(node_reports), indent=2), encoding="utf-8")
    return {"mode": "multi", "report": None, "node_dirs": node_dirs,
            "paths": {"markdown": out_dir / "report.md", "json": out_dir / "report.json"}}
