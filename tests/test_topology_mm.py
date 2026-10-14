"""Mobility Master multi-node: enumeration, per-node audit, aggregate report,
and topology collection."""

from pathlib import Path

from aos8_auditor.collection.classify import classify_exit_kind
from aos8_auditor.collection.collector import Collector
from aos8_auditor.collection.redaction import redact
from aos8_auditor.engine import audit_topology, load_controls
from aos8_auditor.engine.models import Status
from aos8_auditor.model.evidence import (
    CollectionResult,
    CommandResult,
    ControllerIdentity,
    ExitKind,
    NodeRole,
    NodeTarget,
)
from aos8_auditor.reporting.topology_report import _slug, render_topology_markdown, write_topology
from aos8_auditor.transport.topology import enumerate_nodes

CONTROLS = load_controls()
N1 = "/md/Campus/00:1a:1e:00:00:01"
N2 = "/md/Campus/00:1a:1e:00:00:02"
ORG = {"stp_required": False, "ha_required": False, "wip_required": False, "ipv6_required": False}


def test_enumerate_nodes_parses_md_leaves():
    nh = "Config Node\n-----------\n/\n/md\n/md/Campus\n%s\n%s\n/mm\n/mm/mynode\n" % (N1, N2)
    nodes = enumerate_nodes(nh)
    assert [n.node_path for n in nodes] == [N1, N2]
    assert all(n.role == NodeRole.MANAGED for n in nodes)


def test_enumerate_nodes_empty_for_standalone():
    assert enumerate_nodes("Config Node\n/\n/mm\n/mm/mynode\n") == []


# --- red-team regressions: enumeration must handle REAL output shapes ---
def test_enumerate_tabular_type_column():
    txt = ("Default-node is \"/md\"\nConfig Node                  Type\n"
           "-----------                  ----\n/                            System\n"
           "/md                          Group\n/md/Campus                   Group\n"
           "/md/Campus/00:0b:86:01:02:03 Device\n/md/Campus/00:0b:86:01:02:04 Device\n")
    assert [n.node_path for n in enumerate_nodes(txt)] == [
        "/md/Campus/00:0b:86:01:02:03", "/md/Campus/00:0b:86:01:02:04"]


def test_enumerate_deep_nesting_picks_leaves_not_groups():
    txt = "/\n/md\n/md/region\n/md/region/site\n/md/region/site/dev01\n/md/region/site/dev02\n/mm\n"
    assert [n.node_path for n in enumerate_nodes(txt)] == [
        "/md/region/site/dev01", "/md/region/site/dev02"]


def test_enumerate_strips_prompt_and_active_marker():
    txt = "(host) [mynode] #show ...\n* /md/Grp/dev01\n  /md/Grp/dev02\nhost# /md/Grp/dev03\n"
    assert [n.node_path for n in enumerate_nodes(txt)] == [
        "/md/Grp/dev01", "/md/Grp/dev02", "/md/Grp/dev03"]


def test_enumerate_switches_fallback():
    sw = ("IP Address  Name  Type  Configuration Node\n"
          "10.0.0.10  wlc-a  MD  /md/Campus/00:0b:86:aa:bb:01\n"
          "10.0.0.11  wlc-b  MD  /md/Campus/00:0b:86:aa:bb:02\n")
    assert [n.node_path for n in enumerate_nodes("", sw)] == [
        "/md/Campus/00:0b:86:aa:bb:01", "/md/Campus/00:0b:86:aa:bb:02"]


def test_enumerate_ignores_default_node_advisory_line():
    assert enumerate_nodes('Default-node is "/md/East/ctrl-a"\nConfiguration node hierarchy\n') == []


def test_collect_topology_without_cd_does_not_walk():
    from aos8_auditor.model.evidence import ExitKind

    class NoCd:
        def run(self, command, *, timeout_s=None):
            out = {"show configuration node-hierarchy": "/md/G/d1\n/md/G/d2\n"}.get(command, "")
            return CommandResult(command=command, redacted_output=out,
                                 exit_kind=ExitKind.OK if out else ExitKind.EMPTY)

    col = Collector(NoCd(), run_id="x").collect_topology(host="h")
    # nodes recorded, but NOT collected per-node (no cd) -> no /md results
    assert {r.node_path for r in col.results} == {"/"}
    assert any("no node navigation" in w for w in col.collection_warnings)


def test_slug_unique_for_colliding_paths():
    a = _slug("/md/G/00:11:22")
    b = _slug("/md/G/00-11-22")
    assert a != b  # colon- vs dash-separated must not collide


def _mm_collection():
    def cr(cmd, text, node):
        return CommandResult(command=cmd, redacted_output=text, exit_kind=ExitKind.OK, node_path=node)
    return CollectionResult(
        run_id="mm",
        controller=ControllerIdentity(host="mm.gov", model="MM-VA", platform_family="mm", role=NodeRole.MM),
        nodes=[NodeTarget(node_path=N1, role=NodeRole.MANAGED, platform_hint="7240"),
               NodeTarget(node_path=N2, role=NodeRole.MANAGED, platform_hint="7205")],
        results=[
            cr("show running-config", "version 8.6.0.4\nhostname WLC-A\nfips enable\nno spanning-tree\n"
               "ip default-gateway 10.0.0.1\nbanner motd ^ok^\nlogging 10.0.0.9\nloginsession timeout 5\n", N1),
            cr("show version", "ArubaOS (MODEL: Aruba7240), Version 8.6.0.4", N1),
            cr("show fips", "Mode    Enabled\n", N1),
            cr("show running-config", "version 8.6.0.4\nhostname Aruba7205\nspanning-tree\nsnmp-server community public\n", N2),
            cr("show version", "ArubaOS (MODEL: Aruba7205), Version 8.6.0.4", N2),
            cr("show fips", "Mode    Disabled\n", N2),
            cr("show license summary", "AP 100 50 50\nRFProtect 100 50 50\n", "/"),  # MM-global
        ],
    )


def test_audit_topology_per_node():
    reports = audit_topology(_mm_collection(), CONTROLS, tool_version="t",
                             active_profile="high_security", org_profile=ORG)
    assert [nr.node_path for nr in reports] == [N1, N2]
    by = {nr.node_path: nr.report for nr in reports}
    # each node audited against its own config + identity
    assert by[N1].run_metadata.target["model"] == "7240"
    assert by[N2].run_metadata.target["model"] == "7205"
    # hardened node beats the weak one; FIPS differs per node
    assert by[N1].summary.posture_score > by[N2].summary.posture_score
    fips1 = next(f for f in by[N1].results if f.control_id == "AOS8-GLOBAL-FIPS-001")
    fips2 = next(f for f in by[N2].results if f.control_id == "AOS8-GLOBAL-FIPS-001")
    assert fips1.status == Status.PASS and fips2.status == Status.FAIL


def test_write_topology_multi_node_layout(tmp_path):
    reports = audit_topology(_mm_collection(), CONTROLS, tool_version="t",
                             active_profile="high_security", org_profile=ORG)
    written = write_topology(reports, tmp_path)
    assert written["mode"] == "multi"
    assert (tmp_path / "report.md").exists() and (tmp_path / "report.json").exists()
    for np in (N1, N2):
        d = tmp_path / "nodes" / _slug(np)
        assert (d / "report.json").exists() and (d / "report.md").exists()
    agg = (tmp_path / "report.md").read_text()
    assert "Mobility Master" in agg and "Controls failing on one or more nodes" in agg


def test_node_missing_config_does_not_bleed_from_peer():
    # N2 has NO running-config collected; it must NOT be audited against N1's.
    def cr(cmd, text, node):
        return CommandResult(command=cmd, redacted_output=text, exit_kind=ExitKind.OK, node_path=node)
    col = CollectionResult(
        run_id="mm", controller=ControllerIdentity(host="mm", role=NodeRole.MM),
        nodes=[NodeTarget(node_path=N1, role=NodeRole.MANAGED),
               NodeTarget(node_path=N2, role=NodeRole.MANAGED)],
        results=[cr("show running-config", "hostname WLC-A\nfips enable\nbanner motd ^x^\n", N1),
                 cr("show version", "v", N1), cr("show version", "v", N2)])  # N2: no running-config
    from aos8_auditor.parse.model_builder import build_controller_model
    m2 = build_controller_model(col, node_path=N2)
    assert "WLC-A" not in m2.running_config_text  # no bleed from N1
    assert m2.running_config_text.strip() == ""


def test_single_node_writes_flat_report(tmp_path):
    from support import make_collection
    reports = audit_topology(make_collection("hostname x\nfips enable\n", {"show fips": "Mode Enabled\n"}),
                             CONTROLS, tool_version="t", active_profile="high_security", org_profile=ORG)
    written = write_topology(reports, tmp_path)
    assert written["mode"] == "single"
    assert (tmp_path / "report.md").exists() and not (tmp_path / "nodes").exists()


class _FakeMM:
    def __init__(self, global_out, per_node):
        self.node = "/"
        self.global_out = global_out
        self.per_node = per_node

    def set_node(self, p):
        self.node = p

    def run(self, command, *, timeout_s=None):
        out = (self.global_out if self.node == "/" else self.per_node.get(self.node, {})).get(command, "")
        rr = redact(out)
        k, _ = classify_exit_kind(out, echoed_command=command)
        r = CommandResult(command=command, redacted_output=rr.text, exit_kind=k, node_path=self.node)
        r.sha256 = r.compute_sha256()
        return r


def test_collect_topology_walks_managed_nodes():
    nh = "Config Node\n/\n/md\n/md/Campus\n%s\n%s\n/mm\n" % (N1, N2)
    glob = {"show configuration node-hierarchy": nh,
            "show version": "ArubaOS (MODEL: ArubaMM-VA), Version 8.6.0.4",
            "show license summary": "AP 100 50 50\n"}
    per = {N1: {"show running-config": "hostname WLC-A\nfips enable\n", "show fips": "Mode Enabled\n"},
           N2: {"show running-config": "hostname Aruba7205\n", "show fips": "Mode Disabled\n"}}
    c = Collector(_FakeMM(glob, per), run_id="mm")
    col = c.collect_topology(host="mm.gov")
    assert [n.node_path for n in col.nodes] == [N1, N2]
    assert col.controller.detected_topology == "mobility_master"
    # per-node running-config tagged to its node
    rc1 = col.by_command("show running-config", N1)
    assert rc1 is not None and "WLC-A" in rc1.redacted_output
    # license stays MM-global ("/"), not duplicated per node
    assert {r.node_path for r in col.results if r.command == "show license summary"} == {"/"}
