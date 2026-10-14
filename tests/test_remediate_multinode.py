"""Mobility Master: one change set per managed node, never one shared file.

Nodes on the same MM run different configs, so a single remediation.cfg would be
wrong for every node it was not generated from. The properties that matter are
that each node gets its own artifacts, that a node's file only contains that
node's findings, and that every block navigates to its node before configuring
anything — because pasting a managed node's fix at the MM prompt applies it in the
wrong place.
"""

from types import SimpleNamespace

from aos8_auditor.cli import _run_remediation
from aos8_auditor.engine import audit_topology, load_controls
from aos8_auditor.model.evidence import (
    CollectionResult,
    CommandResult,
    ControllerIdentity,
    ExitKind,
    NodeRole,
    NodeTarget,
)
from aos8_auditor.reporting.topology_report import _slug, write_topology

CONTROLS = load_controls()
N1 = "/md/Campus/00:1a:1e:00:00:01"
N2 = "/md/Campus/00:1a:1e:00:00:02"
ORG = {"stp_required": False, "ha_required": False, "wip_required": False,
       "ipv6_required": False}

# Fails on N2 and passes on N1, and needs no answers.
ONLY_N2 = "AOS8-GLOBAL-STP-001"
# Fails on both nodes. Answering it for one node must still not answer it for the
# other, which is what tells the node scoping apart from "the finding wasn't there".
BOTH = "AOS8-MGMT-SSH-PUBKEY-001"

# N1 disables spanning-tree, N2 leaves it on. That one difference is what proves
# the two files are generated independently rather than shared.
RC1 = ("version 8.6.0.4\nhostname WLC-A\nfips enable\nno spanning-tree\n"
       "ip default-gateway 10.0.0.1\nbanner motd ^ok^\nlogging 10.0.0.9\n"
       "loginsession timeout 5\nweb-server profile\n session-timeout 360\n")
RC2 = ("version 8.6.0.4\nhostname WLC-B\nspanning-tree\n"
       "snmp-server community public\nweb-server profile\n session-timeout 3600\n")


def _collection():
    def cr(cmd, text, node):
        return CommandResult(command=cmd, redacted_output=text,
                             exit_kind=ExitKind.OK, node_path=node)
    return CollectionResult(
        run_id="mm", controller=ControllerIdentity(
            host="mm.gov", model="MM-VA", platform_family="mm", role=NodeRole.MM),
        nodes=[NodeTarget(node_path=N1, role=NodeRole.MANAGED, platform_hint="7240"),
               NodeTarget(node_path=N2, role=NodeRole.MANAGED, platform_hint="7205")],
        results=[
            cr("show running-config", RC1, N1),
            cr("show version", "ArubaOS (MODEL: Aruba7240), Version 8.6.0.4", N1),
            cr("show running-config", RC2, N2),
            cr("show version", "ArubaOS (MODEL: Aruba7205), Version 8.6.0.4", N2),
        ])


def _args(**kw):
    base = dict(remediate=False, remediate_from=None, remediate_template=False,
                remediate_out=None, remediate_plain=True, host="mm.gov",
                operator="tester", suppressions=None, apply_remediations=False)
    return SimpleNamespace(**{**base, **kw})


def _setup(tmp_path):
    collection = _collection()
    reports = audit_topology(collection, CONTROLS, tool_version="t",
                             active_profile="high_security", org_profile=ORG)
    written = write_topology(reports, tmp_path)
    assert written["mode"] == "multi"
    return collection, reports, written


def _template(tmp_path, **kw):
    collection, reports, written = _setup(tmp_path)
    rc = _run_remediation(_args(remediate_template=True, **kw), collection,
                          reports, written, tmp_path)
    assert rc == 0
    return reports


def _accept(values, *control_ids, node_path=...):
    """Edit a generated values file the way an operator would."""
    import yaml
    doc = yaml.safe_load(values.read_text())
    for e in doc["changes"]:
        if e["control_id"] in control_ids:
            e["accept"] = True
    if node_path is None:
        doc.pop("node_path", None)
    elif node_path is not ...:
        doc["node_path"] = node_path
    values.write_text(yaml.safe_dump(doc))
    return values


# -- one change set per node ---------------------------------------------

def test_each_node_gets_its_own_values_file(tmp_path):
    _template(tmp_path)
    for node in (N1, N2):
        assert (tmp_path / "nodes" / _slug(node) / "remediation_values.yaml").exists()


def test_a_nodes_file_holds_only_that_nodes_findings(tmp_path):
    """The whole reason these are separate files."""
    import yaml
    _template(tmp_path)

    def ids(node):
        text = (tmp_path / "nodes" / _slug(node) / "remediation_values.yaml").read_text()
        return {e["control_id"] for e in yaml.safe_load(text)["changes"]}

    assert ONLY_N2 in ids(N2), "N2 still runs spanning-tree; the fix belongs here"
    assert ONLY_N2 not in ids(N1), "N1 already passes it; offering it is a wrong fix"


def test_remediate_out_keeps_the_nodes_apart(tmp_path):
    """A single --remediate-out for a multi-node run must not have the second
    node silently overwrite the first."""
    out = tmp_path / "elsewhere"
    _template(tmp_path, remediate_out=str(out))
    assert {p.name for p in out.iterdir()} == {_slug(N1), _slug(N2)}
    for node in (N1, N2):
        assert (out / _slug(node) / "remediation_values.yaml").exists()


def test_the_directory_name_matches_the_report_it_came_from(tmp_path):
    """An operator holding six directories needs to tell which report each one
    explains without opening it."""
    out = tmp_path / "elsewhere"
    _template(tmp_path, remediate_out=str(out))
    for node in (N1, N2):
        assert (tmp_path / "nodes" / _slug(node) / "report.json").exists()
        assert (out / _slug(node)).is_dir()


# -- navigating to the node ----------------------------------------------

def test_every_block_navigates_to_its_node_first(tmp_path):
    """Pasting a managed node's fix at the MM prompt configures the wrong device."""
    collection, reports, written = _setup(tmp_path)
    _run_remediation(_args(remediate_template=True), collection, reports, written, tmp_path)

    node_dir = tmp_path / "nodes" / _slug(N2)
    values = _accept(node_dir / "remediation_values.yaml", ONLY_N2)

    rc = _run_remediation(_args(remediate_from=str(values)), collection, reports,
                          written, tmp_path)
    assert rc == 0
    text = (node_dir / "remediation.cfg").read_text()
    live = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("!")]
    assert live[0] == f"cd {N2}"
    assert live.count(f"cd {N2}") == live.count("configure terminal")


def test_the_rollback_navigates_to_the_same_node(tmp_path):
    """A rollback that reverts on the wrong node turns one outage into two."""
    collection, reports, written = _setup(tmp_path)
    _run_remediation(_args(remediate_template=True), collection, reports, written, tmp_path)

    node_dir = tmp_path / "nodes" / _slug(N2)
    values = _accept(node_dir / "remediation_values.yaml", ONLY_N2)
    _run_remediation(_args(remediate_from=str(values)), collection, reports,
                     written, tmp_path)

    rollback = (node_dir / "rollback.cfg").read_text()
    live = [ln for ln in rollback.splitlines()
            if ln.strip() and not ln.strip().startswith("!")]
    assert not live or live[0] == f"cd {N2}"


def test_the_record_names_the_node_it_belongs_to(tmp_path):
    import json
    collection, reports, written = _setup(tmp_path)
    _run_remediation(_args(remediate_template=True), collection, reports, written, tmp_path)

    node_dir = tmp_path / "nodes" / _slug(N2)
    values = _accept(node_dir / "remediation_values.yaml", ONLY_N2)
    _run_remediation(_args(remediate_from=str(values)), collection, reports,
                     written, tmp_path)

    record = json.loads((node_dir / "remediation.json").read_text())
    assert record["node_path"] == N2


# -- answers belong to the node they were gathered for --------------------

def test_one_nodes_answers_are_not_applied_to_the_other_node(tmp_path):
    """The hazard this scoping exists for. --remediate-from is one file, and the
    loop visits every node, so without the node key N2's reviewed answers would be
    exported as N1's config — for a finding that is genuinely present on both, so
    nothing downstream would notice."""
    collection, reports, written = _setup(tmp_path)
    _run_remediation(_args(remediate_template=True), collection, reports, written, tmp_path)

    n2_dir = tmp_path / "nodes" / _slug(N2)
    values = _accept(n2_dir / "remediation_values.yaml", BOTH)
    rc = _run_remediation(_args(remediate_from=str(values)), collection, reports,
                          written, tmp_path)

    assert rc == 0
    assert (n2_dir / "remediation.cfg").exists()
    assert not (tmp_path / "nodes" / _slug(N1) / "remediation.cfg").exists()


def test_a_skipped_node_says_so(tmp_path, capsys):
    """Skipping silently would read as 'N1 needed nothing'."""
    collection, reports, written = _setup(tmp_path)
    _run_remediation(_args(remediate_template=True), collection, reports, written, tmp_path)

    values = _accept(tmp_path / "nodes" / _slug(N2) / "remediation_values.yaml", BOTH)
    _run_remediation(_args(remediate_from=str(values)), collection, reports,
                     written, tmp_path)

    err = capsys.readouterr().err
    assert f"[{N1}]" in err and N2 in err


def test_a_values_file_naming_no_audited_node_fails_the_run(tmp_path, capsys):
    """Every node skipped means nothing was written at all. Returning 0 there would
    tell a pipeline the remediation step succeeded."""
    collection, reports, written = _setup(tmp_path)
    _run_remediation(_args(remediate_template=True), collection, reports, written, tmp_path)

    values = _accept(tmp_path / "nodes" / _slug(N2) / "remediation_values.yaml", BOTH,
                     node_path="/md/Campus/00:1a:1e:00:00:99")
    rc = _run_remediation(_args(remediate_from=str(values)), collection, reports,
                          written, tmp_path)

    assert rc == 1
    assert not list(tmp_path.rglob("remediation.cfg"))
    assert "not audited in this run" in capsys.readouterr().err


def test_dropping_the_node_key_applies_the_file_everywhere(tmp_path):
    """The documented escape hatch, and the control for the test above: with the
    key gone the same file lands on both nodes, so it is the key doing the work."""
    collection, reports, written = _setup(tmp_path)
    _run_remediation(_args(remediate_template=True), collection, reports, written, tmp_path)

    values = _accept(tmp_path / "nodes" / _slug(N2) / "remediation_values.yaml", BOTH,
                     node_path=None)
    rc = _run_remediation(_args(remediate_from=str(values)), collection, reports,
                          written, tmp_path)

    assert rc == 0
    for node in (N1, N2):
        assert (tmp_path / "nodes" / _slug(node) / "remediation.cfg").exists()
