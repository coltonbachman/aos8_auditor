"""The open-port reference: data integrity, fact join, and report rendering.

This section is REFERENCE DATA — nothing in it is scored and no port is ever
probed. The properties that matter are therefore (a) every row loads and keeps
the guide's wording, (b) the join against audit facts never claims a port is
closeable on a guess, and (c) it renders into every output format.
"""

import pytest

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.models import PortGuidance, PortUsage, Status
from aos8_auditor.engine.open_ports import port_exposure, reference_facts
from aos8_auditor.parse.model_builder import build_controller_model
from aos8_auditor.reporting.html import render_html
from aos8_auditor.reporting.report import render_markdown

from support import make_collection

CONTROLS = load_controls()
ORG = {"deployment_profile": "high_security", "fips_required": True, "stp_required": False,
       "ha_required": True, "wip_required": True, "ipv6_required": False,
       "machine_auth_required": False, "require_external_only_auth": False,
       "require_cert_auth": False}


def _report(rc="hostname w\n", outputs=None):
    return audit(make_collection(rc, outputs or {}), CONTROLS, tool_version="t",
                 active_profile="high_security", org_profile=ORG)


# --------------------------------------------------------------------------
# Reference data integrity
# --------------------------------------------------------------------------

def test_all_three_guide_tables_load():
    pe = port_exposure({})
    assert len(pe.controller_ports) == 43   # guide p.9-14
    assert len(pe.access_point_ports) == 4  # guide p.14
    assert len(pe.control_plane_protocols) == 46  # guide p.30-53


def test_every_row_keeps_the_guides_own_wording():
    pe = port_exposure({})
    for e in pe.controller_ports + pe.access_point_ports:
        assert e.port, "a port row lost its port number"
        assert e.purpose or e.notes, f"port {e.port} has neither purpose nor notes"
    for p in pe.control_plane_protocols:
        assert p.name and (p.description or p.notes), f"protocol {p.name} lost its text"


def test_every_in_use_fact_is_a_real_fact():
    # A typo here would silently pin a port to "unknown" forever.
    available = set(build_controller_model(make_collection("hostname x", {})).facts)
    assert reference_facts() <= available, f"unknown facts: {reference_facts() - available}"


@pytest.mark.parametrize("port", ["123", "514"])
def test_server_for_aps_ports_carry_no_client_side_fact(port):
    # On UDP/123 and UDP/514 the controller is the SERVER for its own APs. The
    # only facts the audit can see for those protocols describe the controller as
    # a CLIENT of upstream servers — the opposite direction, and anti-correlated:
    # a box with no external syslog collector would be told UDP/514 is closeable
    # while its APs are still logging to it. These rows must stay unknown.
    e = _entry(port_exposure({"ntp_server_count": 0, "syslog_server_count": 0}), port)
    assert e.in_use_fact is None, f"port {port} joined against a client-side fact"
    assert e.usage is PortUsage.UNKNOWN and not e.blockable


# --------------------------------------------------------------------------
# The fact join — must never claim "closeable" on a guess
# --------------------------------------------------------------------------

def test_unknown_facts_never_produce_a_conditional_recommendation():
    pe = port_exposure({})  # no facts at all
    for e in pe.controller_ports + pe.access_point_ports:
        assert e.usage is PortUsage.UNKNOWN
        # Only unconditionally safe ports may be marked closeable with no facts.
        assert e.blockable == (e.guidance is PortGuidance.SAFE_TO_BLOCK), e.port


def test_conditional_port_resolves_only_when_the_service_is_unused():
    telnet = "23"
    assert _entry(port_exposure({}), telnet).usage is PortUsage.UNKNOWN
    off = _entry(port_exposure({"telnet_cli_enabled": False}), telnet)
    assert off.usage is PortUsage.NOT_NEEDED and off.blockable
    on = _entry(port_exposure({"telnet_cli_enabled": True}), telnet)
    assert on.usage is PortUsage.IN_USE and not on.blockable


def test_do_not_block_stays_do_not_block_even_when_unused():
    # CPsec off does not make PAPI blockable — the guide says do not block it.
    pe = port_exposure({"cpsec_enabled": False})
    for e in pe.controller_ports + pe.access_point_ports:
        if e.guidance is PortGuidance.DO_NOT_BLOCK:
            assert not e.blockable, f"port {e.port} marked closeable against the guide"


def test_counts_are_consistent_with_the_rows():
    pe = port_exposure({"telnet_cli_enabled": False, "dns_responder_enabled": True})
    rows = pe.controller_ports + pe.access_point_ports
    c = pe.counts
    assert c["blockable_here"] == sum(1 for e in rows if e.blockable)
    assert c["in_use"] + c["not_needed"] + c["unknown"] == len(rows)


def _entry(pe, port):
    return next(e for e in pe.controller_ports if e.port == port)


# --------------------------------------------------------------------------
# Wiring into the report
# --------------------------------------------------------------------------

def test_report_carries_the_section_and_it_is_never_scored():
    r = _report()
    assert r.port_exposure is not None
    # Reference rows must not have leaked into the scored findings.
    ids = {f.control_id for f in r.results}
    assert not any(i.startswith("AOS8-PORTREF") for i in ids)
    scored = [f for f in r.results if f.status in (Status.PASS, Status.FAIL, Status.WARN)]
    assert len(scored) < len(r.results) + len(r.port_exposure.controller_ports)


def test_section_reflects_this_controllers_config():
    r = _report("no ip domain lookup\ntelnet cli\n")
    by_port = {e.port: e for e in r.port_exposure.controller_ports}
    assert by_port["53"].usage is PortUsage.NOT_NEEDED
    assert by_port["23"].usage is PortUsage.IN_USE and not by_port["23"].blockable


@pytest.mark.parametrize("render", [render_markdown, render_html])
def test_section_renders_in_every_format(render):
    text = render(_report())
    assert "Open ports" in text or "open port" in text.lower()
    assert "43" in text  # the controller-port count is stated
    # The read-only promise must be restated wherever ports are listed.
    assert "never scans" in text or "not probed" in text or "no port is probed" in text


def test_empty_section_renders_nothing():
    from aos8_auditor.engine.models import Report, RunMetadata
    r = Report(run_metadata=RunMetadata(tool_version="t", run_id="r"))
    assert "Open ports" not in render_markdown(r)
    assert "Open ports" not in render_html(r)
