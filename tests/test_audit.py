"""End-to-end: collection -> model -> classify -> score -> report."""

from pathlib import Path

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.models import Status
from aos8_auditor.model.evidence import ExitKind
from aos8_auditor.reporting.report import render_markdown, write_report

from support import make_collection

CONTROLS = load_controls()
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

ORG = {
    "deployment_profile": "high_security",
    "fips_required": True,
    "stp_required": False,
    "ha_required": True,
    "wip_required": True,
    "machine_auth_required": False,
    "require_external_only_auth": False,
    "require_cert_auth": False,
}


def _by_id(report):
    return {f.control_id: f for f in report.results}


def test_hardened_config_has_no_failures():
    rc = (FIXTURES / "hardened_running_config.txt").read_text()
    outputs = {
        "show fips": "FIPS Settings:\n--------------\nMode    Enabled\n",
        "show controller-ip": "Switch IP is 10.10.100.254, VLAN Interface: 10\n",
        "show license summary": "Service       Status\nRFProtect     Enabled  permanent\nPEFNG         Enabled\n",
        "show ap database": "Name  Group      Status\nap01  HQ-Floor1  Up\nap02  HQ-Floor2  Up\n",
        "show mgmt-user local-authentication-mode": "Local Authentication Mode: Enabled\n",
        "show wms rogue-ap": ("", ExitKind.EMPTY),
        "show ap blacklist-clients": ("", ExitKind.EMPTY),
    }
    report = audit(make_collection(rc, outputs), CONTROLS, tool_version="test",
                   active_profile="high_security", org_profile=ORG)
    by = _by_id(report)

    assert report.summary.counts.get("fail", 0) == 0, \
        f"unexpected failures: {[f.control_id for f in report.results if f.status == Status.FAIL]}"
    for cid in ["AOS8-GLOBAL-FIPS-001", "AOS8-GLOBAL-STP-001", "AOS8-GLOBAL-SNMP-001",
                "AOS8-NET-DEFAULTVLAN-001", "AOS8-NET-CTRLIP-001", "AOS8-ADMIN-POLICY-001",
                "AOS8-ADMIN-POLICY-002", "AOS8-WLAN-001", "AOS8-DOT1X-001"]:
        assert by[cid].status == Status.PASS, f"{cid} expected pass, got {by[cid].status} ({by[cid].reason})"
    assert report.summary.posture_score >= 90.0


def test_weak_config_fails_the_right_controls():
    rc = "hostname Aruba7240\nsnmp-server community public\nspanning-tree\n"
    outputs = {"show fips": "FIPS Settings:\n--------------\nMode    Disabled\n"}
    report = audit(make_collection(rc, outputs), CONTROLS, tool_version="test",
                   active_profile="high_security", org_profile=ORG)
    by = _by_id(report)

    assert by["AOS8-GLOBAL-FIPS-001"].status == Status.FAIL
    assert by["AOS8-GLOBAL-SNMP-001"].status == Status.FAIL
    assert by["AOS8-GLOBAL-STP-001"].status == Status.FAIL
    assert by["AOS8-GLOBAL-BANNER-001"].status == Status.FAIL
    assert by["AOS8-INIT-002"].status == Status.FAIL  # default-ish hostname
    assert report.summary.posture_score < 80.0


def test_report_renders_and_writes(tmp_path):
    rc = (FIXTURES / "hardened_running_config.txt").read_text()
    report = audit(make_collection(rc, {"show fips": "Mode    Enabled\n"}),
                   CONTROLS, tool_version="test", active_profile="high_security", org_profile=ORG)
    md = render_markdown(report)
    assert "ArubaOS 8 Hardening Audit" in md and "Posture score" in md
    paths = write_report(report, tmp_path)
    assert paths["json"].exists() and paths["markdown"].exists()
    # JSON round-trips back into a Report.
    from aos8_auditor.engine.models import Report
    Report.model_validate_json(paths["json"].read_text())


def test_wlan_open_ssid_fails_even_with_a_secure_ssid():
    rc = ("wlan ssid-profile CORP\n  opmode wpa2-aes\n"
          "wlan ssid-profile GUEST\n  opmode open\n")
    report = audit(make_collection(rc, {}), CONTROLS, tool_version="test",
                   active_profile="high_security", org_profile=ORG)
    assert _by_id(report)["AOS8-WLAN-001"].status == Status.FAIL


def test_profile_cannot_turn_manual_into_fail():
    # A capability-gated MANUAL (e.g. password policy denied to the role) must
    # stay manual regardless of profile overlays.
    rc = ""
    outputs = {"show aaa password-policy mgmt": ("You do not have permission", ExitKind.DENIED)}
    # PWDPOL derives from running_config, so denial of the show alone won't gate
    # it; instead assert the engine-level guard via a localauth-style denial:
    outputs2 = {"show mgmt-user local-authentication-mode": ("You do not have permission", ExitKind.DENIED)}
    report = audit(make_collection(rc, outputs2), CONTROLS, tool_version="test",
                   active_profile="fips", org_profile={**ORG, "require_external_only_auth": True})
    f = _by_id(report)["AOS8-MGMT-LOCALAUTH-001"]
    assert f.status == Status.MANUAL  # never escalated to fail by the fips overlay


def test_controls_load_and_are_unique():
    ids = [c.id for c in CONTROLS]
    assert len(ids) == len(set(ids))
    assert len(CONTROLS) >= 30
