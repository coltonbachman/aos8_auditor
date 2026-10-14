"""Regression tests for the 24 Phase 2 control red-team findings.

Each crafts a config that should pass and/or one that should fail, runs the real
audit, and asserts the verdict — locking in the banner-injection, unanchored-
regex, cross-block-span, per-stanza-scoping, and header-only-cert fixes.
"""

import pytest

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.models import Status

from support import make_collection

CONTROLS = load_controls()
ORG = {
    "deployment_profile": "high_security", "fips_required": True, "stp_required": False,
    "ha_required": True, "wip_required": True, "ipv6_required": True,
    "machine_auth_required": True, "require_external_only_auth": True, "require_cert_auth": True,
}


def _status(rc, cid, outputs=None, org=None):
    r = audit(make_collection(rc, outputs or {}), CONTROLS, tool_version="t",
              active_profile="high_security", org_profile=org or ORG)
    return {f.control_id: f.status.value for f in r.results}[cid]


def test_banner_injection_does_not_false_pass():
    rc = ("hostname WLC\nbanner motd ^\n"
          "country US export rules apply.\nclock timezone is central.\n"
          "ntp server policy: report drift.\nip default-gateway via ticket.\n"
          "switch-role master admins see runbook.\n^\n")
    # directives only in the banner body -> must NOT pass off banner prose
    assert _status(rc, "AOS8-INIT-TIMEZONE-001") == "fail"
    assert _status(rc, "AOS8-INIT-STARTUP-001") == "fail"


def test_ipv6_no_form_not_misread():
    rc = "hostname w\nfirewall\n  no ipv6 enable\n"
    assert _status(rc, "AOS8-NET-IPV6-DISABLED-001", org={**ORG, "ipv6_required": False}) == "pass"
    assert _status(rc, "AOS8-NET-IPV6-ENABLED-001", org={**ORG, "ipv6_required": True}) == "fail"


def test_eap_tls_header_only_certs_fail():
    outs = {"show crypto-local pki serverCerts": "Name  Type(RSA/EC)  Expiry\n",
            "show crypto-local pki trustedCAs": "Name  Issuer  Expiry\n"}
    assert _status("hostname w", "AOS8-AUTH-EAP-TLS-CERTS-001", outs) == "fail"


def test_ldap_authport_scoped_to_ldap_stanza():
    rc = ("aaa authentication-server ldap L1\n  authport 636\n"
          "aaa authentication-server radius R1\n  authport 389\n  enable\n")
    assert _status(rc, "AOS8-AUTH-LDAP-LDAPS-001") == "pass"


def test_blacklist_time_does_not_satisfy_enable():
    assert _status("aaa profile P\n  blacklist-time 3600\n", "AOS8-WIP-BLACKLIST-ENABLE-001") == "fail"
    assert _status("aaa profile P\n  blacklist\n", "AOS8-WIP-BLACKLIST-ENABLE-001") == "pass"


def test_pefng_not_installed_warns():
    assert _status("hostname w", "AOS8-LIC-PEFV-001", {"show license summary": "PEFNG  Not Installed\n"}) == "warn"


def test_persist_header_only_is_pass():
    assert _status("hostname w", "AOS8-INIT-PERSIST-001",
                   {"show configuration pending": "Pending Configuration Changes:\n"}) == "pass"


def test_vlan_staticip_does_not_span_into_vlan1():
    rc = "interface vlan 10\ninterface vlan 1\n  ip address 1.2.3.4 255.255.255.0\n"
    assert _status(rc, "AOS8-NET-VLAN-STATICIP-001") == "fail"


def test_vrrp_auth_per_instance():
    rc = "vrrp 1\n  ip address 1.1.1.1\nvrrp 2\n  authentication s\n"
    assert _status(rc, "AOS8-NET-VRRP-AUTH-001") == "fail"


def test_webui_session_limit_over_max_fails():
    assert _status("web-server profile\n  session-limit 25\n", "AOS8-MGMT-WEBUI-SESSLIMIT-001") == "fail"
    assert _status("web-server profile\n  session-limit 20\n", "AOS8-MGMT-WEBUI-SESSLIMIT-001") == "pass"


def test_trustedca_header_only_not_pass():
    assert _status("hostname w", "AOS8-MGMT-TRUSTEDCA-001",
                   {"show crypto-local pki trustedCAs": "Name  Issuer  Expiry\n"}) == "manual"


def test_http_management_disable_not_false_fail():
    assert _status("web-server profile\n  http-management disable\n",
                   "AOS8-MGMT-SSH-DISABLE-INSECURE-MGMT-001") == "pass"


def test_radius_authport_scoped():
    rc = ("aaa authentication-server radius R1\n  host 1.1.1.1\n  enable\n"
          "aaa authentication-server ldap L1\n  authport 636\n")
    assert _status(rc, "AOS8-AUTH-RADIUS-PORTS-001") == "warn"


def test_netdest_default_route_only_in_acl_is_pass():
    rc = ("netdestination N\n  host 10.0.0.1\n"
          "ip access-list session R\n  network 0.0.0.0 0.0.0.0 nexthop-list g\n")
    assert _status(rc, "AOS8-ROLE-NETDEST-MEMBERSHIP-001") == "pass"


def test_tarpit_in_comment_is_na():
    assert _status("# legacy: wireless-containment tarpit removed\n", "AOS8-WIP-TARPIT-LIC-001",
                   {"show license summary": "RFProtect Not Installed\n"}) == "not_applicable"


def test_initrole_prefix_name_not_false_fail():
    assert _status("aaa profile P\n  initial-role allowall-locked\n", "AOS8-ROLE-INITROLE-001") == "pass"
    assert _status("aaa profile P\n  initial-role allowall\n", "AOS8-ROLE-INITROLE-001") == "fail"


def test_ap_name_hyphen_mac_flagged():
    assert _status("hostname w", "AOS8-AP-NAME-001",
                   {"show ap database": "Name  Group  Status\n00-1a-2b-3c-4d-5e  HQ  Up\n"}) == "warn"


def test_srvderiv_set_vlan_counts():
    rc = "aaa server-group G\n  set vlan condition essid equals corp set-value 100\n"
    assert _status(rc, "AOS8-ROLE-SRVDERIV-001") == "pass"
