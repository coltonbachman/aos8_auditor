"""Facts and controls added from the ArubaOS 8 Controller Hardening Guide (2023).

Every new fact gets three cases where the extractor can produce them: a true
case, a false case, and a silent case that must stay ``None`` so the control
degrades to ``manual`` instead of inventing a verdict. Controls are then driven
through the real audit to confirm the pass/fail/warn mapping.
"""

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.models import GuideDocument
from aos8_auditor.parse.model_builder import build_controller_model

from support import make_collection

CONTROLS = load_controls()
ORG = {
    "deployment_profile": "high_security", "fips_required": True, "stp_required": False,
    "ha_required": True, "wip_required": True, "ipv6_required": True,
    "machine_auth_required": True, "require_external_only_auth": True, "require_cert_auth": True,
}


def _facts(rc="", outputs=None):
    return build_controller_model(make_collection(rc, outputs or {})).facts


def _status(rc, cid, outputs=None, org=None, profile="high_security"):
    r = audit(make_collection(rc, outputs or {}), CONTROLS, tool_version="t",
              active_profile=profile, org_profile=org or ORG)
    return {f.control_id: f.status.value for f in r.results}[cid]


# --------------------------------------------------------------------------
# Cryptography (guide p.19-20)
# --------------------------------------------------------------------------

def test_web_ciphers_high_keyword_and_suite_list():
    assert _facts("web-server profile\n  ciphers high\n")["web_ciphers_high"] is True
    assert _facts("web-server profile\n  ciphers medium\n")["web_ciphers_high"] is False
    assert _facts("web-server profile\n  ciphers low\n")["web_ciphers_high"] is False
    # AOS 8.10 prints the negotiated suite list rather than the keyword.
    strong = {"show web-server profile":
              "Web Server Configuration\n------------------------\n"
              "Parameter                        Value\n"
              "Enable provided cipher suites    ECDHE-ECDSA-AES256-GCM-SHA384:AES256-SHA256\n"}
    assert _facts("", strong)["web_ciphers_high"] is True
    weak = {"show web-server profile":
            "Enable provided cipher suites    ECDHE-RSA-DES-CBC3-SHA:RC4-MD5\n"}
    assert _facts("", weak)["web_ciphers_high"] is False
    assert _facts("hostname w\n")["web_ciphers_high"] is None


def test_web_tls12_only_treats_bare_tlsv1_as_legacy():
    # ArubaOS spells TLS 1.0 'tlsv1' — a substring test for 'tlsv1.0' misses it.
    assert _facts("web-server profile\n  ssl-protocol tlsv1 tlsv1.2\n")["web_tls12_only"] is False
    assert _facts("web-server profile\n  ssl-protocol tlsv1.1 tlsv1.2\n")["web_tls12_only"] is False
    assert _facts("web-server profile\n  ssl-protocol tlsv1.2\n")["web_tls12_only"] is True
    # Versions may render across several lines, with negations alongside.
    multi = "web-server profile\n  ssl-protocol tlsv1.2\n  no ssl-protocol tlsv1\n"
    assert _facts(multi)["web_tls12_only"] is True
    assert _facts("hostname w\n")["web_tls12_only"] is None


def test_web_tls_negation_only_leaves_tls11_enabled():
    # 'no ssl-protocol tlsv1' switches off TLS 1.0 but TLS 1.1 stays on by
    # default, so this must not read as a pass.
    assert _facts("web-server profile\n  no ssl-protocol tlsv1\n")["web_tls12_only"] is False
    both = "web-server profile\n  no ssl-protocol tlsv1\n  no ssl-protocol tlsv1.1\n"
    assert _facts(both)["web_tls12_only"] is True


def test_web_tls12_only_from_show_output():
    out = {"show web-server profile": "SSL/TLS Protocol Config          TLSv1.2\n"}
    assert _facts("", out)["web_tls12_only"] is True
    out2 = {"show web-server profile": "SSL/TLS Protocol Config          TLSv1 TLSv1.1 TLSv1.2\n"}
    assert _facts("", out2)["web_tls12_only"] is False


def test_ssh_weak_ciphers_disabled():
    both = "ssh disable-ciphers aes-cbc\nssh disable-mac hmac-sha1-96\n"
    assert _facts(both)["ssh_weak_ciphers_disabled"] is True
    assert _facts("ssh disable-ciphers aes-cbc\n")["ssh_weak_ciphers_disabled"] is False
    # 'show ssh' is authoritative: an absent suite there proves it is disabled.
    out = {"show ssh": "SSH Settings\n------------\nDisabled ciphers: aes-cbc hmac-sha1-96\n"
                       "Mgmt-auth  username/password\n"}
    assert _facts("", out)["ssh_weak_ciphers_disabled"] is False  # names both as present text
    clean = {"show ssh": "SSH Settings\nCiphers: aes256-ctr aes128-ctr\nMACs: hmac-sha2-256\n"}
    assert _facts("", clean)["ssh_weak_ciphers_disabled"] is True
    assert _facts("hostname w\n")["ssh_weak_ciphers_disabled"] is None


def test_the_mac_is_configured_under_disable_mac_not_disable_ciphers():
    """'ssh disable-ciphers hmac-sha1-96' is not a command ArubaOS accepts, so a
    running-config can never contain it. Looking for the MAC there meant the
    fact came back False no matter what the operator did: apply the real fix and
    the next audit still reported it outstanding."""
    real = "ssh disable-ciphers aes-cbc\nssh disable-mac hmac-sha1-96\n"
    assert _facts(real)["ssh_weak_ciphers_disabled"] is True
    invalid = "ssh disable-ciphers aes-cbc\nssh disable-ciphers hmac-sha1-96\n"
    assert _facts(invalid)["ssh_weak_ciphers_disabled"] is False


def test_show_ssh_cipher_list_is_read_the_way_arubaos_prints_it():
    """Verbatim from an 8.13.3.0 MC-VA with the weak algorithms still enabled.
    The list spells CBC as 'aes128-cbc'/'aes256-cbc', so the literal 'aes-cbc'
    the CLI keyword uses never appears -- testing the page for that substring
    concluded CBC was disabled on every controller in existence."""
    enabled = {"show ssh": (
        "SSH Settings:\n-------------\n"
        "DSA                                 Enabled\n"
        "Ciphers                             aes128-cbc,aes256-cbc,aes128-ctr,"
        "aes192-ctr,aes256-ctr,aes256-gcm@openssh.com\n"
        "MACs                                hmac-sha1-96,hmac-sha1,hmac-sha2-256\n")}
    assert _facts("", enabled)["ssh_weak_ciphers_disabled"] is False
    restricted = {"show ssh": (
        "SSH Settings:\n-------------\n"
        "Ciphers                             aes128-ctr,aes192-ctr,aes256-ctr\n"
        "MACs                                hmac-sha1,hmac-sha2-256\n")}
    assert _facts("", restricted)["ssh_weak_ciphers_disabled"] is True


def test_isakmp_legacy_dh_and_strength():
    legacy = "crypto isakmp policy 10001\n  group 2\ncrypto isakmp policy 10002\n  group 2\n"
    f = _facts(legacy)
    assert f["isakmp_legacy_dh_disabled"] is False
    assert f["isakmp_strong_policy"] is False  # no admin-defined policy at all
    strong = ("crypto isakmp policy 20\n  version v2\n  encryption AES256\n"
              "  hash sha\n  group 14\n  authentication rsa-sig\n")
    f2 = _facts(strong)
    assert f2["isakmp_legacy_dh_disabled"] is True
    assert f2["isakmp_strong_policy"] is True
    # A legacy-priority policy explicitly re-grouped to 14 is acceptable.
    regrouped = "crypto isakmp policy 10001\n  group 14\n"
    assert _facts(regrouped)["isakmp_legacy_dh_disabled"] is True
    assert _facts("hostname w\n")["isakmp_legacy_dh_disabled"] is None
    assert _facts("hostname w\n")["isakmp_strong_policy"] is None


def test_isakmp_strong_policy_from_show_prose():
    out = {"show crypto isakmp policy":
           "Protection suite priority 20\n"
           "  Encryption Algorithm       : AES - Advanced Encryption Standard (256 bits)\n"
           "  Hash Algorithm             : SHA\n"
           "  Authentication Method      : Rivest-Shamir-Adelman Signature\n"
           "  Diffie-Hellman Group       : #14 (2048 bit)\n"
           "  IKE Version                : 2\n"}
    assert _facts("", out)["isakmp_strong_policy"] is True


def test_tkip_detected_in_any_ssid_profile():
    assert _facts("wlan ssid-profile G\n  opmode wpa2-tkip\n")["tkip_in_use"] is True
    assert _facts("wlan ssid-profile G\n  opmode wpa2-aes-tkip\n")["tkip_in_use"] is True
    assert _facts("wlan ssid-profile G\n  opmode wpa2-aes\n")["tkip_in_use"] is False
    assert _facts("hostname w\n")["tkip_in_use"] is None


def test_crypto_2023_control_verdicts():
    weak = ("hostname w\nweb-server profile\n  ciphers medium\n  ssl-protocol tlsv1 tlsv1.2\n"
            "crypto isakmp policy 10001\n  group 2\n"
            "wlan ssid-profile G\n  opmode wpa2-tkip\n")
    assert _status(weak, "AOS8-CRYPTO-WEBCIPHERS-001") == "fail"
    assert _status(weak, "AOS8-CRYPTO-TLS-001") == "fail"
    assert _status(weak, "AOS8-CRYPTO-TKIP-001") == "fail"
    assert _status(weak, "AOS8-CRYPTO-ISAKMP-LEGACYDH-001") == "warn"
    assert _status(weak, "AOS8-CRYPTO-ISAKMP-STRENGTH-001") == "warn"
    good = ("hostname w\nweb-server profile\n  ciphers high\n  ssl-protocol tlsv1.2\n"
            "crypto isakmp policy 20\n  version v2\n  group 14\n  authentication rsa-sig\n"
            "wlan ssid-profile G\n  opmode wpa2-aes\n"
            "ssh disable-ciphers aes-cbc\nssh disable-mac hmac-sha1-96\n")
    for cid in ("AOS8-CRYPTO-WEBCIPHERS-001", "AOS8-CRYPTO-TLS-001", "AOS8-CRYPTO-TKIP-001",
                "AOS8-CRYPTO-ISAKMP-LEGACYDH-001", "AOS8-CRYPTO-ISAKMP-STRENGTH-001",
                "AOS8-CRYPTO-SSH-CIPHERS-001"):
        assert _status(good, cid) == "pass", cid


def test_undeterminable_crypto_controls_report_manual():
    rc = "hostname w\n"
    for cid in ("AOS8-CRYPTO-WEBCIPHERS-001", "AOS8-CRYPTO-TLS-001", "AOS8-CRYPTO-TKIP-001",
                "AOS8-CRYPTO-ISAKMP-LEGACYDH-001", "AOS8-CRYPTO-ISAKMP-STRENGTH-001",
                "AOS8-CRYPTO-SSH-CIPHERS-001"):
        assert _status(rc, cid) == "manual", cid


# --------------------------------------------------------------------------
# Firewall / control-path defense (guide p.23, 25, 54-56)
# --------------------------------------------------------------------------

def test_firewall_flags_prefer_show_output_over_config_silence():
    # 'show firewall' lists every option, so silence in running-config is no
    # longer ambiguous once it is collected.
    out = {"show firewall": ("Global firewall policies\n------------------------\n"
                            "Policy                          Action\n"
                            "Prohibit IP Spoofing            Enabled\n"
                            "Prohibit ARP Spoofing           Disabled\n"
                            "Monitor/police CP attacks       Enabled\n")}
    f = _facts("hostname w\n", out)
    assert f["fw_prohibit_ip_spoofing"] is True
    assert f["fw_prohibit_arp_spoofing"] is False
    assert f["fw_cp_attack_rate_set"] is True


def test_firewall_flags_from_running_config():
    rc = "firewall\n  prohibit-ip-spoofing\n  attack-rate cp 20\n"
    f = _facts(rc)
    assert f["fw_prohibit_ip_spoofing"] is True
    assert f["fw_prohibit_arp_spoofing"] is False  # stanza present, directive absent
    assert f["fw_cp_attack_rate_set"] is True
    assert _facts("hostname w\n")["fw_prohibit_ip_spoofing"] is None
    assert _facts("firewall\n  no prohibit-ip-spoofing\n")["fw_prohibit_ip_spoofing"] is False


def test_cp_bandwidth_contract_count():
    rc = ("firewall\n  cp-bandwidth-contract untrusted-ucast 20\n"
          "  cp-bandwidth-contract untrusted-mcast 4\n"
          "  cp-bandwidth-contract trusted-ucast 160\n"
          "  cp-bandwidth-contract trusted-mcast 4\n")
    assert _facts(rc)["fw_cp_bw_contract_count"] == 4
    assert _facts("firewall\n  cp-bandwidth-contract untrusted-ucast 20\n")["fw_cp_bw_contract_count"] == 1
    assert _facts("hostname w\n")["fw_cp_bw_contract_count"] is None


def test_cp_service_acl_rule_count_needs_show_firewall_cp():
    empty = {"show firewall-cp": "CP firewall policies\n--------------------\nIP Version Source IP\n"}
    assert _facts("hostname w\n", empty)["fw_cp_acl_rule_count"] == 0
    rules = {"show firewall-cp": ("CP firewall policies\n--------------------\n"
                                 "IP Version  Source IP  Action\n"
                                 "ipv4        10.1.1.0   permit\n"
                                 "ipv4        any        deny\n")}
    assert _facts("hostname w\n", rules)["fw_cp_acl_rule_count"] == 2
    # Not visible in running-config when no rules were added.
    assert _facts("hostname w\n")["fw_cp_acl_rule_count"] is None


def test_validuser_acl_narrowing():
    default = "ip access-list session validuser\n  any any any permit\n"
    assert _facts(default)["fw_validuser_narrowed"] is False
    narrowed = ("ip access-list session validuser\n"
                "  network 10.1.0.0 255.255.0.0 any any permit\n  any any any deny\n")
    assert _facts(narrowed)["fw_validuser_narrowed"] is True
    assert _facts("hostname w\n")["fw_validuser_narrowed"] is None


def test_deny_inter_user_globally_or_on_every_vap():
    assert _facts("firewall\n  deny-inter-user-traffic\n")["fw_deny_inter_user"] is True
    per_vap = ("firewall\n"
               "wlan virtual-ap A\n  deny-inter-user-traffic\n"
               "wlan virtual-ap B\n  deny-inter-user-traffic\n")
    assert _facts(per_vap)["fw_deny_inter_user"] is True
    partial = ("firewall\n"
               "wlan virtual-ap A\n  deny-inter-user-traffic\n"
               "wlan virtual-ap B\n  vlan 100\n")
    assert _facts(partial)["fw_deny_inter_user"] is False
    assert _facts("hostname w\n")["fw_deny_inter_user"] is None


def test_cpsec_needs_show_output():
    # The 'control-plane-security' stanza renders empty at defaults.
    assert _facts("control-plane-security\n")["cpsec_enabled"] is None
    on = {"show control-plane-security": "Control Plane Security Profile\n"
                                         "Parameter        Value\n"
                                         "Cpsec Enable     Enabled\n"}
    assert _facts("", on)["cpsec_enabled"] is True
    off = {"show control-plane-security": "Cpsec Enable     Disabled\n"}
    assert _facts("", off)["cpsec_enabled"] is False


def test_firewall_2023_control_verdicts():
    weak = ("hostname w\nfirewall\n  no prohibit-ip-spoofing\n"
            "ip access-list session validuser\n  any any any permit\n")
    outputs = {"show firewall-cp": "CP firewall policies\nIP Version Source IP\n",
               "show control-plane-security": "Cpsec Enable     Disabled\n"}
    assert _status(weak, "AOS8-FW-IPSPOOF-001", outputs) == "fail"
    assert _status(weak, "AOS8-FW-ARPSPOOF-001", outputs) == "fail"
    assert _status(weak, "AOS8-FW-DENY-INTER-USER-001", outputs) == "warn"
    assert _status(weak, "AOS8-FW-LOCALVALIDUSERS-001", outputs) == "warn"
    assert _status(weak, "AOS8-FW-CP-ATTACKRATE-001", outputs) == "warn"
    assert _status(weak, "AOS8-FW-CP-BWCONTRACT-001", outputs) == "warn"
    assert _status(weak, "AOS8-FW-CP-ACL-001", outputs) == "warn"
    assert _status(weak, "AOS8-CPSEC-001", outputs) == "fail"

    good = ("hostname w\nfirewall\n  prohibit-ip-spoofing\n  prohibit-arp-spoofing\n"
            "  deny-inter-user-traffic\n  local-valid-users\n  attack-rate cp 20\n"
            "  cp-bandwidth-contract untrusted-ucast 20\n"
            "  cp-bandwidth-contract untrusted-mcast 4\n"
            "  cp-bandwidth-contract trusted-ucast 160\n"
            "  cp-bandwidth-contract trusted-mcast 4\n")
    good_out = {"show firewall-cp": ("IP Version  Source IP  Action\n"
                                     "ipv4        10.1.1.0   permit\n"),
                "show control-plane-security": "Cpsec Enable     Enabled\n"}
    for cid in ("AOS8-FW-IPSPOOF-001", "AOS8-FW-ARPSPOOF-001", "AOS8-FW-DENY-INTER-USER-001",
                "AOS8-FW-LOCALVALIDUSERS-001", "AOS8-FW-CP-ATTACKRATE-001",
                "AOS8-FW-CP-BWCONTRACT-001", "AOS8-FW-CP-ACL-001", "AOS8-CPSEC-001"):
        assert _status(good, cid, good_out) == "pass", cid


def test_cp_acl_and_cpsec_are_manual_without_their_evidence():
    # Both are gated on show output a pre-2023 bundle never collected; they must
    # drop out of the score rather than fail an otherwise fine controller.
    rc = "hostname w\nfirewall\n  prohibit-ip-spoofing\n"
    assert _status(rc, "AOS8-FW-CP-ACL-001") == "manual"
    assert _status(rc, "AOS8-CPSEC-001") == "manual"


# --------------------------------------------------------------------------
# Administrative lockdown, AP console/debug, user access (p.24-26, 56)
# --------------------------------------------------------------------------

def test_console_block_and_central_auth():
    assert _facts("mgmt-user console-block\n")["mgmt_console_blocked"] is True
    assert _facts("hostname w\n")["mgmt_console_blocked"] is False
    assert _facts("")["mgmt_console_blocked"] is None
    central = ("aaa authentication mgmt\n  enable\n  mschapv2\n  server-group RAD-GRP\n")
    assert _facts(central)["central_mgmt_auth"] is True
    local_only = "aaa authentication mgmt\n  enable\n  server-group internal\n"
    assert _facts(local_only)["central_mgmt_auth"] is False
    assert _facts("hostname w\n")["central_mgmt_auth"] is None


def test_console_block_control_is_high_security_only():
    rc = "hostname w\n"
    assert _status(rc, "AOS8-MGMT-CONSOLE-BLOCK-001") == "warn"
    assert _status(rc, "AOS8-MGMT-CONSOLE-BLOCK-001", profile="baseline",
                   org={**ORG, "deployment_profile": "baseline"}) == "not_applicable"
    assert _status("mgmt-user console-block\n", "AOS8-MGMT-CONSOLE-BLOCK-001") == "pass"


def test_central_mgmt_auth_control_verdicts():
    good = "aaa authentication mgmt\n  enable\n  server-group RAD-GRP\n"
    assert _status(good, "AOS8-MGMT-CENTRALAUTH-001") == "pass"
    bad = "aaa authentication mgmt\n  enable\n  server-group internal\n"
    assert _status(bad, "AOS8-MGMT-CENTRALAUTH-001") == "fail"
    assert _status("hostname w\n", "AOS8-MGMT-CENTRALAUTH-001") == "manual"


def test_ap_console_and_debug_shell():
    assert _facts('ap system-profile "default"\n  ap-console-protection\n')["ap_console_protected"] is True
    assert _facts("ap system-profile P\n  no ap-console-protection\n")["ap_console_protected"] is False
    assert _facts("ap system-profile P\n  no console-enable\n")["ap_console_protected"] is True
    assert _facts("hostname w\n")["ap_console_protected"] is None
    assert _facts("ap system-profile P\n  telnet\n")["ap_debug_shell_enabled"] is True
    assert _facts("ap system-profile P\n  ap-console-protection\n")["ap_debug_shell_enabled"] is False
    assert _facts("hostname w\n")["ap_debug_shell_enabled"] is None
    out = {"show ap system-profile default": "Parameter          Value\nTelnet             Enabled\n"}
    assert _facts("", out)["ap_debug_shell_enabled"] is True


def test_ap_controls_verdicts():
    bad = "ap system-profile P\n  no ap-console-protection\n  telnet\n"
    assert _status(bad, "AOS8-AP-CONSOLE-PROTECT-001") == "fail"
    assert _status(bad, "AOS8-AP-TELNET-DEBUG-001") == "fail"
    good = 'ap system-profile "default"\n  ap-console-protection\n'
    assert _status(good, "AOS8-AP-CONSOLE-PROTECT-001") == "pass"
    assert _status(good, "AOS8-AP-TELNET-DEBUG-001") == "pass"
    assert _status("hostname w\n", "AOS8-AP-CONSOLE-PROTECT-001") == "manual"
    assert _status("hostname w\n", "AOS8-AP-TELNET-DEBUG-001") == "manual"


def test_enforce_dhcp_only_scores_referenced_profiles():
    # ArubaOS ships unused factory 'default-*' AAA profiles; failing on those
    # would be noise, so only profiles a virtual AP points at are checked.
    rc = ("wlan virtual-ap V\n  aaa-profile CORP\n"
          "aaa profile CORP\n  enforce-dhcp\n"
          "aaa profile default-dot1x\n")
    assert _facts(rc)["aaa_enforce_dhcp"] is True
    rc2 = ("wlan virtual-ap V\n  aaa-profile CORP\n"
           "aaa profile CORP\n  initial-role guest\n")
    assert _facts(rc2)["aaa_enforce_dhcp"] is False
    assert _facts("hostname w\n")["aaa_enforce_dhcp"] is None
    assert _status(rc, "AOS8-AAA-ENFORCE-DHCP-001") == "pass"
    assert _status(rc2, "AOS8-AAA-ENFORCE-DHCP-001") == "warn"


def test_ra_guard_only_evaluated_when_ipv6_required():
    rc = "user-role corp\n  access-list session ra-guard\n"
    assert _facts(rc)["ra_guard_applied"] is True
    assert _facts("user-role corp\n  access-list session allowall\n")["ra_guard_applied"] is False
    assert _facts("hostname w\n")["ra_guard_applied"] is None
    assert _status(rc, "AOS8-ROLE-RA-GUARD-001") == "pass"
    assert _status("user-role corp\n  access-list session allowall\n",
                   "AOS8-ROLE-RA-GUARD-001") == "warn"
    assert _status(rc, "AOS8-ROLE-RA-GUARD-001", org={**ORG, "ipv6_required": False}) == "not_applicable"


# --------------------------------------------------------------------------
# The two named fixes: password-policy tiering and local-auth gating
# --------------------------------------------------------------------------

def test_password_policy_splits_enabled_from_length():
    none_at_all = _facts("hostname w\n")
    assert none_at_all["password_policy_enabled"] is None
    assert none_at_all["password_policy_ok"] is None
    short = _facts("aaa password-policy mgmt\n  enable\n  password-min-length 8\n")
    assert short["password_policy_enabled"] is True
    assert short["password_min_length"] == 8
    assert short["password_policy_ok"] is False
    federal = _facts("aaa password-policy mgmt\n  enable\n  password-min-length 15\n")
    assert federal["password_policy_ok"] is True
    out = {"show aaa password-policy mgmt":
           "Enable password policy   No\nMinimum password length required   8\n"}
    assert _facts("", out)["password_policy_enabled"] is False


def test_password_policy_control_warns_below_fifteen_and_fails_when_off():
    # 2023 Controller guide baseline (8) met, 2020 federal bar (15) not -> warn.
    short = "aaa password-policy mgmt\n  enable\n  password-min-length 8\n"
    assert _status(short, "AOS8-MGMT-PWDPOL-001") == "warn"
    federal = "aaa password-policy mgmt\n  enable\n  password-min-length 15\n"
    assert _status(federal, "AOS8-MGMT-PWDPOL-001") == "pass"
    off = {"show aaa password-policy mgmt": "Enable password policy   No\n"}
    assert _status("hostname w\n", "AOS8-MGMT-PWDPOL-001", off) == "fail"
    assert _status("hostname w\n", "AOS8-MGMT-PWDPOL-001") == "manual"


def test_localauth_control_gated_to_high_security_and_fips():
    rc = "hostname w\n"
    out = {"show mgmt-user local-authentication-mode": "Local Authentication Mode: Enabled\n"}
    assert _status(rc, "AOS8-MGMT-LOCALAUTH-001", out) == "fail"
    baseline_org = {**ORG, "deployment_profile": "baseline"}
    assert _status(rc, "AOS8-MGMT-LOCALAUTH-001", out, org=baseline_org,
                   profile="baseline") == "not_applicable"


# --------------------------------------------------------------------------
# Citation provenance (F3)
# --------------------------------------------------------------------------

def test_references_carry_a_document_discriminator():
    by_id = {c.id: c for c in CONTROLS}
    pwdpol = by_id["AOS8-MGMT-PWDPOL-001"]
    docs = {r.document for r in pwdpol.references}
    assert docs == {GuideDocument.FEDERAL_2020, GuideDocument.CONTROLLER_2023}
    # Controls written from the 2023 guide must not claim the 2020 federal one.
    for cid in ("AOS8-CRYPTO-TKIP-001", "AOS8-FW-IPSPOOF-001", "AOS8-CPSEC-001"):
        assert all(r.document is GuideDocument.CONTROLLER_2023 for r in by_id[cid].references), cid
    # Pre-existing controls keep the federal default with no edits.
    assert all(r.document is GuideDocument.FEDERAL_2020
               for r in by_id["AOS8-MGMT-CERT-001"].references)


# --------------------------------------------------------------------------
# Open-port exposure (guide p.9-14 controller ports, p.30-53 control plane)
# --------------------------------------------------------------------------

def test_telnet_cli_enabled_fact():
    assert _facts("telnet cli\n")["telnet_cli_enabled"] is True
    assert _facts("telnet soe\n")["telnet_cli_enabled"] is True
    assert _facts("no telnet cli\n")["telnet_cli_enabled"] is False
    # Off by default: a config that never mentions telnet has it disabled.
    assert _facts("hostname w\n")["telnet_cli_enabled"] is False
    # No running-config at all -> undeterminable, not "off".
    assert _facts("")["telnet_cli_enabled"] is None


def test_dns_responder_enabled_fact():
    # On by default; only an explicit 'no ip domain lookup' turns it off.
    assert _facts("hostname w\n")["dns_responder_enabled"] is True
    assert _facts("no ip domain lookup\n")["dns_responder_enabled"] is False
    assert _facts("ip domain lookup\n")["dns_responder_enabled"] is True
    assert _facts("")["dns_responder_enabled"] is None


def test_captive_portal_in_use_is_keyed_off_roles_not_profiles():
    in_use = "user-role guest\n  captive-portal guest-cp\n"
    assert _facts(in_use)["captive_portal_in_use"] is True
    # ArubaOS ships a factory 'default' captive-portal profile on every
    # controller, so a bare profile stanza must NOT count as in use.
    ships_by_default = ("aaa authentication captive-portal \"default\"\n"
                        "  server-group internal\n"
                        "user-role authenticated\n  access-list session allowall\n")
    assert _facts(ships_by_default)["captive_portal_in_use"] is False
    # No roles visible at all -> undeterminable.
    assert _facts("hostname w\n")["captive_portal_in_use"] is None


def test_cp_denies_captive_portal_fact():
    # The guide's own example rules for an unused captive portal.
    denied = ("firewall cp\n"
              "  ipv4 deny any proto 6 ports 8080 8083\n"
              "  ipv4 deny any proto 6 ports 8088 8088\n")
    assert _facts(denied)["cp_denies_captive_portal"] is True
    # Covering only 8080-8083 leaves 8088 open -> not satisfied.
    partial = "firewall cp\n  ipv4 deny any proto 6 ports 8080 8083\n"
    assert _facts(partial)["cp_denies_captive_portal"] is False
    # A permit over the same range is not a deny.
    permit = ("firewall cp\n"
              "  ipv4 permit any proto 6 ports 8080 8083\n"
              "  ipv4 permit any proto 6 ports 8088 8088\n")
    assert _facts(permit)["cp_denies_captive_portal"] is False
    # No control-plane ACL evidence at all -> undeterminable, never "not denied".
    assert _facts("hostname w\n")["cp_denies_captive_portal"] is None


def test_dns_responder_control_warns_when_left_on():
    assert _status("no ip domain lookup\n", "AOS8-PORTS-DNS-RESPONDER-001") == "pass"
    assert _status("hostname w\n", "AOS8-PORTS-DNS-RESPONDER-001") == "warn"


def test_captive_portal_port_control_paths():
    denied = ("firewall cp\n"
              "  ipv4 deny any proto 6 ports 8080 8083\n"
              "  ipv4 deny any proto 6 ports 8088 8088\n")
    assert _status(denied, "AOS8-PORTS-CAPTIVE-PORTAL-001") == "pass"
    # Captive portal actually in use -> the ports are needed, nothing to score.
    in_use = "user-role guest\n  captive-portal guest-cp\n"
    assert _status(in_use, "AOS8-PORTS-CAPTIVE-PORTAL-001") == "not_applicable"
    # Unused, control-plane ACL present, ports left open -> warn.
    open_ports = ("user-role authenticated\n  access-list session allowall\n"
                  "firewall cp\n  ipv4 permit any proto 6 ports 8080 8083\n")
    assert _status(open_ports, "AOS8-PORTS-CAPTIVE-PORTAL-001") == "warn"
    # No control-plane ACL evidence -> manual, never a guessed warn.
    assert _status("hostname w\n", "AOS8-PORTS-CAPTIVE-PORTAL-001") == "manual"
