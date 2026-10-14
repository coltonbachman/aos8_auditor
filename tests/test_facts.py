"""Facts-extractor regressions from the Phase 1 red-team (false pass/fail)."""

from aos8_auditor.parse.model_builder import build_controller_model

from support import make_collection


def _facts(rc="", outputs=None):
    return build_controller_model(make_collection(rc, outputs or {})).facts


def test_syslog_only_counts_real_hosts():
    assert _facts("logging trap warnings\n")["syslog_server_count"] == 0
    assert _facts("logging level warnings\n")["syslog_server_count"] == 0
    assert _facts("logging 10.10.100.200\n")["syslog_server_count"] == 1
    assert _facts("logging syslog.example.gov\n")["syslog_server_count"] == 1


def test_rfprotect_tabular_license():
    out = {"show license summary": "Service    Total Used Remaining\nRFProtect  100   50   50\n"}
    assert _facts("", out)["rfprotect_licensed"] is True
    out2 = {"show license summary": "RFProtect  Expired\n"}
    assert _facts("", out2)["rfprotect_licensed"] is False


def test_controller_loopback_no_is_not_loopback():
    f = _facts("", {"show controller-ip": "Switch IP is Configured to Loopback: No\n"})
    assert f["controller_ip_source"] is None  # -> control degrades to manual
    f2 = _facts("controller-ip loopback 0\n")
    assert f2["controller_ip_source"] == "loopback"


def test_password_policy_real_output_format():
    out = {"show aaa password-policy mgmt":
           "Enable password policy        Yes\nMinimum password length required   15\n"}
    f = _facts("", out)
    assert f["password_policy_ok"] is True and f["password_min_length"] == 15


def test_snmp_v3_secure_requires_all_users_strong():
    weak = ("snmp-server user a auth-prot sha X priv-prot aes Y\n"
            "snmp-server user b auth-prot md5 X priv-prot des Y\n")
    assert _facts(weak)["snmp_v3_secure"] is False
    strong = ("snmp-server user a auth-prot sha X priv-prot aes Y\n"
              "snmp-server user b auth-prot sha X priv-prot aes Y\n")
    assert _facts(strong)["snmp_v3_secure"] is True


def test_ap_database_header_and_named_default():
    out = {"show ap database":
           "AP Database\nName     Group   Status\n"
           "ap01     corp    Up\n"
           "default  corp    Up\n"      # AP NAMED default, group corp -> not counted
           "ap03     default Up\n"      # group default -> counted
           "Flags: U = Up\nI = Inactive; D = Dirty\nTotal APs:3\n"}
    f = _facts("", out)
    assert f["aps_total"] == 3
    assert f["aps_in_default"] == 1


def test_permit_all_equivalents_detected():
    assert _facts("ip access-list session R\n  any any any permit\n")["any_any_any_permit"] is True
    assert _facts("ip access-list session R\n  network 0.0.0.0 0.0.0.0 any permit\n")["any_any_any_permit"] is True
    assert _facts("ip access-list session R\n  user host 10.0.0.1 svc-dns permit\n")["any_any_any_permit"] is False


def test_external_auth_via_server_group_without_enable():
    rc = ("aaa authentication-server radius RAD1\n  host 10.0.0.1\n"
          "aaa server-group G\n  auth-server RAD1\n")
    assert _facts(rc)["external_auth_present"] is True


def test_admin_policy_binding_is_found_in_either_argument_order():
    """ArubaOS spells the interface binding two ways across trains, and only one
    of them parses on 8.13. Reading the policy name from a fixed offset found
    'session' there and reported a controller that had done exactly the right
    thing as not having done it -- the audit's own remediation, applied, still
    failing on the next run."""
    acl = "ip access-list session ADMIN\n  user any tcp 4343 permit\n"
    train_813 = acl + "interface gigabitethernet 0/0/0\n  ip access-group session ADMIN\n"
    guide_order = acl + "interface gigabitethernet 0/0/0\n  ip access-group ADMIN session\n"
    for rc in (train_813, guide_order):
        f = _facts(rc)
        assert f["admin_policy_defined"] is True
        assert f["admin_policy_applied"] is True
    unbound = _facts(acl + "interface gigabitethernet 0/0/0\n  no trusted\n")
    assert unbound["admin_policy_defined"] is True
    assert unbound["admin_policy_applied"] is False
