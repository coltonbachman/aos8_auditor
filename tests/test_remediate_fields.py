"""Field typing, collision handling and validation."""

import pytest

from aos8_auditor.remediate.context import DeviceContext, context_from_config
from aos8_auditor.remediate.fields import (
    Field,
    FieldType,
    fields_for,
    infer_type,
    remaining_placeholders,
    render_line,
)
from aos8_auditor.remediate.validate import completions, validate

CONFIG = """\
hostname wlc-lab
vlan 100
vlan-name mgmt vlan 220
interface vlan 220
 ip address 10.20.30.5 255.255.255.0
interface gigabitethernet 0/0/1
 description uplink
controller-ip vlan 220
aaa server-group corp-servers
aaa authentication-server radius corp-radius
user-role authenticated
"""


@pytest.mark.parametrize("placeholder,command,expected", [
    ("<ip>", "host <ip>", FieldType.IP),
    ("<mask>", "ip address <ip> <mask>", FieldType.NETMASK),
    ("<id>", "interface vlan <id>", FieldType.VLAN_ID),
    ("<id>", "vrrp <id>", FieldType.NUMBER),
    ("<secret>", "key <secret>", FieldType.SECRET),
    ("<key>", "wpa-passphrase <key>", FieldType.SECRET),
    ("<port>", "interface gigabitethernet <port>", FieldType.INTERFACE),
    ("<delim>", "banner motd <delim>", FieldType.DELIMITER),
    ("<approved text>", "banner motd <delim> <approved text> <delim>", FieldType.TEXT),
    ("<name>", "aaa server-group <name>", FieldType.NAME),
])
def test_infer_type(placeholder, command, expected):
    assert infer_type(placeholder, command) is expected


def test_ntp_key_id_is_a_number_not_a_secret():
    """Regression: 'key' means the next token is a credential, but 'ntp server
    <ip> key <id>' names a key ID. Typing it SECRET would mask it and refuse the
    documented default."""
    assert infer_type("<id>", "ntp server <ip> key <id>") is FieldType.NUMBER


def test_same_placeholder_different_meaning_is_two_fields():
    fields = fields_for(["vrrp <id>", "vlan <id>"])
    assert len(fields) == 2
    assert {f.type for f in fields} == {FieldType.NUMBER, FieldType.VLAN_ID}


def test_same_placeholder_same_meaning_is_one_field():
    fields = fields_for(["ntp server <ip>", "logging <ip>"])
    assert len(fields) == 1
    assert fields[0].line_indexes == [0, 1]


def test_render_line_does_not_cross_contaminate_colliding_placeholders():
    """Each line gets only the field that governs it — otherwise the VRRP router
    id lands in the VLAN command."""
    commands = ["vrrp <id>", "vlan <id>"]
    fields = fields_for(commands)
    for f in fields:
        f.value = "7" if f.type is FieldType.NUMBER else "220"
    assert render_line(commands[0], fields) == "vrrp 7"
    assert render_line(commands[1], fields) == "vlan 220"


def test_unfilled_placeholders_survive_rendering():
    commands = ["logging <syslog-server-ip>"]
    assert remaining_placeholders(render_line(commands[0], fields_for(commands)))


def test_secrets_are_masked_on_request():
    f = Field(placeholder="<secret>", type=FieldType.SECRET, value="hunter2hunter2")
    f.used_in = ["key <secret>"]
    assert "hunter2" not in render_line("key <secret>", [f], mask_secrets=True)
    assert render_line("key <secret>", [f]) == "key hunter2hunter2"


# -- validation -----------------------------------------------------------

def _field(ftype, placeholder="<x>", command=""):
    f = Field(placeholder=placeholder, type=ftype)
    if command:
        f.used_in = [command]
    return f


def test_vlan_out_of_range_blocks():
    r = validate(_field(FieldType.VLAN_ID), "9000")
    assert not r.ok and "out of range" in r.message


def test_vlan_not_in_config_only_warns():
    """Operators create VLANs; the config is a snapshot, so this cannot block."""
    ctx = context_from_config(CONFIG)
    r = validate(_field(FieldType.VLAN_ID), "300", ctx)
    assert r.ok and r.warning


def test_vlan_in_config_reports_its_name():
    ctx = context_from_config(CONFIG)
    r = validate(_field(FieldType.VLAN_ID), "220", ctx)
    assert r.ok and not r.warning and "mgmt" in r.message


def test_controllers_own_address_warns():
    ctx = context_from_config(CONFIG)
    r = validate(_field(FieldType.IP), "10.20.30.5", ctx)
    assert r.ok and r.warning and "own address" in r.message


def test_documented_default_secret_is_an_error():
    assert not validate(_field(FieldType.SECRET), "aruba123").ok


def test_short_secret_warns_but_is_allowed():
    r = validate(_field(FieldType.SECRET), "short")
    assert r.ok and r.warning


def test_empty_is_always_an_error():
    for ftype in FieldType:
        assert not validate(_field(ftype), "   ").ok


def test_bad_netmask_blocks():
    assert not validate(_field(FieldType.NETMASK), "255.0.255.0").ok
    assert validate(_field(FieldType.NETMASK), "255.255.255.0").ok


def test_delimiter_must_be_one_punctuation_character():
    assert not validate(_field(FieldType.DELIMITER), "ab").ok
    assert not validate(_field(FieldType.DELIMITER), "a").ok
    assert validate(_field(FieldType.DELIMITER), "^").ok


def test_completions_offer_only_the_right_kind_of_name():
    ctx = context_from_config(CONFIG)
    group = _field(FieldType.NAME, "<name>", "aaa server-group <name>")
    assert completions(group, ctx) == ["corp-servers"]
    role = _field(FieldType.NAME, "<name>", "user-role <name>")
    assert completions(role, ctx) == ["authenticated"]


def test_completions_for_interfaces_and_vlans():
    ctx = context_from_config(CONFIG)
    assert completions(_field(FieldType.INTERFACE), ctx) == ["0/0/1"]
    assert completions(_field(FieldType.VLAN_ID), ctx) == ["100", "220"]


def test_context_without_a_config_never_blocks():
    ctx = DeviceContext()
    assert validate(_field(FieldType.VLAN_ID), "300", ctx).ok
    assert validate(_field(FieldType.INTERFACE), "0/0/9", ctx).ok


# -- names of things that have to exist already ---------------------------
#
# A mistyped name is the one field type that produces a command the controller
# rejects on sight while looking perfectly well-formed on screen, so it is worth
# the same warning VLANs and interfaces already get.

REF_CONFIG = CONFIG + """\
ip access-list session validate-mgmt
 any any svc-https permit
interface mgmt
 shutdown
"""


def test_binding_to_an_acl_the_controller_does_not_have_warns():
    ctx = context_from_config(REF_CONFIG)
    f = _field(FieldType.NAME, "<admin-policy>", "ip access-group session <admin-policy>")
    r = validate(f, "testing-admin-policy", ctx)
    assert r.ok and r.warning
    assert "session ACL" in r.message and "testing-admin-policy" in r.message


def test_binding_to_an_acl_the_controller_has_is_accepted_quietly():
    ctx = context_from_config(REF_CONFIG)
    f = _field(FieldType.NAME, "<admin-policy>", "ip access-group session <admin-policy>")
    r = validate(f, "validate-mgmt", ctx)
    assert r.ok and not r.warning


def test_a_name_the_change_itself_creates_is_not_second_guessed():
    """'ip access-list session <name>' is how a new ACL comes into being."""
    ctx = context_from_config(REF_CONFIG)
    f = _field(FieldType.NAME, "<name>", "ip access-list session <name>")
    r = validate(f, "brand-new-policy", ctx)
    assert r.ok and not r.warning


def test_a_role_bound_by_a_profile_is_checked_too():
    ctx = context_from_config(REF_CONFIG)
    f = _field(FieldType.NAME, "<role>", "dot1x-default-role <role>")
    assert validate(f, "authenticated", ctx).warning is False
    r = validate(f, "typoed-role", ctx)
    assert r.ok and r.warning and "user role" in r.message


def test_a_kind_the_config_never_mentioned_is_not_guessed_at():
    """CONFIG has no session ACLs at all: silence beats a warning we cannot back."""
    ctx = context_from_config(CONFIG)
    f = _field(FieldType.NAME, "<admin-policy>", "ip access-group session <admin-policy>")
    assert not validate(f, "anything-at-all", ctx).warning


def test_a_name_in_no_known_command_is_left_alone():
    ctx = context_from_config(REF_CONFIG)
    f = _field(FieldType.NAME, "<label>", "banner motd <label>")
    assert validate(f, "whatever", ctx).ok


def test_a_syntactically_impossible_name_is_still_an_error_first():
    ctx = context_from_config(REF_CONFIG)
    f = _field(FieldType.NAME, "<admin-policy>", "ip access-group session <admin-policy>")
    assert not validate(f, "has spaces").ok
    assert not validate(f, "has spaces", ctx).ok


def test_interface_mgmt_does_not_invent_an_interface_from_the_next_line():
    """'interface mgmt' takes no port, and \\s spans newlines: 0/0/1 only."""
    ctx = context_from_config(REF_CONFIG)
    assert ctx.interfaces == {"0/0/1"}
    assert "shutdown" not in ctx.interfaces


def test_an_argument_is_read_from_its_own_line_only():
    ctx = context_from_config("interface vlan\n 220\nvlan\n 300\nnetdestination\n corp\n")
    assert ctx.vlans == set()
    assert ctx.objects.get("netdestinations", set()) == set()
