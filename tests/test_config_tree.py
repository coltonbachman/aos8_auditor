"""The running-config tree parser: indentation + '!' blocks, query helpers."""

from aos8_auditor.parse.config_tree import parse_config

SAMPLE = """version 8.6.0.4
hostname "JITC7240"
no spanning-tree
web-server profile
  session-timeout 360
  mgmt-auth certificate
!
netdestination AOS-Controllers
  host 10.10.100.254 position 1
  host 10.10.101.254 position 2
!
interface vlan 1
  no ip address
  shutdown
interface gigabitethernet 0/0/2
  ip access-group AOS-Admin-Only-Policy session
"""


def test_top_level_keywords():
    root = parse_config(SAMPLE)
    kws = [c.keyword for c in root.children]
    assert "version" in kws and "web-server" in kws and "netdestination" in kws
    # Child lines did not leak to the top level.
    assert "session-timeout" not in kws
    assert "host" not in kws


def test_block_children_attached():
    root = parse_config(SAMPLE)
    ws = root.find("web-server")
    assert ws is not None
    assert ws.has_child("session-timeout")
    assert ws.child("session-timeout").args == ["360"]
    assert ws.has_child("mgmt-auth")


def test_bang_terminates_block():
    root = parse_config(SAMPLE)
    nd = root.find("netdestination")
    # netdestination block has its two hosts; the following 'interface' is a sibling.
    assert len(nd.find_all("host")) == 2
    # order preserved (position matters)
    assert nd.find_all("host")[0].args[0] == "10.10.100.254"


def test_dedent_terminates_block_without_bang():
    root = parse_config(SAMPLE)
    interfaces = root.find_all("interface")
    assert len(interfaces) == 2
    vlan1 = interfaces[0]
    assert vlan1.matches("interface", "vlan", "1")
    assert vlan1.has_child("shutdown")
    # the 'no ip address' child is present and distinct from a bare 'ip'
    assert any(c.matches("no", "ip", "address") for c in vlan1.children)


def test_find_all_deep_and_matches():
    root = parse_config(SAMPLE)
    assert root.find("no").matches("no", "spanning-tree")
    # 'ip access-group ...' is nested under the gigabitethernet interface; the
    # node keyword is 'ip' with 'access-group' as its first arg.
    deep = [n for n in root.find_all_deep("ip") if n.matches("ip", "access-group")]
    assert len(deep) == 1 and deep[0].args[1] == "AOS-Admin-Only-Policy"


def test_tabs_and_ragged_indent():
    txt = "aaa profile P\n\tauthentication-dot1x default\n        dot1x-default-role authd\n"
    root = parse_config(txt)
    p = root.find("aaa")
    assert p.has_child("authentication-dot1x")
    assert p.has_child("dot1x-default-role")
