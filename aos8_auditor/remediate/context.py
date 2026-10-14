"""What the audited controller already has, for validating and completing fields.

Everything here is read out of the evidence bundle that was already collected —
no probing, no second session. It exists so the wizard can say "VLAN 220 exists
in the running config as 'mgmt'" instead of only "220 is in range", and so a
typo'd interface or a collision with the controller's own address is caught
before the change reaches a window rather than after.

All of it is advisory: an unknown name or VLAN produces a warning, never a block.
Operators legitimately create new objects, and the running config is a snapshot.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_OBJECT_KINDS: dict[str, tuple[str, ...]] = {
    # field-name -> config keywords whose LAST argument is the object's name
    "aaa_profiles": ("aaa profile",),
    "server_groups": ("aaa server-group",),
    "auth_servers": ("aaa authentication-server radius", "aaa authentication-server ldap",
                     "aaa authentication-server tacacs"),
    "dot1x_profiles": ("aaa authentication dot1x",),
    "user_roles": ("user-role",),
    "session_acls": ("ip access-list session",),
    "ssid_profiles": ("wlan ssid-profile",),
    "virtual_aps": ("wlan virtual-ap",),
    "ap_groups": ("ap-group",),
    "ap_system_profiles": ("ap system-profile",),
    "netdestinations": ("netdestination",),
}

# A command's arguments are on the same line as the command. ``\s`` includes the
# newline, so a keyword that can appear with no argument at all — 'interface mgmt'
# is the one that bites — otherwise reaches over the line break and captures the
# first word of the line below it, and the controller acquires an interface
# called 'shutdown'. Horizontal whitespace only, everywhere an argument is read.
_H = r"[ \t]"
_VLAN_IF_RE = re.compile(rf"(?im)^{_H}*interface{_H}+vlan{_H}+(\d+){_H}*$")
_VLAN_RE = re.compile(rf"(?im)^{_H}*vlan{_H}+(\d[\d,\- \t]*){_H}*$")
_VLAN_NAME_RE = re.compile(rf"(?im)^{_H}*vlan-name{_H}+(\S+){_H}+vlan{_H}+(\d+)")
_PHYS_IF_RE = re.compile(rf"(?im)^{_H}*interface{_H}+(?:gigabitethernet|fastethernet|"
                         rf"xgigabitethernet|tengigabitethernet|mgmt){_H}+(\S+)")
_IP_ADDR_RE = re.compile(rf"(?im)^{_H}*ip{_H}+address{_H}+(\d+\.\d+\.\d+\.\d+)")
_CTRL_IP_RE = re.compile(rf"(?im)^{_H}*controller-ip{_H}+vlan{_H}+(\d+)")


@dataclass
class DeviceContext:
    """Facts from the audited config that make field validation concrete."""

    host: str | None = None
    hostname: str | None = None
    node_path: str = "/"
    vlans: set[int] = field(default_factory=set)
    vlan_names: dict[int, str] = field(default_factory=dict)
    interfaces: set[str] = field(default_factory=set)
    own_ips: set[str] = field(default_factory=set)
    controller_ip_vlan: int | None = None
    objects: dict[str, set[str]] = field(default_factory=dict)

    def names_of(self, *kinds: str) -> list[str]:
        out: set[str] = set()
        for k in kinds:
            out |= self.objects.get(k, set())
        return sorted(out)

    @property
    def all_object_names(self) -> list[str]:
        out: set[str] = set()
        for v in self.objects.values():
            out |= v
        return sorted(out)

    def vlan_label(self, vid: int) -> str | None:
        return self.vlan_names.get(vid)


def _expand_vlan_list(spec: str) -> set[int]:
    """'100,200-202' -> {100, 200, 201, 202}."""
    out: set[int] = set()
    for part in re.split(r"[,\s]+", spec.strip()):
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit() and int(lo) <= int(hi):
                out |= set(range(int(lo), min(int(hi), 4094) + 1))
        elif part.isdigit():
            out.add(int(part))
    return {v for v in out if 1 <= v <= 4094}


def context_from_config(config_text: str, *, host: str | None = None,
                        node_path: str = "/") -> DeviceContext:
    """Build a :class:`DeviceContext` from sanitized running-config text."""
    ctx = DeviceContext(host=host, node_path=node_path)

    for m in _VLAN_IF_RE.finditer(config_text):
        ctx.vlans.add(int(m.group(1)))
    for m in _VLAN_RE.finditer(config_text):
        ctx.vlans |= _expand_vlan_list(m.group(1))
    for m in _VLAN_NAME_RE.finditer(config_text):
        ctx.vlan_names[int(m.group(2))] = m.group(1)
        ctx.vlans.add(int(m.group(2)))
    for m in _PHYS_IF_RE.finditer(config_text):
        ctx.interfaces.add(m.group(1))
    for m in _IP_ADDR_RE.finditer(config_text):
        ctx.own_ips.add(m.group(1))
    m = _CTRL_IP_RE.search(config_text)
    if m:
        ctx.controller_ip_vlan = int(m.group(1))
    m = re.search(rf"(?im)^{_H}*hostname{_H}+(\S+)", config_text)
    if m:
        ctx.hostname = m.group(1).strip('"')

    for fieldname, keywords in _OBJECT_KINDS.items():
        found: set[str] = set()
        for kw in keywords:
            pat = re.compile(
                rf"(?im)^{_H}*{re.escape(kw)}{_H}+(\"[^\"]+\"|\S+){_H}*$")
            for m in pat.finditer(config_text):
                found.add(m.group(1).strip('"'))
        if found:
            ctx.objects[fieldname] = found
    return ctx


def context_from_model(model, *, host: str | None = None) -> DeviceContext:
    """Build a context from a parsed :class:`ControllerModel`."""
    ident = getattr(model, "identity", None)
    ctx = context_from_config(
        model.running_config_text,
        host=host or (ident.host if ident else None),
        node_path=getattr(model, "node_path", "/"),
    )
    if ident is not None and getattr(ident, "host", None):
        # The audit target address is the one an operator is most likely to lock
        # themselves out of, whether or not it appears in the config text.
        ctx.own_ips.add(ident.host)
    return ctx
