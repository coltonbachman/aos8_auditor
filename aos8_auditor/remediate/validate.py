"""Per-field validation.

The wizard validates a field the moment it is entered, not the line when it is
accepted, which is the whole reason for typing the placeholders. Two levels:

* **error**  — the value cannot be right (VLAN 4200, a malformed address). The
  change cannot be accepted; it can always still be skipped.
* **warning** — the value is syntactically fine but does not match what the
  audited config shows (a VLAN that does not exist yet, an interface this model
  does not have, the controller's own address). Operators create new objects all
  the time and the config is a snapshot, so these never block.

Reachability, credential correctness and "does the RADIUS server actually answer"
are explicitly out of scope: nothing here touches the network.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .context import DeviceContext
from .fields import Field, FieldType

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,62}$")
_INTERFACE_RE = re.compile(r"^\d+(/\d+){0,2}$")
# Values the guide names explicitly as defaults that must not survive hardening.
_KNOWN_WEAK_SECRETS = frozenset({"aruba123", "admin", "password", "changeme", "public", "private"})


@dataclass(frozen=True)
class ValidationResult:
    ok: bool           # False blocks acceptance
    message: str = ""
    warning: bool = False

    @property
    def level(self) -> str:
        return "error" if not self.ok else ("warn" if self.warning else "ok")


_OK = ValidationResult(True)


def _err(msg: str) -> ValidationResult:
    return ValidationResult(False, msg)


def _warn(msg: str) -> ValidationResult:
    return ValidationResult(True, msg, warning=True)


def validate(f: Field, value: str, ctx: DeviceContext | None = None) -> ValidationResult:
    """Validate ``value`` for field ``f`` against the audited config."""
    v = value.strip() if f.type is not FieldType.TEXT else value
    if not v.strip():
        return _err("required")
    if "\n" in v and f.type is not FieldType.TEXT:
        return _err("must be a single line")
    ctx = ctx or DeviceContext()
    result = _VALIDATORS[f.type](v, ctx)
    if f.type is FieldType.NAME and result.ok and not result.warning:
        # Only once the name is syntactically fine, and never in place of a
        # warning the type validator already raised.
        return _check_name_exists(f, v, ctx)
    return result


def _validate_ip(v: str, ctx: DeviceContext) -> ValidationResult:
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return _err(f"{v} is not an IP address")
    if v in ctx.own_ips:
        return _warn(f"{v} is this controller's own address — check that is intended")
    if addr.version == 4 and (addr.is_loopback or addr.is_multicast or addr.is_unspecified):
        return _warn(f"{v} is not a normal host address")
    return ValidationResult(True, f"valid IPv{addr.version} · reachability is not tested")


def _validate_netmask(v: str, ctx: DeviceContext) -> ValidationResult:
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{v}")
    except ValueError:
        return _err(f"{v} is not a valid subnet mask")
    return _OK


def _validate_vlan(v: str, ctx: DeviceContext) -> ValidationResult:
    if not v.isdigit():
        return _err("VLAN id must be an integer")
    vid = int(v)
    if not 1 <= vid <= 4094:
        return _err(f"{vid} is out of range (1-4094)")
    if vid == 1:
        return _warn("VLAN 1 is the default VLAN — the guide advises against using it")
    if ctx.vlans and vid not in ctx.vlans:
        return _warn(f"VLAN {vid} is not in the audited running config — it must exist first")
    label = ctx.vlan_label(vid)
    return ValidationResult(True, f'{vid} · exists in the running config as "{label}"' if label
                            else f"{vid} · exists in the running config")


def _validate_interface(v: str, ctx: DeviceContext) -> ValidationResult:
    if not _INTERFACE_RE.match(v):
        return _err(f"{v} is not an interface — expected slot/module/port, e.g. 0/0/1")
    if ctx.interfaces and v not in ctx.interfaces:
        return _warn(f"{v} is not an interface seen on this controller")
    return _OK


def _validate_name(v: str, ctx: DeviceContext) -> ValidationResult:
    if not _NAME_RE.match(v):
        return _err("names may use letters, digits and - _ . : (max 63, no spaces)")
    return _OK


# Lines that *create* an object. A name in one of these is new by definition and
# warning that the controller has never heard of it would be backwards.
_NAME_DEFINITIONS: tuple[str, ...] = (
    "ip access-list", "user-role", "aaa profile", "aaa server-group",
    "aaa authentication-server", "aaa authentication dot1x", "wlan ssid-profile",
    "wlan virtual-ap", "ap-group", "ap system-profile", "netdestination",
)

# Lines that *bind* to an object the controller must already have, and what to
# call the missing thing when it does not. First match wins, so the longer forms
# come before the ones they start with.
_NAME_REFERENCES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("ip access-group", ("session_acls",), "session ACL"),
    ("session-acl", ("session_acls",), "session ACL"),
    ("dot1x-server-group", ("server_groups",), "server group"),
    ("mac-server-group", ("server_groups",), "server group"),
    ("server-group", ("server_groups",), "server group"),
    ("auth-server", ("auth_servers",), "authentication server"),
    ("authentication-dot1x", ("dot1x_profiles",), "802.1X authentication profile"),
    ("aaa-profile", ("aaa_profiles",), "AAA profile"),
    ("ssid-profile", ("ssid_profiles",), "SSID profile"),
    ("virtual-ap", ("virtual_aps",), "virtual AP profile"),
    ("ap-system-profile", ("ap_system_profiles",), "AP system profile"),
    ("dot1x-default-role", ("user_roles",), "user role"),
    ("mac-default-role", ("user_roles",), "user role"),
    ("initial-role", ("user_roles",), "user role"),
    ("default-role", ("user_roles",), "user role"),
    ("set role", ("user_roles",), "user role"),
)


def _name_reference(f: Field) -> tuple[tuple[str, ...], str] | None:
    """The kind of object this field has to name already, if it has to name one."""
    cmds = [c.lower().strip() for c in f.used_in]
    if any(c.startswith(d) for c in cmds for d in _NAME_DEFINITIONS):
        return None  # this change creates it
    for cmd in cmds:
        for needle, kinds, label in _NAME_REFERENCES:
            if cmd.startswith(needle):
                return kinds, label
    return None


def _check_name_exists(f: Field, v: str, ctx: DeviceContext) -> ValidationResult:
    """Warn when a field names an object the audited config does not contain.

    The same courtesy VLANs and interfaces already get. A name is the one field
    type where a typo produces a command that is perfectly well-formed and that
    the controller rejects on sight, and finding that out at the field costs a
    keystroke where finding it out during the apply costs a stopped run and a
    half-applied block.
    """
    ref = _name_reference(f)
    if ref is None:
        return _OK
    kinds, label = ref
    known = ctx.names_of(*kinds)
    if not known:
        return _OK  # nothing of this kind was parsed; silence beats guessing
    if v in known:
        return ValidationResult(True, f"{v} · exists in the running config")
    return _warn(f"no {label} named {v!r} in the audited config — the controller "
                 "will reject this unless it exists by the time it is applied")


def _validate_number(v: str, ctx: DeviceContext) -> ValidationResult:
    if not v.lstrip("-").isdigit():
        return _err("must be an integer")
    return _OK


def _validate_secret(v: str, ctx: DeviceContext) -> ValidationResult:
    if v.lower() in _KNOWN_WEAK_SECRETS:
        return _err(f"{v!r} is a documented default — the guide requires it be replaced")
    if len(v) < 8:
        return _warn(f"{len(v)} characters — short for a shared secret")
    return ValidationResult(True, "masked on screen; strength is not otherwise checked")


def _validate_delimiter(v: str, ctx: DeviceContext) -> ValidationResult:
    if len(v) != 1:
        return _err("the delimiter is a single character")
    if v.isalnum() or v.isspace():
        return _err("use a punctuation character, not a letter, digit or space")
    return _OK


def _validate_text(v: str, ctx: DeviceContext) -> ValidationResult:
    if "\r" in v:
        return _err("carriage returns are not accepted")
    return _OK


_VALIDATORS = {
    FieldType.IP: _validate_ip,
    FieldType.NETMASK: _validate_netmask,
    FieldType.VLAN_ID: _validate_vlan,
    FieldType.INTERFACE: _validate_interface,
    FieldType.NAME: _validate_name,
    FieldType.NUMBER: _validate_number,
    FieldType.SECRET: _validate_secret,
    FieldType.DELIMITER: _validate_delimiter,
    FieldType.TEXT: _validate_text,
}


def completions(f: Field, ctx: DeviceContext) -> list[str]:
    """Existing values from the audited config that would fit this field."""
    if f.type is FieldType.INTERFACE:
        return sorted(ctx.interfaces)
    if f.type is FieldType.VLAN_ID:
        return [str(v) for v in sorted(ctx.vlans)]
    if f.type is FieldType.NAME:
        return _name_completions(f, ctx)
    return []


_NAME_KINDS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("aaa profile",), ("aaa_profiles",)),
    (("aaa server-group", "server-group", "dot1x-server-group"), ("server_groups",)),
    (("aaa authentication-server", "auth-server"), ("auth_servers",)),
    (("aaa authentication dot1x", "authentication-dot1x"), ("dot1x_profiles",)),
    (("user-role", "-role"), ("user_roles",)),
    (("ip access-list session", "access-list session", "ip access-group"), ("session_acls",)),
    (("wlan ssid-profile",), ("ssid_profiles",)),
    (("wlan virtual-ap",), ("virtual_aps",)),
    (("ap-group",), ("ap_groups",)),
    (("ap system-profile",), ("ap_system_profiles",)),
    (("netdestination",), ("netdestinations",)),
)


def _name_completions(f: Field, ctx: DeviceContext) -> list[str]:
    """Offer only names of the right kind, based on the command the field sits in."""
    for cmd in f.used_in:
        low = cmd.lower()
        for needles, kinds in _NAME_KINDS:
            if any(n in low for n in needles):
                names = ctx.names_of(*kinds)
                if names:
                    return names
    return []
