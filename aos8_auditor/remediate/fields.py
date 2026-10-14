"""Which parts of a remediation command a human has to fill in, and what type
each one is.

The catalog already answers the first question: every ``remediation_hint`` marks
operator-supplied values as ``<angle brackets>``, so "editable only where it makes
sense" needs no new annotation — the placeholders *are* the edit points, and
everything else is fixed syntax from the hardening guide.

The type is inferred from the placeholder name plus the command it sits in, which
is what lets the wizard validate per field instead of per line. The same
placeholder can mean different things on different lines of one hint::

    vrrp <id>          ->  VRRP router id   (1-255)
    ...
    vlan <id>          ->  VLAN id          (1-4094)

so fields are keyed by (placeholder, inferred type): the two ``<id>`` above are
two questions, while the three ``<id>`` in the NTP hint are one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .hints import tokenize

_PLACEHOLDER_RE = re.compile(r"<[^>]+>")


class FieldType(str, Enum):
    SECRET = "secret"        # masked; never written to the JSON change record
    IP = "ip"                # IPv4/IPv6 address
    NETMASK = "netmask"      # dotted-quad subnet mask
    VLAN_ID = "vlan_id"      # 1-4094
    INTERFACE = "interface"  # slot/module/port
    NUMBER = "number"        # bare integer (key id, VRRP id, policy number)
    NAME = "name"            # profile / group / role / ACL object name
    DELIMITER = "delimiter"  # banner delimiter character
    TEXT = "text"            # free text (banner body, time zone)


_TYPE_HINT = {
    FieldType.SECRET: "shared secret — masked, and never written to the change record",
    FieldType.IP: "IPv4 or IPv6 address",
    FieldType.NETMASK: "dotted-quad subnet mask, e.g. 255.255.255.0",
    FieldType.VLAN_ID: "VLAN id · integer 1-4094",
    FieldType.INTERFACE: "interface · slot/module/port, e.g. 0/0/1",
    FieldType.NUMBER: "integer",
    FieldType.NAME: "object name · letters, digits, - _ . :",
    FieldType.DELIMITER: "single delimiter character that does not appear in the text",
    FieldType.TEXT: "free text",
}

_SECRET_WORDS = ("secret", "password", "passphrase", "psk", "strong")
# Literal command words whose next argument is a credential even when the
# placeholder itself is not named like one.
_SECRET_PREDECESSORS = frozenset({
    "key", "password", "ap-console-password", "md5", "sha", "wpa-passphrase",
})


@dataclass
class Field:
    """One operator-supplied value, shared across every line that uses it."""

    placeholder: str            # "<ip>"
    type: FieldType
    value: str = ""
    # Every (line index, command) this placeholder appears on, for the "used in"
    # hint and so the editor can show which lines a value will change.
    used_in: list[str] = field(default_factory=list)
    line_indexes: list[int] = field(default_factory=list)

    @property
    def token(self) -> str:
        return self.placeholder.strip("<>")

    @property
    def key(self) -> tuple[str, FieldType]:
        return (self.placeholder, self.type)

    @property
    def is_secret(self) -> bool:
        return self.type is FieldType.SECRET

    @property
    def filled(self) -> bool:
        return bool((self.value or "").strip())

    @property
    def hint(self) -> str:
        base = _TYPE_HINT[self.type]
        return f"{base} · used in '{self.used_in[0]}'" if self.used_in else base

    def display(self) -> str:
        """What the wizard shows for the current value."""
        if not self.filled:
            return self.placeholder
        return "•" * min(len(self.value), 12) if self.is_secret else self.value


def infer_type(placeholder: str, command: str) -> FieldType:
    """Type for ``placeholder`` as used in ``command``."""
    token = placeholder.strip("<>").strip().lower()
    literals = [t.lower() for t in tokenize(command) if not t.startswith("<")]
    idx = _placeholder_index(command, placeholder)
    prev = _preceding_literal(command, idx)

    if any(w in token for w in _SECRET_WORDS):
        return FieldType.SECRET
    # Before the "what follows this word is a credential" rule: 'ntp server <ip>
    # key <id>' names a key ID, not the key itself.
    if token in ("id", "vlan", "x") or token.endswith("-id"):
        return FieldType.VLAN_ID if "vlan" in literals else FieldType.NUMBER
    if prev in _SECRET_PREDECESSORS:
        return FieldType.SECRET
    if "mask" in token:
        return FieldType.NETMASK
    if "subnet" in token or "network" in token:
        return FieldType.IP
    if token == "ip" or token.endswith("-ip") or token in ("vip", "gateway") \
            or "host" in token or token.endswith("-address"):
        return FieldType.IP
    if token == "delim":
        return FieldType.DELIMITER
    if "text" in token or "zone" in token or "offset" in token or token == "op":
        return FieldType.TEXT
    if token in ("port", "p", "interface") and literals[:1] == ["interface"]:
        return FieldType.INTERFACE
    return FieldType.NAME


def _placeholder_index(command: str, placeholder: str) -> int:
    toks = tokenize(command)
    return toks.index(placeholder) if placeholder in toks else -1


def _preceding_literal(command: str, index: int) -> str:
    if index <= 0:
        return ""
    toks = tokenize(command)
    for t in reversed(toks[:index]):
        if not t.startswith("<"):
            return t.lower()
    return ""


def fields_for(commands: list[str]) -> list[Field]:
    """Every distinct operator-supplied value across a change's command lines.

    Order is order-of-first-appearance, which is the order the wizard asks for
    them — reading the block top to bottom.
    """
    out: list[Field] = []
    by_key: dict[tuple[str, FieldType], Field] = {}
    for i, cmd in enumerate(commands):
        for ph in _PLACEHOLDER_RE.findall(cmd):
            ftype = infer_type(ph, cmd)
            f = by_key.get((ph, ftype))
            if f is None:
                f = Field(placeholder=ph, type=ftype)
                by_key[(ph, ftype)] = f
                out.append(f)
            if cmd not in f.used_in:
                f.used_in.append(cmd)
            if i not in f.line_indexes:
                f.line_indexes.append(i)
    return out


def fields_in(command: str, fields: list[Field]) -> list[Field]:
    """The subset of ``fields`` that governs this specific line.

    Necessary because two fields can share a placeholder: ``<id>`` is a VRRP
    router id on one line of a hint and a VLAN id on another. Substituting the
    whole field list into every line would put one line's answer on the other's.
    """
    exact = [f for f in fields if command in f.used_in]
    if exact:
        return exact
    # Derived text (a rollback line, an operator's own edit) is not in any
    # ``used_in``; re-infer the type against this line to pick the right field.
    out: list[Field] = []
    for ph in dict.fromkeys(_PLACEHOLDER_RE.findall(command)):
        want = infer_type(ph, command)
        match = next((f for f in fields if f.placeholder == ph and f.type is want), None) \
            or next((f for f in fields if f.placeholder == ph), None)
        if match is not None and match not in out:
            out.append(match)
    return out


def render_line(command: str, fields: list[Field], *, mask_secrets: bool = False) -> str:
    """Substitute filled field values into one command line.

    Unfilled placeholders are left as-is so an incomplete line is obvious both on
    screen and in any file that (deliberately) exports it.
    """
    out = command
    for f in fields_in(command, fields):
        if not f.filled:
            continue
        replacement = f.display() if (mask_secrets and f.is_secret) else f.value
        out = out.replace(f.placeholder, replacement)
    return out


def remaining_placeholders(command: str) -> list[str]:
    return _PLACEHOLDER_RE.findall(command)
