"""The single source of truth for which commands the auditor may ever send.

Two independent gates give defense in depth, so even a buggy control physically
cannot emit a state-changing command:

1. **Allowlist** — only ``show ...``, the session-scoped pager toggle, and
   read-only node navigation (``cd <path>``) are permitted.
2. **Denylist** — an explicit verb denylist rejects anything that could mutate
   state, generate files, or move data off-box, even if it somehow slipped past
   the allowlist (e.g. ``show`` followed by a piped mutating verb).

``assert_safe`` is called at the transport boundary on every command.
``COMMAND_CATALOG`` and ``CAPABILITY_PROBE`` define what collection sends.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


class UnsafeCommandError(RuntimeError):
    """Raised when a command is not on the allowlist or hits the denylist."""


# 'show' and its accepted CLI abbreviations.
_SHOW_ABBREV = frozenset({"sh", "sho", "show"})
_ALLOW_EXACT = frozenset({"no paging", "encrypt disable"})

# Mutating/file-generating LEADING verbs. This is belt-and-suspenders on top of
# the allowlist: it is checked only against the command's first token, so feature
# nouns that legitimately appear inside a read-only command (e.g. "show license",
# "show fips", "show crypto-local ...") are never wrongly rejected. As the first
# token is already constrained to show/no/cd/encrypt by the allowlist, this gate
# only ever fires if the allowlist is loosened in future.
_DENY_FIRST_TOKENS = frozenset({
    "configure", "config", "write", "reload", "reset", "boot", "halt", "shutdown",
    "clear", "delete", "rename", "remove", "erase", "purge",
    "copy", "scp", "ftp", "tftp", "rcp", "upload", "download",
    "backup", "restore", "export", "import", "tar",
    "license", "fips", "crypto", "ap-regroup", "ap-rename", "provision",
    "set", "make", "move", "wipe", "format",
    "ping", "traceroute", "telnet", "ssh", "tech-support",
})

# A '|' display-filter segment must match EXACTLY one of these — a single
# modifier plus at most one no-whitespace pattern token. This blocks the AOS
# 'redirect'/'save' file-writing modifiers and any extra tokens (e.g.
# '| include x redirect flash: out.txt'), which the earlier first-token-only
# check let ride through.
_PIPE_SEGMENT = re.compile(r"(?i)^(?:(?:include|exclude|begin)\s+\S+|count)$")

# 'show <target>' forms that are read-only but file-generating / CPU-heavy and
# therefore out of scope for an unattended audit. Gated even though they lead
# with 'show'. (File-transfer forms like 'tar logs tech-support' are already
# rejected by the allowlist.)
_DENY_SHOW_TARGETS = frozenset({"tech-support"})

# Shell/CLI metacharacters and file-redirection verbs that could chain,
# substitute, or redirect output. Single '|' is handled separately (display
# filters); '||' is caught here.
_CHAIN_RE = re.compile(r"(?i)[;&]|\$\(|\$\{|`|\|\||>|<|\bexec\b|\bredirect\b|\btee\b")

_DENY_EXEMPT = frozenset({"encrypt disable", "no paging"})


def _nav_ok(base: str) -> bool:
    """Read-only node navigation pinned to the /mm or /md subtree, no traversal."""
    m = re.fullmatch(r"cd\s+(\S+)", base)
    if not m:
        return False
    path = m.group(1)
    if not path.startswith("/"):
        return False
    segs = [s for s in path.split("/") if s != ""]
    if not segs or segs[0] not in ("mm", "md"):
        return False  # also rejects bare '/'
    for s in segs:
        if s in (".", ".."):
            return False
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", s):
            return False
    return True


def is_safe(command: str) -> bool:
    try:
        assert_safe(command)
        return True
    except UnsafeCommandError:
        return False


def assert_safe(command: str) -> None:
    """Raise :class:`UnsafeCommandError` unless ``command`` is read-only safe."""
    if command is None:
        raise UnsafeCommandError("command is None")
    cmd = command.strip()
    if not cmd:
        raise UnsafeCommandError("empty command")

    # Reject any control / line-separator / format (zero-width) characters,
    # including Unicode line separators (U+2028/2029) and NEL (U+0085) that some
    # CLIs treat as newlines. Tab is tolerated and normalized to a space below.
    for ch in cmd:
        if ch == "\t":
            continue
        if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
            raise UnsafeCommandError(f"command contains a control/separator character: {command!r}")

    # Normalize internal whitespace (tabs / repeated spaces) to single spaces.
    cmd = re.sub(r"[\t ]+", " ", cmd).strip()

    # No command chaining/substitution/redirection, ever.
    if _CHAIN_RE.search(cmd):
        raise UnsafeCommandError(f"command contains chaining/redirection metacharacters: {command!r}")

    # Split off any '|' display-filter segments; each must match the strict form.
    base, *pipe_segments = cmd.split("|")
    base = base.strip()
    for seg in pipe_segments:
        if not _PIPE_SEGMENT.fullmatch(seg.strip()):
            raise UnsafeCommandError(f"unsafe pipe segment {seg.strip()!r} in command: {command!r}")

    tokens = base.split(" ")
    first = tokens[0].lower() if tokens else ""
    is_show = first in _SHOW_ABBREV and len(tokens) >= 2

    # Allowlist gate on the base command.
    if not (is_show or base in _ALLOW_EXACT or _nav_ok(base)):
        raise UnsafeCommandError(f"command not on read-only allowlist: {command!r}")

    # Leading-verb denylist — belt-and-suspenders if the allowlist is ever
    # loosened (today the allowlist already constrains the first token).
    if base not in _DENY_EXEMPT and first in _DENY_FIRST_TOKENS:
        raise UnsafeCommandError(f"command leads with forbidden verb {first!r}: {command!r}")

    # Reject file-generating/CPU-heavy 'show <target>' forms.
    if is_show and tokens[1].lower() in _DENY_SHOW_TARGETS:
        raise UnsafeCommandError(f"command targets a forbidden 'show' subject {tokens[1]!r}: {command!r}")
    return None


@dataclass(frozen=True)
class CommandSpec:
    """Metadata for a collected command.

    ``key`` is the logical evidence key controls reference (decoupled from exact
    command syntax so controls survive command drift). ``alternates`` are tried
    in order if the primary returns UNSUPPORTED on a given train.
    """

    key: str
    command: str
    alternates: tuple[str, ...] = ()
    may_be_denied: bool = False
    timeout_s: int = 60
    note: str = ""

    def __post_init__(self) -> None:
        for c in (self.command, *self.alternates):
            assert_safe(c)  # construction-time guarantee: catalog is all-safe


# Cheap probes run first to learn what the read-only role can actually see.
CAPABILITY_PROBE: tuple[str, ...] = (
    "show version",
    "show running-config",
    "show rights",
    "show mgmt-user local-authentication-mode",
    "show crypto-local pki serverCerts",
    "show snmp",
    "show license",
    "show ap database",
    "show wms rogue-ap",
)

# MVP read-only evidence catalog (corrected per the gap analysis: precise show
# commands, not 'show running-config | include ...').
COMMAND_CATALOG: tuple[CommandSpec, ...] = (
    CommandSpec("show_version", "show version"),
    CommandSpec("running_config", "show running-config", timeout_s=300),
    CommandSpec("config_pending", "show configuration pending"),
    CommandSpec("show_fips", "show fips"),
    CommandSpec("show_banner", "show banner", alternates=("show running-config",)),
    CommandSpec("loginsession_timeout", "show loginsession timeout", alternates=("show running-config",)),
    CommandSpec("web_server_profile", "show web-server profile"),
    CommandSpec("snmp", "show snmp"),
    CommandSpec("snmp_user", "show snmp user", may_be_denied=True),
    CommandSpec("snmp_trap_host", "show snmp trap-host"),
    CommandSpec("ntp_servers", "show ntp servers", alternates=("show ntp status",)),
    CommandSpec("ntp_status", "show ntp status"),
    CommandSpec("ntp_auth_keys", "show ntp authentication-keys", may_be_denied=True),
    CommandSpec("ntp_trusted_keys", "show ntp trusted-keys"),
    CommandSpec("lcd_menu", "show lcd-menu", alternates=("show running-config",)),
    CommandSpec("mgmt_localauth", "show mgmt-user local-authentication-mode"),
    CommandSpec("mgmt_user", "show mgmt-user", may_be_denied=True),
    CommandSpec("password_policy", "show aaa password-policy mgmt", may_be_denied=True),
    CommandSpec("server_certs", "show crypto-local pki serverCerts", may_be_denied=True),
    CommandSpec("trusted_cas", "show crypto-local pki trustedCAs", may_be_denied=True),
    CommandSpec("vlan", "show vlan"),
    CommandSpec("ip_interface_brief", "show ip interface brief", alternates=("show interface brief",)),
    CommandSpec("port_status", "show port status"),
    CommandSpec("controller_ip", "show controller-ip"),
    CommandSpec("ip_route", "show ip route"),
    CommandSpec("vrrp", "show vrrp", alternates=("show vrrp stats",)),
    CommandSpec("aaa_auth_servers", "show aaa authentication-server all"),
    CommandSpec("aaa_server_groups", "show aaa server-group"),
    CommandSpec("aaa_dot1x", "show aaa authentication dot1x"),
    CommandSpec("aaa_derivation_user", "show aaa derivation-rules user"),
    CommandSpec("rights", "show rights"),
    CommandSpec("ip_access_list", "show ip access-list brief", alternates=("show ip access-list all",)),
    CommandSpec("netdestination", "show netdestination"),
    CommandSpec("ap_database", "show ap database", timeout_s=120),
    CommandSpec("ap_group", "show ap-group"),
    CommandSpec("wlan_virtual_ap", "show wlan virtual-ap"),
    CommandSpec("wlan_ssid_profile", "show wlan ssid-profile"),
    CommandSpec("aaa_profile", "show aaa profile"),
    CommandSpec("wms_rogue_ap", "show wms rogue-ap"),
    CommandSpec("ap_monitor_ap_list", "show ap monitor ap-list", alternates=("show wms ap",)),
    CommandSpec("blacklist_clients", "show ap blacklist-clients", alternates=("show ap blacklist-time",)),
    CommandSpec("license_summary", "show license summary", alternates=("show license",)),
    # --- ArubaOS 8 Controller Hardening Guide (rev 10, 2023) evidence ---------
    # These settings are invisible in 'show running-config' when they sit at
    # their AOS defaults (the stanzas render empty), so the state has to be read
    # back from the feature's own show command or it stays undeterminable.
    CommandSpec("show_firewall", "show firewall",
                note="global firewall options + Control Path Defense rate limits (guide p.23)"),
    CommandSpec("firewall_cp", "show firewall-cp",
                note="administrator-configured control-plane service ACL (guide p.25)"),
    CommandSpec("firewall_cp_internal", "show firewall-cp internal", may_be_denied=True,
                note="default control-plane rules permitted from any source (guide p.25)"),
    CommandSpec("control_plane_security", "show control-plane-security",
                note="CPsec enable + auto cert provisioning (guide p.20)"),
    CommandSpec("crypto_isakmp_policy", "show crypto isakmp policy", may_be_denied=True,
                note="observed IKE version / DH group / auth method (guide p.20)"),
    CommandSpec("ap_system_profile", "show ap system-profile default",
                alternates=('show ap system-profile "default"',),
                note="AP console protection + debug shell for the default profile (guide p.24)"),
    CommandSpec("validuser_acl", "show ip access-list validuser",
                alternates=("show ip access-list all",),
                note="valid-user ACL contents, to tell 'narrowed' from factory default (guide p.54)"),
    CommandSpec("show_ssh", "show ssh",
                note="SSH cipher/MAC restriction state for 'ssh disable-ciphers' (guide p.19)"),
    CommandSpec("aaa_auth_mgmt", "show aaa authentication mgmt", may_be_denied=True,
                note="centralized management authentication profile (guide p.26)"),
    # Mobility Master topology discovery (UNSUPPORTED on standalone -> ignored).
    CommandSpec("node_hierarchy", "show configuration node-hierarchy", may_be_denied=True),
    CommandSpec("switches", "show switches", may_be_denied=True),
)

# Evidence keys that are Mobility-Master-GLOBAL (collected once at /mm), not per
# managed device. Everything else in the catalog is collected per node on an MM.
GLOBAL_KEYS = frozenset({"license_summary", "node_hierarchy", "switches"})
