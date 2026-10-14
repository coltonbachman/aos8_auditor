"""Compute the cross-object / numeric facts the controls assert against.

Every extractor is defensive: it returns ``None`` when the answer cannot be
determined from the available (read-only, possibly redacted) evidence, so a
control degrades to ``manual`` rather than guessing a pass/fail. Facts are a flat
dict consumed by the ``fact_*`` predicates and by control ``condition`` gates.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model_builder import ControllerModel

# Default/factory server-certificate names that must not remain bound in prod.
_DEFAULT_CERT_NAMES = {"default", "securelogin", "default-self-signed", "factory-cert"}
_LOGGING_NONHOST = {"level", "console", "facility", "category", "format", "buffered", "synchronous"}


def _rc(model: "ControllerModel"):
    return model.config_root


def _fips_enabled(model) -> bool | None:
    t = model.text_for("show_fips")
    if re.search(r"(?im)^\s*Mode\s+Enabled\b", t):
        return True
    if re.search(r"(?im)^\s*Mode\s+Disabled\b", t):
        return False
    if re.search(r"(?im)^\s*fips\s+enable\b", model.running_config_text):
        return True
    return None


def _loginsession_seconds(model) -> int | None:
    m = re.search(r"(?im)^\s*loginsession\s+timeout\s+(\d+)\s*(sec)?\b", model.running_config_text)
    if not m:
        return None
    val = int(m.group(1))
    return val if m.group(2) else val * 60  # minutes unless 'sec'


def _webui_timeout(model) -> int | None:
    node = None
    for n in _rc(model).find_all("web-server"):
        node = n
    if node is not None:
        st = node.child("session-timeout")
        if st and st.args and st.args[0].isdigit():
            return int(st.args[0])
    m = re.search(r"(?im)session-timeout\s+(\d+)", model.text_for("web_server_profile"))
    return int(m.group(1)) if m else None


def _snmp_v1v2c_present(model) -> bool:
    return bool(re.search(r"(?im)^\s*snmp-server\s+community\b", model.running_config_text))


def _snmp_v3_secure(model) -> bool | None:
    lines = re.findall(r"(?im)^\s*snmp-server\s+user\b.*$", model.running_config_text)
    if not lines:
        return None
    # Secure only if EVERY v3 user uses SHA auth AND AES privacy.
    for line in lines:
        if not (re.search(r"auth-prot\s+sha", line, re.I) and re.search(r"priv-prot\s+aes", line, re.I)):
            return False
    return True


def _is_host(token: str) -> bool:
    """A syslog target: an IPv4/IPv6 literal or a dotted FQDN — not a keyword."""
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", token):
        return True
    if ":" in token and re.fullmatch(r"[0-9A-Fa-f:]+", token):  # IPv6
        return True
    return bool(re.fullmatch(r"(?=.*\.)[A-Za-z0-9.-]+", token)) and not token.replace(".", "").isdigit()


def _count_logging_servers(model) -> int:
    # Positive validation: a 'logging <host>' node counts only when its first arg
    # is an IP/FQDN, so 'logging level/trap/console/facility/...' never counts.
    n = 0
    for node in _rc(model).find_all("logging"):
        if node.args and _is_host(node.args[0]) and node.args[0].lower() not in _LOGGING_NONHOST:
            n += 1
    return n


def _ntp(model) -> tuple[int, bool]:
    rc = model.running_config_text
    servers = len(re.findall(r"(?im)^\s*ntp\s+server\b", rc))
    authenticated = bool(
        re.search(r"(?im)^\s*ntp\s+authenticate\b", rc)
        and re.search(r"(?im)^\s*ntp\s+authentication-key\b", rc)
        and re.search(r"(?im)^\s*ntp\s+trusted-key\b", rc)
    )
    return servers, authenticated


def _lcd_disabled(model) -> bool | None:
    if (model.identity.platform_family or "") != "7200":
        return None
    t = model.text_for("lcd_menu")
    if re.search(r"(?i)disable", t):
        return True
    for n in _rc(model).find_all("lcd-menu"):
        if n.find_all_deep("disable"):
            return True
    if t or _rc(model).find_all("lcd-menu"):
        return False
    return None


def _local_auth_disabled(model) -> bool | None:
    t = model.text_for("mgmt_localauth")
    if re.search(r"(?i)Local Authentication Mode\s*:?\s*Disabled", t):
        return True
    if re.search(r"(?i)Local Authentication Mode\s*:?\s*Enabled", t):
        return False
    if re.search(r"(?im)^\s*no\s+mgmt-user\s+localauth\b", model.running_config_text):
        return True
    return None


def _password_policy(model) -> tuple[bool | None, int | None, bool | None]:
    """Return ``(policy_ok, min_length, policy_enabled)``.

    ``policy_enabled`` is broken out from ``policy_ok`` on purpose: the two guides
    set different length bars (Federal 2020 wants >= 15; Controller 2023 shows
    ``password-min-length 8`` and a sample output of 10), so the control needs to
    tell "no policy at all" (a real fail on both guides) from "policy enabled but
    shorter than the federal bar" (a warn).
    """
    block = None
    for n in _rc(model).find_all("aaa"):
        if n.matches("aaa", "password-policy", "mgmt"):
            block = n
            break
    text = model.text_for("password_policy")
    enabled = None
    minlen = None
    if block is not None:
        enabled = block.has_child("enable")
        ml = block.find("password-min-length")
        if ml and ml.args and ml.args[0].isdigit():
            minlen = int(ml.args[0])
    # Real 'show aaa password-policy mgmt' prints e.g. "Minimum password length
    # required   15" and "Enable password policy   Yes" (a word between the label
    # and value), so the label-to-value gap must be permissive.
    m = re.search(r"(?i)Minimum\s+password\s+length(?:\s+required)?\s*:?\s*(\d+)", text)
    if minlen is None and m:
        minlen = int(m.group(1))
    if enabled is None:
        if re.search(r"(?i)Enable\s+password\s+policy\s*:?\s*(yes|true|enabled)", text):
            enabled = True
        elif re.search(r"(?i)Enable\s+password\s+policy\s*:?\s*(no|false|disabled)", text):
            enabled = False
    ok = None
    if enabled is not None or minlen is not None:
        ok = bool(enabled) and (minlen is not None and minlen >= 15)
    return ok, minlen, enabled


def _vlan1(model) -> dict:
    block = None
    for n in _rc(model).find_all("interface"):
        if n.matches("interface", "vlan", "1"):
            block = n
            break
    if block is None:
        return {"present": False, "has_ip": None, "shutdown": None, "hardened": None}
    has_ip = any(c.matches("ip", "address") for c in block.children)
    shutdown = block.has_child("shutdown")
    operstate_up = any(c.matches("operstate", "up") for c in block.children)
    hardened = (not has_ip) and shutdown and not operstate_up
    return {"present": True, "has_ip": has_ip, "shutdown": shutdown, "hardened": hardened}


def _controller_ip(model) -> tuple[str | None, bool | None]:
    t = model.text_for("controller_ip")
    m = re.search(r"(?i)\bVlan\s*(?:Interface)?\s*:?\s*(\d+)", t)
    if m:
        vid = m.group(1)
        return f"vlan{vid}", vid == "1"
    m = re.search(r"(?im)^\s*controller-ip\s+vlan\s+(\d+)", model.running_config_text)
    if m:
        return f"vlan{m.group(1)}", m.group(1) == "1"
    if re.search(r"(?im)^\s*controller-ip\s+loopback\b", model.running_config_text):
        return "loopback", False
    # Only an AFFIRMATIVE loopback statement counts — the standard line
    # "Switch IP is Configured to Loopback: No" must NOT read as loopback.
    if re.search(r"(?i)(?:configured\s+(?:to|on)\s+loopback\s*:?\s*yes|loopback\s*:?\s*yes)", t):
        return "loopback", False
    return None, None


def _aaa_profile_complete(model) -> bool | None:
    profiles = [n for n in _rc(model).find_all("aaa") if n.args and n.args[0].lower() == "profile"]
    if not profiles:
        return None
    for p in profiles:
        if (p.has_child("authentication-dot1x") and p.has_child("dot1x-default-role")
                and p.has_child("dot1x-server-group")):
            return True
    return False


def _external_auth(model) -> dict:
    rc = _rc(model)
    out = {"radius": 0, "ldap": 0, "tacacs": 0}
    # Server names referenced by a server-group count as "in use" even without a
    # per-server 'enable' line.
    referenced: set[str] = set()
    for n in rc.find_all("aaa"):
        if n.args[:1] == ["server-group"]:
            for c in n.children:
                if c.keyword.lower() == "auth-server" and c.args:
                    referenced.add(c.args[0].lower())
    for n in rc.find_all("aaa"):
        if n.args[:1] == ["authentication-server"] and len(n.args) >= 3:
            kind, name = n.args[1].lower(), n.args[2].lower()
            if kind in out and (n.has_child("enable") or name in referenced):
                out[kind] += 1
    return out


def _aps(model) -> tuple[int | None, int | None]:
    """Parse 'show ap database': count data rows between the header and the
    Flags legend, and read the Group column by position (so an AP merely *named*
    'default' is not miscounted)."""
    t = model.text_for("ap_database")
    if not t.strip():
        return None, None
    lines = t.splitlines()
    header_idx = group_idx = None
    for i, ln in enumerate(lines):
        low = ln.lower()
        if "name" in low and "group" in low:
            header_idx = i
            cols = ln.split()
            group_idx = next((j for j, c in enumerate(cols) if c.lower() == "group"), None)
            break
    if header_idx is None:
        return None, None
    total = 0
    in_default = 0
    for ln in lines[header_idx + 1:]:
        s = ln.strip()
        if not s or set(s) <= set("-= "):  # separator rule
            continue
        if re.match(r"(?i)^(flags?\s*:|total\b|num\b|[a-z]\s*=)", s):
            break  # reached the Flags legend / totals footer
        toks = s.split()
        if len(toks) < 2:
            continue
        total += 1
        grp = toks[group_idx] if (group_idx is not None and group_idx < len(toks)) else None
        if grp is not None and grp.lower() == "default":
            in_default += 1
    if total == 0:
        return None, None
    return total, in_default


_PERMIT_ALL_PATTERNS = (
    r"\bany\s+any\s+any\s+permit\b",                       # alias any any any permit
    r"\b(?:ipv4|ipv6)\s+any\s+any\s+permit\b",             # ipv4 any any permit
    r"\bany\s+any\s+\S+\s+permit\b",                       # any any <svc> permit
    r"\bnetwork\s+0\.0\.0\.0\s+0\.0\.0\.0\b.*\bpermit\b",  # network 0.0.0.0 0.0.0.0 ... permit
)


def _any_any_permit(model) -> bool:
    blob = model.text_for("ip_access_list") + "\n" + model.text_for("rights") + "\n" + model.running_config_text
    return any(re.search(p, blob, re.IGNORECASE) for p in _PERMIT_ALL_PATTERNS)


def _admin_policy(model) -> tuple[bool, bool]:
    rc = _rc(model)
    defined = False
    policy_names: list[str] = []
    for n in rc.find_all("ip"):
        if n.args[:2] == ["access-list", "session"] and len(n.args) >= 3:
            body = " ".join(c.text for c in n.children).lower()
            if "4343" in body or "svc-ssh" in body or "svc-https" in body:
                defined = True
                policy_names.append(n.args[2])
    applied = False
    for n in rc.find_all("interface"):
        for c in n.children:
            # ArubaOS spells this binding both ways depending on train. The
            # guide's transcript is 'ip access-group <name> session'; an 8.13
            # parser rejects that outright and accepts only 'ip access-group
            # session <name>'. Reading the name from a fixed offset matched the
            # guide's order and found 'session' on 8.13, so a correctly bound
            # policy was reported as never applied. Match it wherever it lands.
            if c.matches("ip", "access-group") and any(a in policy_names
                                                       for a in c.args[1:]):
                applied = True
    return defined, applied


def _rfprotect_licensed(model) -> bool | None:
    t = model.text_for("license_summary")
    if not t.strip():
        return None
    for ln in t.splitlines():
        if not re.search(r"(?i)rf\s?protect", ln):
            continue
        # Negative indicators first: 'Not Installed' contains the substring
        # 'installed', so it must be checked before the positive forms.
        if re.search(r"(?i)\b(expired|disabled)\b|not\s+installed", ln):
            return False
        if re.search(r"(?i)\b(enabled|active|installed|permanent|subscription)\b", ln):
            return True
        # Tabular form: 'RFProtect   100   50   50' (Total Used Remaining) — a
        # non-zero installed/total count means licensed.
        nums = [int(x) for x in re.findall(r"\b(\d+)\b", ln)]
        if nums:
            return max(nums) > 0
    return False


def _am_group_present(model) -> bool:
    rc = _rc(model)
    for n in rc.find_all("rf"):
        if "radio-profile" in " ".join(n.args).lower():
            for c in n.children:
                if c.matches("mode", "am-mode") or "am-mode" in c.text.lower():
                    return True
    return bool(re.search(r"(?im)\bam-mode\b", model.running_config_text))


def _count_lines(text: str) -> int:
    n = 0
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("-") or s.lower().startswith(("name", "total", "mac", "flags", "ssid")):
            continue
        n += 1
    return n


def _aaa_servers(model, kind: str) -> list:
    out = []
    for n in _rc(model).find_all("aaa"):
        if n.args[:1] == ["authentication-server"] and len(n.args) >= 3 and n.args[1].lower() == kind:
            out.append(n)
    return out


def _ldap_ldaps_only(model) -> bool | None:
    servers = _aaa_servers(model, "ldap")
    if not servers:
        return None
    for s in servers:
        ap = s.find("authport")
        port = ap.args[0] if (ap and ap.args) else None
        if port != "636":  # missing or legacy 389 = not LDAPS
            return False
    return True


def _radius_authport_set(model) -> bool | None:
    servers = _aaa_servers(model, "radius")
    if not servers:
        return None
    return all(s.has_child("authport") for s in servers)


def _tacacs_session_auth(model) -> bool | None:
    servers = _aaa_servers(model, "tacacs")
    if not servers:
        return None
    return all(s.has_child("session-authorization") for s in servers)


def _server_group_count(model) -> int:
    return sum(1 for n in _rc(model).find_all("aaa") if n.args[:1] == ["server-group"])


def _netdest_has_default_route(model) -> bool:
    for n in _rc(model).find_all("netdestination"):
        for c in n.children:
            if c.keyword.lower() == "network" and c.args[:2] == ["0.0.0.0", "0.0.0.0"]:
                return True
    return False


def _vrrp_all_authenticated(model) -> bool | None:
    blocks = _rc(model).find_all("vrrp")
    if not blocks:
        return None
    return all(b.has_child("authentication") for b in blocks)


def _nondefault_vlan_static_ip(model) -> bool:
    for n in _rc(model).find_all("interface"):
        if n.args[:1] == ["vlan"] and len(n.args) >= 2 and n.args[1] != "1":
            if any(c.matches("ip", "address") for c in n.children):
                return True
    return False


def _webui_session_limit(model) -> int | None:
    for n in _rc(model).find_all("web-server"):
        sl = n.find("session-limit")
        if sl and sl.args and sl.args[0].isdigit():
            return int(sl.args[0])
    m = re.search(r"(?im)^\s*session-limit\s+(\d+)", model.text_for("web_server_profile"))
    return int(m.group(1)) if m else None


def _pefng_licensed(model) -> bool | None:
    t = model.text_for("license_summary")
    if not t.strip():
        return None
    for ln in t.splitlines():
        if not re.search(r"(?i)\bpef(v|ng)?\b", ln):
            continue
        # Negatives first ('Not Installed' contains 'installed').
        if re.search(r"(?i)\b(expired|disabled)\b|not\s+installed", ln):
            return False
        if re.search(r"(?i)\b(enabled|active|installed|permanent|subscription)\b", ln):
            return True
        nums = [int(x) for x in re.findall(r"\b(\d+)\b", ln)]
        return (max(nums) > 0) if nums else False
    return False


def _cert_present(model, key: str) -> bool | None:
    """A real cert/CA inventory has a data row (not just a column header)."""
    t = model.text_for(key)
    if not t.strip():
        return None
    lines = t.splitlines()
    hdr = next((i for i, ln in enumerate(lines) if "name" in ln.lower()
                and any(tok in ln.lower() for tok in ("expiry", "issuer", "type", "status"))), None)
    if hdr is None:
        return True if re.search(r"(?im)\bCN\s*=\s*\S", t) else None
    for ln in lines[hdr + 1:]:
        s = ln.strip()
        if not s or set(s) <= set("-= "):
            continue
        if re.match(r"(?i)^(total|num|flags?\s*:)\b", s):
            break
        return True  # a real data row beyond the header
    return False


# --------------------------------------------------------------------------
# ArubaOS 8 Controller Hardening Guide (rev 10, 2023) facts.
#
# The 2020 Federal guide the original catalog was built from does not cover
# cryptography configuration, firewall/control-path defense, console lockdown or
# AP debug access. Everything below backs a control cited to the 2023 guide.
# Same discipline as above: return None whenever the evidence cannot decide.
# --------------------------------------------------------------------------

# Cipher-suite tokens that mean the HTTPS server is NOT at 'ciphers high'.
_WEAK_TLS_SUITE_TOKENS = ("3des", "des-cbc3", "rc4", "-md5", "null", "export", "adh", "anon", "-des-")
# TLS versions the guide says to disable ("For the strongest security
# configuration, TLS 1.0 and TLS 1.1 should be disabled"). Matched as whole
# tokens, never as substrings: the ArubaOS CLI spells TLS 1.0 as bare 'tlsv1',
# so a substring test for "tlsv1.0" misses it while "tlsv1" matches every
# version including tlsv1.2.
_LEGACY_TLS_TOKENS = frozenset({"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"})
# What the ArubaOS 8 web server offers before anyone touches it.
_DEFAULT_TLS_ENABLED = frozenset({"tlsv1", "tlsv1.1", "tlsv1.2"})


def _has_legacy_tls(value: str) -> bool:
    """True if ``value`` names any TLS version the guide says to disable."""
    return any(tok in _LEGACY_TLS_TOKENS for tok in re.split(r"[^a-z0-9.]+", value.lower()))


def _web_server_block(model):
    """The ``web-server profile`` stanza, whichever spelling the train renders."""
    for n in _rc(model).find_all("web-server"):
        return n
    return None


def _web_ciphers_high(model) -> bool | None:
    """HTTPS restricted to >= 128-bit suites ('web-server profile ciphers high').

    'high' is the factory default and therefore usually absent from
    running-config, so an explicit downgrade is what we look for there; the show
    output is authoritative when present.
    """
    block = _web_server_block(model)
    if block is not None:
        c = block.find("ciphers")
        if c and c.args:
            val = c.args[0].strip('"').lower()
            if val in ("low", "medium"):
                return False
            if val == "high":
                return True
    text = model.text_for("web_server_profile")
    m = re.search(r"(?im)^\s*Enable\s+provided\s+cipher\s+suites\s{2,}(.+?)\s*$", text)
    if m:
        val = m.group(1).strip().lower()
        if val in ("low", "medium"):
            return False
        if val == "high":
            return True
        # Newer trains print the negotiated suite list instead of the keyword.
        return not any(tok in val for tok in _WEAK_TLS_SUITE_TOKENS)
    return None


def _web_tls12_only(model) -> bool | None:
    """TLS 1.0/1.1 disabled ('web-server profile ssl-protocol tlsv1.2')."""
    block = _web_server_block(model)
    if block is not None:
        # ArubaOS may render the enabled versions across several lines, and a
        # legacy version is switched off with its own 'no ssl-protocol <ver>'.
        enabled, disabled = set(), set()
        for c in block.children:
            if c.keyword == "ssl-protocol":
                enabled.update(a.strip('"').lower() for a in c.args)
            elif c.keyword == "no" and c.args and c.args[0] == "ssl-protocol":
                disabled.update(a.strip('"').lower() for a in c.args[1:])
        if enabled:
            return not (enabled - disabled) & _LEGACY_TLS_TOKENS
        if disabled:
            # Only negations: the surviving set is the AOS default minus them,
            # so 'no ssl-protocol tlsv1' alone still leaves TLS 1.1 enabled.
            return not (_DEFAULT_TLS_ENABLED - disabled) & _LEGACY_TLS_TOKENS
    text = model.text_for("web_server_profile")
    m = re.search(r"(?im)^\s*SSL/TLS\s+Protocol\s+Config\s{2,}(.+?)\s*$", text)
    if m:
        return not _has_legacy_tls(m.group(1))
    return None


def _ssh_weak_ciphers_disabled(model) -> bool | None:
    """Both 'ssh disable-ciphers aes-cbc' and 'ssh disable-mac hmac-sha1-96'.

    Per the guide these are scanner false positives, not real weaknesses; the
    control exists to close the scan finding, so it is low severity.

    The MAC is under 'disable-mac', not 'disable-ciphers'. Looking for it under
    the latter -- as this did -- is not a near miss: 'ssh disable-ciphers
    hmac-sha1-96' is rejected by ArubaOS, so no running-config can ever contain
    it, and the fact could only ever come back False. An operator who applied
    the fix correctly would be told it was still outstanding on every later run.
    """
    rc = model.running_config_text
    text = model.text_for("show_ssh")
    haystack = rc + "\n" + text
    if not re.search(r"(?im)^\s*ssh\s+disable-(?:ciphers|mac)\b", haystack) and not text:
        return None
    cbc = bool(re.search(r"(?im)^\s*ssh\s+disable-ciphers\s+aes-cbc\b", haystack))
    mac = bool(re.search(r"(?im)^\s*ssh\s+disable-mac\s+hmac-sha1-96\b", haystack))
    if not (cbc or mac) and text:
        # 'show ssh' renders the surviving lists, so an algorithm missing from
        # one proves it is disabled however that happened. Read the specific
        # field rather than the whole page, and match ArubaOS's spelling: the
        # cipher list reads 'aes128-cbc,aes256-cbc,...', which does not contain
        # the literal 'aes-cbc' that the CLI keyword uses. Testing the page for
        # that substring reported CBC as disabled on every controller alive.
        ciphers, macs = _ssh_show_field(text, "Ciphers"), _ssh_show_field(text, "MACs")
        if ciphers is not None:
            cbc = "-cbc" not in ciphers
        if macs is not None:
            mac = "hmac-sha1-96" not in macs
    return cbc and mac


def _ssh_show_field(text: str, label: str) -> str | None:
    """One 'label   value' row of ``show ssh``, lowercased. None if absent.

    Absent has to stay distinguishable from empty: a field this parser cannot
    find is a field it cannot draw a conclusion from, and the caller leaves the
    algorithm marked as still enabled rather than guessing in the safe-looking
    direction.
    """
    # Two separators, because trains differ: 8.13 pads the label out into a
    # column ('Ciphers<spaces>aes128-cbc,...') and other renderings use a colon.
    m = re.search(rf"(?im)^\s*{re.escape(label)}(?:\s*:|[ \t]{{2,}})[ \t]*(.+?)\s*$", text)
    return m.group(1).lower() if m else None


def _isakmp_policies(model) -> list:
    """Every ``crypto isakmp policy <priority>`` stanza in running-config."""
    out = []
    for n in _rc(model).find_all("crypto"):
        if len(n.args) >= 3 and n.args[0] == "isakmp" and n.args[1] == "policy" and n.args[2].isdigit():
            out.append((int(n.args[2]), n))
    return out


def _isakmp_legacy_dh_disabled(model) -> bool | None:
    """Factory-default IKE policies (priority >= 10000, DH group 2) removed.

    'beginning in ArubaOS 6.4, factory-default IKE policies (with priority
    numbers of 10000 or higher) may be disabled, and replaced with
    administrator-defined IKE policies.'
    """
    text = model.text_for("crypto_isakmp_policy")
    policies = _isakmp_policies(model)
    if not policies and not text:
        return None
    for prio, node in policies:
        if prio < 10000:
            continue
        # A legacy default that has been explicitly re-grouped to 14 is fine.
        g = node.find("group")
        if g and g.args and g.args[0].isdigit() and int(g.args[0]) >= 14:
            continue
        return False
    if text:
        for m in re.finditer(r"(?im)^\s*Protection\s+suite\s+priority\s+(\d+)", text):
            if int(m.group(1)) >= 10000:
                return False
    return True


def _isakmp_strong_policy(model) -> bool | None:
    """An admin-defined IKEv2 policy with DH group 14 and RSA-sig auth exists.

    This is the ~112-bit configuration the guide walks through (crypto isakmp
    policy 20 / version v2 / group 14 / authentication RSA-sig).
    """
    text = model.text_for("crypto_isakmp_policy")
    policies = _isakmp_policies(model)
    if not policies and not text:
        return None
    for prio, node in policies:
        if prio >= 10000:
            continue  # factory default, not administrator-defined
        ver = node.find("version")
        group = node.find("group")
        auth = node.find("authentication")
        v2 = bool(ver and ver.args and ver.args[0].lower() in ("v2", "2"))
        g14 = bool(group and group.args and group.args[0].isdigit() and int(group.args[0]) >= 14)
        rsa = bool(auth and auth.args and auth.args[0].lower() in ("rsa-sig", "ecdsa-sig",
                                                                  "ecdsa-256", "ecdsa-384"))
        if v2 and g14 and rsa:
            return True
    # 'show crypto isakmp policy' prose form.
    for blk in re.split(r"(?im)^\s*Protection\s+suite\s+priority\s+", text)[1:]:
        head = blk.split("\n", 1)[0]
        prio = re.match(r"\s*(\d+)", head)
        if prio and int(prio.group(1)) >= 10000:
            continue
        if (re.search(r"(?i)Version\s*:?\s*2", blk)
                and re.search(r"(?i)Diffie-Hellman\s+Group\s*:?\s*#?\s*(1[4-9]|2[0-9])", blk)
                and re.search(r"(?i)(Rivest-Shamir-Adelman|RSA|ECDSA)\s*(Signature|-sig)", blk)):
            return True
    return False if (policies or text) else None


def _tkip_in_use(model) -> bool | None:
    """Any wlan ssid-profile whose opmode includes TKIP ('do not use TKIP')."""
    profiles = [n for n in _rc(model).find_all("wlan")
                if n.args and n.args[0] == "ssid-profile"]
    if not profiles:
        return None
    for n in profiles:
        for om in n.find_all("opmode"):
            if any("tkip" in a.lower() for a in om.args):
                return True
    return False


def _firewall_block(model):
    for n in _rc(model).find_all("firewall"):
        if not n.args:  # the global 'firewall' stanza, not 'firewall cp'
            return n
    return None


def _firewall_flag(model, directive: str) -> bool | None:
    """A global firewall toggle, preferring observed 'show firewall' state.

    'show firewall' lists every option with Enabled/Disabled, so its absence from
    running-config (an AOS default) is no longer ambiguous once it is collected.
    """
    text = model.text_for("show_firewall")
    if text:
        label = directive.replace("-", "[- ]")
        m = re.search(rf"(?im)^\s*{label}\b[^\n]*?\b(Enabled|Disabled)\b", text)
        if m:
            return m.group(1).lower() == "enabled"
    block = _firewall_block(model)
    if block is not None and block.has_child(directive):
        return True
    if re.search(rf"(?im)^\s*no\s+{re.escape(directive)}\b", model.running_config_text):
        return False
    if block is not None or text:
        return False
    return None


def _firewall_cp_attack_rate(model) -> bool | None:
    """'firewall attack-rate cp <n>' — the Monitor/police CP attacks setting."""
    text = model.text_for("show_firewall")
    if text:
        m = re.search(r"(?im)^\s*Monitor/police\s+CP\s+attacks\s+(Enabled|Disabled)", text)
        if m:
            return m.group(1).lower() == "enabled"
    block = _firewall_block(model)
    if block is not None:
        for n in block.find_all("attack-rate"):
            if n.args and n.args[0].lower() == "cp":
                return True
        return False
    return None


def _firewall_cp_bw_contracts(model) -> int | None:
    """Count of control-plane bandwidth contracts (rate limits) configured."""
    text = model.text_for("show_firewall")
    if text:
        n = len(re.findall(r"(?im)^\s*Rate\s+limit\s+CP\s+\S+.*\bEnabled\b", text))
        if n:
            return n
    block = _firewall_block(model)
    if block is None:
        return None
    return len(block.find_all("cp-bandwidth-contract"))


def _firewall_cp_acl_count(model) -> int | None:
    """Administrator-defined control-plane service ACL rules ('firewall cp')."""
    text = model.text_for("firewall_cp")
    if text:
        rows = re.findall(r"(?im)^\s*(ipv4|ipv6)\s+\S+", text)
        return len(rows)
    for n in _rc(model).find_all("firewall"):
        if n.args and n.args[0] == "cp":
            return len([c for c in n.children if c.keyword in ("ipv4", "ipv6")])
    return None


def _validuser_narrowed(model) -> bool | None:
    """The 'validuser' session ACL narrowed past the default 'any any any permit'.

    'For maximum security, the validuser ACL should be modified so that ONLY IP
    addresses valid for wireless clients are permitted.'
    """
    text = model.text_for("validuser_acl")
    block = None
    for n in _rc(model).find_all("ip"):
        if n.matches("ip", "access-list", "session", "validuser"):
            block = n
            break
    if block is not None:
        lines = [c.raw_line.strip().lower() for c in block.children]
        if not lines:
            return None
        catchall = any(re.fullmatch(r"any\s+any\s+any\s+permit", ln) for ln in lines)
        return not catchall
    if text:
        body = text.lower()
        if "validuser" not in body and "permit" not in body:
            return None
        return not re.search(r"(?im)^\s*(4\s+)?any\s+any\s+any\s+permit", text)
    return None


def _deny_inter_user(model) -> bool | None:
    """Inter-user traffic denied globally, or on every virtual AP."""
    g = _firewall_flag(model, "deny-inter-user-traffic")
    if g:
        return True
    vaps = [n for n in _rc(model).find_all("wlan") if n.args and n.args[0] == "virtual-ap"]
    if vaps:
        if all(v.has_child("deny-inter-user-traffic") for v in vaps):
            return True
        return False
    return g


def _console_block(model) -> bool | None:
    """'mgmt-user console-block' — serial console disabled while AOS runs."""
    rc = model.running_config_text
    if re.search(r"(?im)^\s*mgmt-user\s+console-block\b", rc):
        return True
    if re.search(r"(?im)^\s*no\s+mgmt-user\s+console-block\b", rc):
        return False
    return False if rc.strip() else None


def _central_mgmt_auth(model) -> bool | None:
    """'aaa authentication mgmt' enabled and bound to a server-group.

    The 2023 guide's preferred alternative to disabling local auth outright.
    """
    text = model.text_for("aaa_auth_mgmt")
    if text:
        enabled = re.search(r"(?im)^\s*Enable\s*:?\s*(Enabled|Yes|True)\b", text)
        group = re.search(r"(?im)^\s*Server\s*Group\s*:?\s*(\S+)", text)
        if enabled or group:
            grp = group.group(1).strip() if group else ""
            return bool(enabled) and grp.lower() not in ("", "n/a", "none", "internal")
    for n in _rc(model).find_all("aaa"):
        if n.matches("aaa", "authentication", "mgmt"):
            sg = n.find("server-group")
            grp = sg.args[0].strip('"') if (sg and sg.args) else ""
            return n.has_child("enable") and grp.lower() not in ("", "internal")
    return None


def _ap_system_profiles(model) -> list:
    return [n for n in _rc(model).find_all("ap")
            if len(n.args) >= 1 and n.args[0] == "system-profile"]


def _ap_console_protected(model) -> bool | None:
    """AP console protected: 'ap-console-protection' on, or console disabled.

    Only the default profile is resolvable from ``show ap system-profile
    default``; for other profiles an explicit ``no ap-console-protection`` in
    running-config is still caught, but silence stays unknown.
    """
    profiles = _ap_system_profiles(model)
    rc = model.running_config_text
    if re.search(r"(?im)^\s*no\s+ap-console-protection\b", rc):
        return False
    if re.search(r"(?im)^\s*no\s+ap-console-password\b", rc):
        return False
    text = model.text_for("ap_system_profile")
    if text:
        m = re.search(r"(?im)^\s*Console\s+enable\s{2,}(\S+)", text)
        if m and m.group(1).lower() in ("disabled", "false", "no"):
            return True
        m = re.search(r"(?im)^\s*(?:AP\s+)?console\s+protection\s{2,}(\S+)", text)
        if m:
            return m.group(1).lower() in ("enabled", "true", "yes")
    for n in profiles:
        if n.has_child("ap-console-protection"):
            return True
    # 'no console-enable' disables the port outright, which also satisfies the
    # guide. ConfigNode.text is the node's own line, so scan the children.
    for n in profiles:
        for c in n.children:
            if c.keyword == "no" and c.args and c.args[0] == "console-enable":
                return True
    return None


def _ap_debug_shell_enabled(model) -> bool | None:
    """AP remote debug shell ('ap system-profile ... telnet') left enabled.

    Off by default, so its presence in running-config is an explicit enable.
    """
    profiles = _ap_system_profiles(model)
    text = model.text_for("ap_system_profile")
    if not profiles and not text:
        return None
    for n in profiles:
        for c in n.children:
            if c.keyword == "telnet" and not c.args:
                return True
    if text:
        m = re.search(r"(?im)^\s*Telnet\s{2,}(\S+)", text)
        if m:
            return m.group(1).lower() in ("enabled", "true", "yes")
    return False


def _aaa_profiles_enforce_dhcp(model) -> bool | None:
    """Every in-use aaa profile has 'enforce-dhcp'.

    Referenced profiles only: the factory ships a dozen unused 'default-*' AAA
    profiles that no virtual AP points at, and failing on those would be noise.
    """
    profiles = {}
    for n in _rc(model).find_all("aaa"):
        if n.args and n.args[0] == "profile":
            name = " ".join(n.args[1:]).strip('"')
            profiles[name] = n
    if not profiles:
        return None
    referenced = set()
    for v in _rc(model).find_all("wlan"):
        if not (v.args and v.args[0] == "virtual-ap"):
            continue
        ap = v.find("aaa-profile")
        if ap and ap.args:
            referenced.add(" ".join(ap.args).strip('"'))
    targets = [profiles[n] for n in referenced if n in profiles] or list(profiles.values())
    if not targets:
        return None
    return all(t.has_child("enforce-dhcp") for t in targets)


def _ra_guard_applied(model) -> bool | None:
    """The 'ra-guard' session ACL applied to at least one user role."""
    roles = [n for n in _rc(model).find_all("user-role")]
    if not roles:
        return None
    for r in roles:
        for al in r.find_all("access-list"):
            if len(al.args) >= 2 and al.args[0] == "session" and al.args[1].strip('"') == "ra-guard":
                return True
    return False


def _cpsec_enabled(model) -> bool | None:
    """Control Plane Security (CPsec) enabled.

    Not decidable from running-config: the ``control-plane-security`` stanza
    renders empty when it is at defaults, so this needs the show output.
    """
    text = model.text_for("control_plane_security")
    if text:
        m = re.search(r"(?im)^\s*Cpsec\s+Enable\s*:?\s{2,}(\S+)", text)
        if not m:
            m = re.search(r"(?im)^\s*Cpsec\s+Enable\s*:?\s*(\S+)", text)
        if m:
            return m.group(1).lower() in ("enabled", "true", "yes")
    for n in _rc(model).find_all("control-plane-security"):
        if n.has_child("cpsec-enable"):
            return True
        if re.search(r"(?im)^\s*no\s+cpsec-enable\b", n.text):
            return False
    return None


# --------------------------------------------------------------------------
# Open-port exposure facts (Controller/AP Open Ports, guide p.9-14, and the
# control-plane inventory, p.30-53).
#
# These do NOT probe anything - the auditor never scans. They answer "is the
# service behind this documented port actually in use on this controller", so
# the port reference can say "not needed here, and the guide says it is
# blockable" instead of listing 43 ports flatly.
# --------------------------------------------------------------------------


def _telnet_cli_enabled(model) -> bool | None:
    """'telnet cli' / 'telnet soe' - off by default, and absent under FIPS."""
    rc = model.running_config_text
    if re.search(r"(?im)^\s*telnet\s+(cli|soe)\b", rc):
        return True
    if re.search(r"(?im)^\s*no\s+telnet\s+(cli|soe)\b", rc):
        return False
    return False if rc.strip() else None


def _dns_responder_enabled(model) -> bool | None:
    """The UDP/53 DNS responder, quieted with 'no ip domain lookup'.

    Not a real DNS server: it answers every query with the controller's own
    address, which is what makes scanners report cache snooping and traffic
    amplification against it. Enabled unless explicitly turned off.
    """
    rc = model.running_config_text
    if re.search(r"(?im)^\s*no\s+ip\s+domain\s+lookup\b", rc):
        return False
    if re.search(r"(?im)^\s*ip\s+domain\s+lookup\b", rc):
        return True
    return True if rc.strip() else None


def _captive_portal_in_use(model) -> bool | None:
    """A user role actually applies a captive-portal profile.

    Checked through role references, never through the presence of an
    'aaa authentication captive-portal' stanza: ArubaOS ships a factory
    'default' captive-portal profile on every controller, in use or not.
    """
    roles = list(_rc(model).find_all("user-role"))
    if not roles:
        return None
    for r in roles:
        if r.has_child("captive-portal"):
            return True
    return False


_CP_PORT_RULE_RE = re.compile(
    r"(?im)^\s*(?:ipv4|ipv6)\s+(?:\S+\s+)*?(?P<action>permit|deny)\b[^\n]*?"
    r"\bports?\s+(?P<start>\d+)\s+(?P<end>\d+)")


def _cp_rules(model) -> list[tuple[str, int, int]]:
    """(action, start_port, end_port) for every control-plane firewall rule."""
    out: list[tuple[str, int, int]] = []
    text = model.text_for("firewall_cp")
    for m in re.finditer(r"(?im)^\s*(?:ipv4|ipv6)\s+\S*\s*\S*\s+(\d+)\s+(\d+)\s+(\d+)\s+(\w+)", text):
        out.append((m.group(4).lower(), int(m.group(2)), int(m.group(3))))
    for n in _rc(model).find_all("firewall"):
        if not (n.args and n.args[0] == "cp"):
            continue
        for c in n.children:
            m = _CP_PORT_RULE_RE.match(c.raw_line)
            if m:
                out.append((m.group("action").lower(), int(m.group("start")), int(m.group("end"))))
    return out


def _snmp_configured(model) -> bool:
    """Any SNMP agent configuration at all - v1/v2c community, v3 user or host.

    Broader than the v1/v2c and v3 strength facts: this only answers "is UDP/161
    doing anything here", which is what decides whether the port reference calls
    161 needed or blockable.
    """
    rc = model.running_config_text
    return bool(re.search(r"(?im)^\s*snmp-server\s+(community|user|host)\b", rc))


def _cp_denies_captive_portal(model) -> bool | None:
    """A control-plane firewall rule denies the captive-portal ports.

    The guide's own example rules for an unused captive portal are
    ``ipv4 deny any proto 6 ports 8080 8083`` and ``... ports 8088 8088``.
    """
    if not model.text_for("firewall_cp") and not any(
            n.args and n.args[0] == "cp" for n in _rc(model).find_all("firewall")):
        return None
    rules = _cp_rules(model)
    denied = {p for action, lo, hi in rules if action.startswith("deny")
              for p in (8080, 8081, 8088) if lo <= p <= hi}
    return {8080, 8081, 8088}.issubset(denied)


def compute_facts(model: "ControllerModel") -> dict:
    rc = model.running_config_text
    cli_secs = _loginsession_seconds(model)
    ntp_servers, ntp_auth = _ntp(model)
    pw_ok, pw_minlen, pw_enabled = _password_policy(model)
    vlan1 = _vlan1(model)
    ctrl_ip_src, ctrl_ip_on_vlan1 = _controller_ip(model)
    ext = _external_auth(model)
    aps_total, aps_default = _aps(model)
    admin_defined, admin_applied = _admin_policy(model)

    return {
        "fips_enabled": _fips_enabled(model),
        "spanning_tree_disabled": bool(re.search(r"(?im)^\s*no\s+spanning-tree\b", rc)),
        "banner_present": model.config_root.has_child("banner")
        or bool(re.search(r"(?im)^\s*banner\b", rc)),
        "cli_timeout_seconds": cli_secs,
        "cli_timeout_disabled": (cli_secs == 0) if cli_secs is not None else None,
        "webui_session_timeout": _webui_timeout(model),
        "snmp_v1v2c_present": _snmp_v1v2c_present(model),
        "snmp_v3_secure": _snmp_v3_secure(model),
        "syslog_server_count": _count_logging_servers(model),
        "ntp_server_count": ntp_servers,
        "ntp_authenticated": ntp_auth,
        "lcd_menu_disabled": _lcd_disabled(model),
        "ssh_pubkey_auth": bool(re.search(r"(?im)^\s*ssh\s+mgmt-auth\s+public-key\b", rc)),
        "local_auth_disabled": _local_auth_disabled(model),
        "password_policy_ok": pw_ok,
        "password_min_length": pw_minlen,
        "password_policy_enabled": pw_enabled,
        "controller_ip_source": ctrl_ip_src,
        "controller_ip_on_vlan1": ctrl_ip_on_vlan1,
        "vlan1_present": vlan1["present"],
        "vlan1_has_ip": vlan1["has_ip"],
        "vlan1_hardened": vlan1["hardened"],
        "default_gateway_present": bool(re.search(r"(?im)^\s*ip\s+default-gateway\b", rc)),
        "vrrp_present": model.config_root.has_child("vrrp")
        or bool(re.search(r"(?im)^\s*vrrp\b", rc)),
        "radius_enabled": ext["radius"],
        "ldap_enabled": ext["ldap"],
        "tacacs_enabled": ext["tacacs"],
        "external_auth_present": (ext["radius"] + ext["ldap"] + ext["tacacs"]) > 0,
        "aaa_profile_complete": _aaa_profile_complete(model),
        "aps_total": aps_total,
        "aps_in_default": aps_default,
        "any_any_any_permit": _any_any_permit(model),
        "admin_policy_defined": admin_defined,
        "admin_policy_applied": admin_applied,
        "rfprotect_licensed": _rfprotect_licensed(model),
        "am_group_present": _am_group_present(model),
        "rogue_ap_count": _count_lines(model.text_for("wms_rogue_ap")),
        "blacklist_count": _count_lines(model.text_for("blacklist_clients")),
        # Per-stanza / cross-object / numeric facts, added to replace
        # fragile flat-config regexes flagged by the red-team.
        "ldap_ldaps_only": _ldap_ldaps_only(model),
        "radius_authport_set": _radius_authport_set(model),
        "tacacs_session_auth": _tacacs_session_auth(model),
        "server_group_count": _server_group_count(model),
        "netdest_has_default_route": _netdest_has_default_route(model),
        "vrrp_all_authenticated": _vrrp_all_authenticated(model),
        "nondefault_vlan_static_ip": _nondefault_vlan_static_ip(model),
        "webui_session_limit": _webui_session_limit(model),
        "pefng_licensed": _pefng_licensed(model),
        "server_cert_present": _cert_present(model, "server_certs"),
        "trusted_ca_present": _cert_present(model, "trusted_cas"),
        # ArubaOS 8 Controller Hardening Guide (rev 10, 2023) facts.
        "web_ciphers_high": _web_ciphers_high(model),
        "web_tls12_only": _web_tls12_only(model),
        "ssh_weak_ciphers_disabled": _ssh_weak_ciphers_disabled(model),
        "isakmp_legacy_dh_disabled": _isakmp_legacy_dh_disabled(model),
        "isakmp_strong_policy": _isakmp_strong_policy(model),
        "tkip_in_use": _tkip_in_use(model),
        "fw_prohibit_ip_spoofing": _firewall_flag(model, "prohibit-ip-spoofing"),
        "fw_prohibit_arp_spoofing": _firewall_flag(model, "prohibit-arp-spoofing"),
        "fw_deny_inter_user": _deny_inter_user(model),
        "fw_local_valid_users": _firewall_flag(model, "local-valid-users"),
        "fw_validuser_narrowed": _validuser_narrowed(model),
        "fw_cp_attack_rate_set": _firewall_cp_attack_rate(model),
        "fw_cp_bw_contract_count": _firewall_cp_bw_contracts(model),
        "fw_cp_acl_rule_count": _firewall_cp_acl_count(model),
        "mgmt_console_blocked": _console_block(model),
        "central_mgmt_auth": _central_mgmt_auth(model),
        "ap_console_protected": _ap_console_protected(model),
        "ap_debug_shell_enabled": _ap_debug_shell_enabled(model),
        "aaa_enforce_dhcp": _aaa_profiles_enforce_dhcp(model),
        "ra_guard_applied": _ra_guard_applied(model),
        "cpsec_enabled": _cpsec_enabled(model),
        # Open-port exposure (guide p.9-14, p.30-53). Nothing here is probed.
        "telnet_cli_enabled": _telnet_cli_enabled(model),
        "dns_responder_enabled": _dns_responder_enabled(model),
        "captive_portal_in_use": _captive_portal_in_use(model),
        "cp_denies_captive_portal": _cp_denies_captive_portal(model),
        # Only facts that describe the LISTENER belong here: the controller is an
        # NTP/syslog server for its APs on UDP/123 and UDP/514, and the facts the
        # audit can see for those (ntp_server_count, syslog_server_count) are the
        # controller as a CLIENT of upstream servers — the opposite direction.
        "snmp_configured": _snmp_configured(model),
    }
