"""Secret redaction for captured ArubaOS evidence.

Runs over every command's output BEFORE anything is written to disk or displayed.
Design principles:

* **Preserve structure, redact value.** Controls need to assert that a secret
  *exists* and is structurally correct (e.g. ``auth-prot sha ... priv-prot aes``),
  not its value. So we keep directives/keywords and replace only the secret token
  with ``[REDACTED:<kind>]``. Encryption *format* selectors (``7``, ``hex``,
  ``cleartext`` ...) between a directive and its value are kept; the value AFTER
  them is what gets redacted.
* **Fail closed, three ways.** Dedicated per-directive rules handle the common
  cases precisely; a directive-gated token sweep redacts surviving secret-shaped
  tokens after any known secret keyword; and finally a *directive-independent*
  entropy backstop redacts any sufficiently long, high-entropy hex/base64 run
  wherever it appears. The entropy pass is what a deny-list of directive names
  structurally cannot give you: it catches an encrypted-credential blob on a
  directive we have never seen. All three run even on lines that already contain
  a ``[REDACTED:]`` marker, so a format-token or multi-secret line cannot leak the
  rest. Output-format drift on a newer 8.x train therefore degrades to
  over-redaction, never a leak.

The engine runs against the UNredacted in-memory model only long enough to
classify; persistence and display always use redacted text.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

_REDACT = "[REDACTED:{kind}]"

# Keyword values that must NOT be treated as a secret when they appear after a
# bare ``authentication`` directive (VRRP puts a secret there; AAA/dot1x use a
# keyword).
_AUTH_KEYWORDS = {
    "dot1x", "mac", "certificate", "wpa", "wpa2", "eap", "open", "none",
    "allowall", "mschapv2", "stateful-dot1x", "captive-portal", "vpn", "wired",
    # IKE/ISAKMP authentication METHOD names (crypto isakmp policy). These name an
    # algorithm, not a credential — the actual IKE pre-shared key lives on
    # 'crypto isakmp key', which has its own rule. Redacting the method name here
    # would make the ISAKMP strength controls undecidable for no privacy gain.
    "rsa-sig", "ecdsa-sig", "ecdsa-256", "ecdsa-384", "pre-share", "psk",
}

# Same-line separator. Deliberately NOT '\s+': a directive and its value are
# always on one line in both config and 'show' output, so allowing the gap to
# span a newline never protects a real secret — it only lets a directive word
# that happens to END a line swallow the first token of the NEXT one. That is
# not hypothetical: 'authentication method: Pre-Shared Key' in
# 'show crypto isakmp policy' ate the 'Diffie-Hellman' off the following line,
# blanking the very DH-group text the ISAKMP controls parse. A secret genuinely
# stranded on its own line is still caught by the per-line failsafe sweep and
# the entropy backstop.
_S = r"[ \t]+"
# Optional encryption-format selector(s) between a directive and the secret value:
# a 1-2 digit type code (e.g. '7', '8') or a format word. Captured into a kept
# group so the actual value after them is what gets redacted.
_FMT = r"(?P<fmt>(?:(?:\d{1,2}|format|hex|cleartext|encrypted|ascii|plaintext)" + _S + r"){0,2})"
# The secret: a double-quoted span (may contain spaces) or a single token. Never
# re-match an already-inserted marker.
_VAL = r'(?P<secret>"[^"]*"|(?!\[REDACTED)\S+)'

_HASHISH = re.compile(r"^[A-Za-z0-9+/=._-]{16,}$")

# --- Entropy backstop -------------------------------------------------------
# A directive-independent last line of defence: any long, high-entropy hex or
# base64 *run* is treated as a secret regardless of the keyword (if any) in
# front of it. Lengths and per-charset entropy floors follow the detect-secrets
# / truffleHog high-entropy defaults, so the bundle never ships a token those
# scanners would flag after the fact. Calibrated against a real captured bundle:
# on that data these thresholds flag the encrypted credential blobs and nothing
# else — IPs, VLANs, SSIDs, hostnames, ACL names, SNMP trap names, mDNS/UPnP
# service ids and hyphen-chunked license keys all stay below the floor because
# ``:._-`` break them into sub-20-char pieces or their entropy is too low.
_ENTROPY_MIN_LEN = 20
_HEX_ENTROPY_MIN = 3.0
_B64_ENTROPY_MIN = 4.5
# Maximal base64-charset run (hex is a subset). ``:._-`` and whitespace are NOT
# in the class, so structured/dotted/hyphenated tokens can never form one long
# run — and no ``[REDACTED:...]`` marker contains a 20-char alnum run either.
_ENTROPY_RUN_RE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % _ENTROPY_MIN_LEN)
_PURE_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _is_high_entropy_run(run: str) -> bool:
    """True if ``run`` is a long hex/base64 blob above its charset entropy floor.

    A run is scored as *hex* only when it is all hex chars AND contains at least
    one ``a-f`` letter; a purely decimal run (e.g. a long numeric id or counter)
    falls through to the stricter base64 floor, which such digit strings never
    reach — so numeric ids are preserved while real hex secrets are caught.
    """
    core = run.rstrip("=")
    if len(core) < _ENTROPY_MIN_LEN:
        return False
    is_hex = bool(_PURE_HEX_RE.match(core)) and any(c in "abcdefABCDEF" for c in core)
    floor = _HEX_ENTROPY_MIN if is_hex else _B64_ENTROPY_MIN
    return _shannon_entropy(core) >= floor


def is_masked(token: str) -> bool:
    """Heuristic: does this token look like a hashed/encrypted/masked secret?"""
    if not token:
        return False
    if set(token) <= {"*"} and len(token) >= 4:
        return True
    return bool(_HASHISH.match(token)) and not token.isdigit()


@dataclass
class RedactionResult:
    text: str
    count: int = 0
    kinds: list[str] = field(default_factory=list)


# Per-directive rules: (kind, compiled pattern with a `secret` group). Order
# matters — more specific first. Each keeps everything except the `secret` span.
_RULES: list[tuple[str, re.Pattern[str]]] = [
    # SNMPv3 auth + privacy (format selector tolerated, e.g. 'auth-prot sha 7 <hash>').
    ("snmp-auth", re.compile(r"(?i)(auth-prot" + _S + r"(?:sha|sha2|md5)" + _S + r")" + _FMT + _VAL)),
    ("snmp-priv", re.compile(r"(?i)(priv-prot" + _S + r"(?:aes|aes128|aes192|aes256|des|3des)" + _S + r")" + _FMT + _VAL)),
    ("snmp-community", re.compile(r"(?i)(snmp-server" + _S + r"community" + _S + r")" + _FMT + _VAL)),
    # NTP authentication key material.
    ("ntp-key", re.compile(r"(?i)(ntp" + _S + r"authentication-key" + _S + r"\d+" + _S + r"(?:md5|sha1|sha)" + _S + r")" + _FMT + _VAL)),
    # WPA passphrase / PSK (passphrase may contain spaces -> rest of line).
    ("wpa-passphrase", re.compile(r"(?im)(wpa-passphrase" + _S + r")(?P<secret>(?!\[REDACTED).+?)[ \t]*$")),
    ("psk", re.compile(r"(?i)(?<![\w-])(psk" + _S + r")" + _FMT + _VAL)),
    ("pre-shared-key", re.compile(r"(?i)(pre-shared-key" + _S + r")" + _FMT + _VAL)),
    # Password / passwd / LDAP bind credentials (policy params like
    # 'password-min-length' are hyphenated single tokens and never match '\s+').
    ("bind-pwd", re.compile(r"(?i)((?:bind-?pwd|bindpasswd)" + _S + r")" + _FMT + _VAL)),
    # AP provisioning credentials: the AP console login and the backup/rescue
    # passwords are stored as encrypted blobs in 'ap system-profile' blocks. The
    # generic 'password'/'passwd' rules below never fire on these because
    # 'password' is preceded by 'console-' (not whitespace) and 'passwords' is
    # not a 'passwd' token.
    ("ap-console-password", re.compile(r"(?i)(ap-console-password" + _S + r")" + _FMT + _VAL)),
    ("bkup-passwords", re.compile(r"(?i)(bkup-passwords" + _S + r")" + _FMT + _VAL)),
    ("passwd", re.compile(r"(?im)(?:(?<=\s)|^)((?:[a-z]+-)?passwd" + _S + r")" + _FMT + _VAL)),
    ("password", re.compile(r"(?im)(?:(?<=\s)|^)(password" + _S + r")" + _FMT + _VAL)),
    ("enable-secret", re.compile(r"(?i)(enable" + _S + r"secret" + _S + r")" + _FMT + _VAL)),
    ("clikey", re.compile(r"(?i)(clikey" + _S + r")" + _FMT + _VAL)),
    ("mschapv2", re.compile(r"(?i)(mschapv2" + _S + r")(?P<secret>(?!\[REDACTED)(?![a-z-]+\b)\S+)")),
    # Pre-shared / shared 'key' with an explicit format selector ('key 7 <hex>').
    ("preshared-key", re.compile(r"(?i)(?<![\w-])(key" + _S + r")(?P<fmt>(?:(?:\d{1,2}|format|hex|cleartext|encrypted|ascii|plaintext)" + _S + r"){1,2})" + _VAL)),
    # 'key <secret>' where the value is not a numeric key-id reference and not a
    # format selector (those are handled by the format rule above).
    ("preshared-key", re.compile(r'(?i)(?<![\w-])(key' + _S + r')(?P<secret>"[^"]*"|(?!\[REDACTED)(?!\d+\b)(?!(?:format|hex|cleartext|encrypted|ascii|plaintext)\b)\S+)')),
    # Line-leading 'key <value>' as a single token (radius/tacacs blocks): redact
    # any value, including a purely numeric one (fail closed at line start).
    ("shared-key", re.compile(r"(?im)^([ \t]*key" + _S + r")(?P<secret>(?!\[REDACTED)\S+)[ \t]*$")),
]

# PEM private-key blocks (multi-line).
_PEM_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)

# mgmt-user local account hash: 'mgmt-user <name> <role> <hashblob>'. Only the
# trailing long base64-ish blob is redacted, so 'mgmt-user webui-cacert ...'
# (which ends in a role, not a hash) is left intact.
_MGMT_USER_RE = re.compile(
    r"(?im)^([ \t]*mgmt-user" + _S + r"\S+" + _S + r"\S+" + _S + r")"
    r"(?P<secret>[A-Za-z0-9+/=]{12,})[ \t]*$")

# Bare 'authentication <value>' line (VRRP secret) — redacted only when the value
# is not a known auth-type keyword.
_VRRP_AUTH_RE = re.compile(r"(?im)^([ \t]*authentication" + _S + r")(?P<secret>\S+)[ \t]*$")

_STRUCT_WORDS = {
    "address", "position", "version", "vlan", "port", "host", "mode", "type",
    "source", "dest", "destination", "peer", "ip", "ipaddr", "netmask",
    "interface", "format", "hex", "cleartext", "encrypted", "ascii", "plaintext",
    "md5", "sha", "sha1", "sha2", "aes", "des", "enable", "disable", "name", "id",
    "priority", "trap", "inform", "default", "any", "permit", "deny",
    # Status words from the tabular 'show' forms. Without these the directive-gated
    # sweep masks the *state* of a security setting: 'MSCHAPv2  Disabled' in
    # 'show aaa authentication mgmt' became '[REDACTED:failsafe]' because
    # 'Disabled' is mixed-case and >= 8 chars, hiding the answer the control
    # needs. These are dictionary status words, never credential values.
    "disabled", "enabled", "unknown", "allowed", "denied", "supported",
    "unsupported", "configured", "unconfigured", "available", "yes", "no",
}
_SPECIAL = "!@#$%^&*"


def _replace_secret_group(text: str, kind: str, pattern: re.Pattern[str], counter: list[int], kinds: set[str]) -> str:
    def _sub(m: re.Match[str]) -> str:
        whole = m.group(0)
        s0 = m.start("secret") - m.start(0)
        s1 = m.end("secret") - m.start(0)
        counter[0] += 1
        kinds.add(kind)
        return whole[:s0] + _REDACT.format(kind=kind) + whole[s1:]

    return pattern.sub(_sub, text)


def _is_risk_directive(tok: str) -> bool:
    t = tok.lower().strip().strip('"')
    if not t:
        return False
    if t in {"psk", "community", "mschapv2", "isakmp", "auth-prot", "priv-prot",
             "key", "secret", "password", "pwd", "bindpasswd", "bind-pwd", "wep-key"}:
        return True
    return t.endswith(("passwd", "passwords", "password", "passphrase", "-pwd", "-key"))


def _secret_shaped(tok: str) -> bool:
    t = tok.strip()
    if t.startswith("[REDACTED"):
        return False
    core = t[1:-1] if len(t) >= 2 and t[0] == '"' and t[-1] == '"' else t
    if not core or core.lower() in _STRUCT_WORDS:
        return False
    if re.fullmatch(r"\d+", core):  # pure integer (id / count)
        return False
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){1,3}", core):  # IPv4-ish
        return False
    if re.fullmatch(r"\d+(?:\.\d+){1,}", core):  # dotted version
        return False
    if len(core) < 6:
        return False
    has_digit = any(c.isdigit() for c in core)
    has_alpha = any(c.isalpha() for c in core)
    has_special = any(c in _SPECIAL for c in core)
    if has_digit and has_alpha:
        return True
    if has_special:
        return True
    if any(c.isupper() for c in core) and any(c.islower() for c in core) and len(core) >= 8:
        return True
    if re.fullmatch(r"[0-9a-fA-F]{12,}", core):
        return True
    if re.fullmatch(r"[A-Za-z0-9+/]{20,}={0,2}", core):
        return True
    return False


_WS_SPLIT = re.compile(r"(\s+)")


def _failsafe_line(line: str, counter: list[int], kinds: set[str]) -> str:
    parts = _WS_SPLIT.split(line)  # keeps whitespace runs as separate parts
    risk_idx = None
    for i, p in enumerate(parts):
        if p.strip() and _is_risk_directive(p):
            risk_idx = i
            break
    if risk_idx is None:
        return line
    for i in range(risk_idx + 1, len(parts)):
        p = parts[i]
        if p.strip() and _secret_shaped(p):
            parts[i] = _REDACT.format(kind="failsafe")
            counter[0] += 1
            kinds.add("failsafe")
    return "".join(parts)


def redact(text: str) -> RedactionResult:
    """Return a :class:`RedactionResult` with all detectable secrets removed."""
    if not text:
        return RedactionResult(text=text or "", count=0, kinds=[])

    counter = [0]
    kinds: set[str] = set()

    def _pem_sub(m: re.Match[str]) -> str:
        counter[0] += 1
        kinds.add("private-key")
        return "-----BEGIN PRIVATE KEY-----\n[REDACTED:private-key]\n-----END PRIVATE KEY-----"

    out = _PEM_RE.sub(_pem_sub, text)
    out = _replace_secret_group(out, "mgmt-user-hash", _MGMT_USER_RE, counter, kinds)

    def _vrrp_sub(m: re.Match[str]) -> str:
        value = m.group("secret")
        if value.lower() in _AUTH_KEYWORDS:
            return m.group(0)
        counter[0] += 1
        kinds.add("vrrp-auth")
        return m.group(1) + _REDACT.format(kind="vrrp-auth")

    out = _VRRP_AUTH_RE.sub(_vrrp_sub, out)

    for kind, pattern in _RULES:
        out = _replace_secret_group(out, kind, pattern, counter, kinds)

    # Directive-independent entropy backstop: redact any long, high-entropy
    # hex/base64 run anywhere in the output. This is the layer that survives
    # directive drift — an encrypted credential on a directive we have no rule
    # for still gets caught. Runs can't span newlines (the class excludes them)
    # and never occur inside a [REDACTED:...] marker, so this is safe to apply to
    # the whole text at once.
    def _entropy_sub(m: re.Match[str]) -> str:
        if _is_high_entropy_run(m.group(0)):
            counter[0] += 1
            kinds.add("high-entropy")
            return _REDACT.format(kind="high-entropy")
        return m.group(0)

    out = _ENTROPY_RUN_RE.sub(_entropy_sub, out)

    # Token-level fail-closed sweep over every secret-bearing line — runs even on
    # lines that already contain a [REDACTED:] marker, so a format-token or
    # multi-secret line cannot leak the remaining values.
    trailing_nl = out.endswith("\n")
    swept = [_failsafe_line(ln, counter, kinds) for ln in out.splitlines()]
    out = "\n".join(swept) + ("\n" if trailing_nl else "")

    return RedactionResult(text=out, count=counter[0], kinds=sorted(kinds))
