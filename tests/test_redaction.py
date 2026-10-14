"""Redaction must remove every secret value while preserving structure.

This is the single most important correctness property of the collection layer:
audit evidence routinely leaves the secure environment, so a leaked shared key
or passphrase would itself be an incident.
"""

from pathlib import Path

import pytest

from aos8_auditor.collection.redaction import is_masked, redact

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_running_config.txt"

# Secret VALUES that must never survive redaction.
SECRETS = [
    "publicCommunityStr",
    "S3cretAuthPass99",
    "S3cretPrivPass00",
    "myNtpSecretKey123",
    "R@diusSh4redKeyValue99",
    "Ld@pBindP4ssword",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "Sup3rSecret Passphrase With Spaces",
    "aruba123secret",
    "MyIkePreSharedKey",
    "TopSecretKeyMaterialMustNeverLeak",
    "ZZZZprivatekeybytescontinuehere",
    # AP provisioning credentials (encrypted blobs in 'ap system-profile').
    "fd6ec6dee2395c7af2d96a012c8e8fdf576c7fd601deda67",  # ap-console-password
    "4870d95db6832dee31940aaffac4c4337f3db3f20c7a39e3",  # bkup-passwords
]

# Structure / non-secret tokens that MUST be preserved so controls still work.
PRESERVED = [
    "auth-prot sha",
    "priv-prot",
    "snmp-server community",
    "ntp authentication-key 1 md5",
    "ntp trusted-key 1",
    "ntp server 10.10.100.5 key 1",  # the key *id* 1 must survive
    "password-min-length 15",        # policy param must NOT be redacted
    "authport 636",
    "opmode wpa2-aes",
    "admin-dn cn=svc-bind,dc=example,dc=gov",
    "10.10.100.50",                  # IPs preserved for topology controls
    "read-only",                     # mgmt-user role must survive (not a hash)
    "MyTrustedCA",
    "essid CORP",
    'ap system-profile "default"',   # profile block header must survive
    "ap-console-password",           # directive kept, only the value redacted
    "bkup-passwords",
]


@pytest.fixture(scope="module")
def redacted():
    return redact(FIXTURE.read_text())


def test_no_secret_value_survives(redacted):
    text = redacted.text
    leaked = [s for s in SECRETS if s in text]
    assert not leaked, f"secrets leaked through redaction: {leaked}"


def test_structure_preserved(redacted):
    text = redacted.text
    missing = [p for p in PRESERVED if p not in text]
    assert not missing, f"redaction destroyed non-secret structure: {missing}"


def test_pem_block_redacted_but_markers_kept(redacted):
    text = redacted.text
    assert "[REDACTED:private-key]" in text
    assert "BEGIN PRIVATE KEY" in text and "END PRIVATE KEY" in text


def test_redaction_reports_counts_and_kinds(redacted):
    assert redacted.count > 0
    assert "private-key" in redacted.kinds
    assert any(k in redacted.kinds for k in ("snmp-auth", "snmp-priv"))


def test_mgmt_user_hash_redacted_but_role_account_line_intact(redacted):
    text = redacted.text
    # The local admin hash is gone...
    assert "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" not in text
    # ...but the webui-cacert mapping (ends in a role, not a hash) is intact.
    assert "operatoraccount read-only" in text


def test_idempotent(redacted):
    # Re-redacting already-redacted text changes nothing material.
    again = redact(redacted.text)
    assert again.text == redacted.text


def test_is_masked():
    assert is_masked("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
    assert is_masked("********")
    assert not is_masked("12")
    assert not is_masked("read-only")  # has hyphen, short-ish, not a hash
    assert not is_masked("")


# --- Entropy backstop: catches encrypted blobs on directives we have NO rule
# for. This is the layer that survives ArubaOS output/directive drift. ---------

# (input line, blob that must not survive) — the DIRECTIVE is deliberately one
# with no dedicated rule, so only the entropy pass can catch these.
ENTROPY_LEAKS = [
    ("some-future-directive fd6ec6dee2395c7af2d96a012c8e8fdf576c7fd601deda67",
     "fd6ec6dee2395c7af2d96a012c8e8fdf576c7fd601deda67"),                       # 48-char hex
    ("mystery-key 9Xk2mQ7pRtVwYzB4nD6sFhJlNcE0aUgIoP1vW5xZ3T",
     "9Xk2mQ7pRtVwYzB4nD6sFhJlNcE0aUgIoP1vW5xZ3T"),                            # random base64
    ("bareblob a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
     "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"),                              # 40-char hex, no keyword hint
]


@pytest.mark.parametrize("line,blob", ENTROPY_LEAKS)
def test_entropy_backstop_catches_unknown_directives(line, blob):
    out = redact(line + "\n").text
    assert blob not in out, f"high-entropy blob {blob!r} leaked from {line!r} -> {out!r}"
    assert "[REDACTED:high-entropy]" in out


# Long/identifier-shaped tokens that are NOT secrets and must NOT be swept up by
# the entropy pass (calibrated against a real captured bundle).
ENTROPY_PRESERVE = [
    "urn:schemas-upnp-org:service:ConnectionManager:1",   # UPnP service id (has :-)
    "_96084372._sub._googlecast._tcp",                    # mDNS id (has ._)
    "wlsxClientPskAuthenticationFailed",                  # SNMP trap name (entropy < b64 floor)
    "10.10.100.254",                                      # IPv4 (dotted)
    "12345678901234567890",                               # 20-digit numeric id (decimal, not hex)
    "mediaserver-01.corp.example.gov",                    # hostname
]


@pytest.mark.parametrize("token", ENTROPY_PRESERVE)
def test_entropy_backstop_preserves_topology(token):
    out = redact(token + "\n").text
    assert token in out, f"entropy pass over-redacted non-secret {token!r} -> {out!r}"


def test_entropy_kind_reported():
    r = redact("weird-directive fd6ec6dee2395c7af2d96a012c8e8fdf576c7fd601deda67\n")
    assert "high-entropy" in r.kinds and r.count >= 1


# --- Regression cases from the adversarial red-team (each previously leaked) ---
# (input line, the secret VALUE that must not survive)
REDTEAM_LEAKS = [
    ("password 7 094F471A1A0A0E11", "094F471A1A0A0E11"),
    ("password 8 a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0", "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0"),
    ("snmp-server user u auth-prot sha 7 deadbeefdeadbeefdeadbeefdeadbeef priv-prot aes 7 cafebabecafebabecafe", "deadbeefdeadbeefdeadbeefdeadbeef"),
    ("snmp-server user u auth-prot sha 7 deadbeefdeadbeefdeadbeefdeadbeef priv-prot aes 7 cafebabecafebabecafe", "cafebabecafebabecafe"),
    ("   bind-pwd LdapBindP4ssword", "LdapBindP4ssword"),
    ("   bindpasswd LdapBindPass00", "LdapBindPass00"),
    ("   mschapv2 MyMschapSecret99", "MyMschapSecret99"),
    ("clikey MyCliKeyValue1234567890ABCDEFG", "MyCliKeyValue1234567890ABCDEFG"),
    ("crypto-local isakmp key 7 0123456789abcdef address 10.0.0.1", "0123456789abcdef"),
    ("enable secret cisco123", "cisco123"),
    ("crypto ipsec pre-shared-key shortpsk99", "shortpsk99"),
    ("pre-shared-key MyPreShared99", "MyPreShared99"),
    ('crypto-local isakmp key "Quoted Secret Key" address 1.1.1.1', "Quoted Secret Key"),
    ("key MySecret1 backup-key MySecret2val", "MySecret2val"),
    ("   wep-key 1 deadbeef1234cafe", "deadbeef1234cafe"),
    ("   key format hex deadbeefcafe1234", "deadbeefcafe1234"),
    # AP provisioning credentials — 'password' is preceded by 'console-' and
    # 'passwords' is not a 'passwd' token, so the generic rules never fired.
    ("    ap-console-password fd6ec6dee2395c7af2d96a012c8e8fdf576c7fd601deda67", "fd6ec6dee2395c7af2d96a012c8e8fdf576c7fd601deda67"),
    ("    bkup-passwords 4870d95db6832dee31940aaffac4c4337f3db3f20c7a39e3", "4870d95db6832dee31940aaffac4c4337f3db3f20c7a39e3"),
    ("    ap-console-password cleartextConsolePw1", "cleartextConsolePw1"),
]


@pytest.mark.parametrize("line,secret", REDTEAM_LEAKS)
def test_redteam_leaks_are_closed(line, secret):
    out = redact(line + "\n").text
    assert secret not in out, f"secret {secret!r} leaked from line {line!r} -> {out!r}"


# Non-secret structure on these lines must be preserved (no over-redaction).
REDTEAM_PRESERVE = [
    ("   key format hex deadbeefcafe1234", "format hex"),  # format tokens kept
    ("ntp server 10.10.100.5 key 1", "key 1"),             # numeric key-id kept
    ("   ntp trusted-key 7", "trusted-key 7"),
    ("ldap key-attribute userPrincipalName", "userPrincipalName"),  # not a secret line
    ("aaa password-policy mgmt", "password-policy"),
    ("   password-min-length 15", "password-min-length 15"),
    ("    ap-console-password fd6ec6dee2395c7af2d96a012c8e8fdf576c7fd601deda67", "ap-console-password"),
    ("    bkup-passwords 4870d95db6832dee31940aaffac4c4337f3db3f20c7a39e3", "bkup-passwords"),
]


@pytest.mark.parametrize("line,kept", REDTEAM_PRESERVE)
def test_redteam_preserves_structure(line, kept):
    out = redact(line + "\n").text
    assert kept in out, f"redaction destroyed non-secret token {kept!r} in {line!r} -> {out!r}"


# IKE authentication METHOD names sit on a bare 'authentication <token>' line,
# the same shape as a VRRP authentication password. They name an algorithm, not
# a credential — the real IKE pre-shared key lives on 'crypto isakmp key' — so
# masking them would make the ISAKMP strength controls undecidable for no
# privacy gain.
ISAKMP_METHODS = ["rsa-sig", "ecdsa-sig", "ecdsa-256", "ecdsa-384", "pre-share"]


@pytest.mark.parametrize("method", ISAKMP_METHODS)
def test_isakmp_auth_method_not_redacted(method):
    cfg = f"crypto isakmp policy 20\n  version v2\n  group 14\n  authentication {method}\n"
    out = redact(cfg).text
    assert method in out, f"IKE auth method {method!r} was redacted -> {out!r}"


def test_vrrp_authentication_password_still_redacted():
    out = redact("vrrp 10\n  authentication Vrrp$ecret123\n").text
    assert "Vrrp$ecret123" not in out
    assert "authentication" in out


# --- Same-line separator: over-redaction across a newline ------------------
# A directive and its value are always on one line. Letting the gap span a
# newline meant a directive word ENDING a line swallowed the first token of the
# next one, blanking evidence the controls parse. Both cases below are real
# output captured from an ArubaOS 8.13 controller.

ISAKMP_PROSE = """ISAKMP ENABLED
Protection suite priority 20
\t Version 1
\t hash algorithm: Secure Hash Algorithm 160
\t authentication method: Pre-Shared Key
\t Diffie-Hellman Group: #2 (1024 bit)
\t lifetime: 28800 seconds
"""

AAA_MGMT_TABLE = """Management Authentication Profile
---------     -----
Default Role  root
Enable        No
MSCHAPv2      Disabled
"""


def test_line_ending_in_key_does_not_eat_the_next_line():
    """'...Pre-Shared Key' + newline must not redact 'Diffie-Hellman'."""
    out = redact(ISAKMP_PROSE).text
    assert "Diffie-Hellman Group: #2 (1024 bit)" in out, out
    assert "REDACTED" not in out


def test_status_word_after_a_risk_directive_is_not_a_secret():
    """'MSCHAPv2  Disabled' is the answer a control needs, not a credential."""
    out = redact(AAA_MGMT_TABLE).text
    assert "MSCHAPv2      Disabled" in out, out
    assert "REDACTED" not in out


@pytest.mark.parametrize("line,secret", [
    ("crypto isakmp key Sup3rSecretPSK address 10.1.1.1", "Sup3rSecretPSK"),
    ('crypto isakmp key "my secret psk" address 10.1.1.1', "my secret psk"),
    ("  key MyRadiusKey123", "MyRadiusKey123"),
    ("  key 7 a1b2c3d4e5f6a7b8", "a1b2c3d4e5f6a7b8"),
    ("snmp-server community Str0ngC0mmunity", "Str0ngC0mmunity"),
    ("mgmt-user bob root aB3xY9zQ1mNpKr7T", "aB3xY9zQ1mNpKr7T"),
    ("enable secret 7 d41d8cd98f00b204", "d41d8cd98f00b204"),
    ("ntp authentication-key 1 md5 N0dPassw0rd!", "N0dPassw0rd!"),
    ("  authentication Vrrp$ecret123", "Vrrp$ecret123"),
])
def test_same_line_secrets_still_redacted(line, secret):
    """The narrowing must not cost a single real same-line secret."""
    out = redact(line + "\n").text
    assert secret not in out, f"{secret!r} survived -> {out!r}"


@pytest.mark.parametrize("blob", [
    "a1b2c3d4e5f6a7b8c9d0e1f2",
    "aB3xY9zQ1mNpKr7TvW2sLd8Fg",
])
def test_value_stranded_on_the_next_line_still_caught_by_entropy(blob):
    """The per-line rules no longer reach across the newline, so the
    directive-independent entropy backstop is what covers this shape -- which
    is how AOS stores credentials (encrypted/hashed blobs)."""
    out = redact(f"key\n{blob}\n").text
    assert blob not in out, out
