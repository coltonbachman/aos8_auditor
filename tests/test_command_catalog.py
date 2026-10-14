"""The command safelist must allow read-only shows and reject anything that
could mutate state, generate files, move data off-box, or chain a command."""

import pytest

from aos8_auditor.collection.command_catalog import (
    COMMAND_CATALOG,
    CommandSpec,
    UnsafeCommandError,
    assert_safe,
    is_safe,
)

SAFE = [
    "show version",
    "show running-config",
    "show license summary",        # 'license' is a noun here, must be allowed
    "show fips",                   # 'fips' as a show target, allowed
    "show crypto-local pki serverCerts",  # 'crypto-local' not the 'crypto' verb
    "show ap database",
    "no paging",
    "encrypt disable",
    "cd /md/Campus/00:11:22:33:44:55",
    "cd /mm",
    "show running-config | include fips",
    "show running-config | begin vlan",
    "show running-config | exclude 0.0.0.0",
    "show log security | count",
    "show ap blacklist-clients",
    "sh run",                      # AOS accepts 'sh'/'sho' abbreviations
    "sho version",
    "show\tversion",               # tab between verb and arg is normalized
]

UNSAFE = [
    "configure terminal",
    "con t",
    "write memory",
    "write erase all",
    "reload",
    "fips enable",
    "license add 1234",
    "backup flash",
    "copy flash: scp:",
    "tar logs tech-support",
    "show tech-support",           # file-generating / CPU heavy
    "show running-config; reload",  # chaining
    "show running-config && reload",
    "show foo | reload",            # mutating verb after pipe
    "show foo | sh",
    "show foo > /tmp/x",            # redirection
    "show foo `reload`",            # command substitution
    "show version\nreload",         # embedded newline
    # red-team regressions:
    "show running-config | include foo redirect flash: out.txt",  # pipe redirect exfil
    "show running-config | include x save flash: cfg.txt",        # pipe save exfil
    "show running-config | begin password | redirect tftp 1.2.3.4 x",
    "show version reload",     # Unicode line separator (U+2028)
    "show version reload",     # Unicode paragraph separator
    "show version\x85write memory",  # NEL
    "show version\x0breload",       # vertical tab
    "cd /md/../../mm",              # node traversal
    "cd /md/..",
    "cd /",                         # bare root
    "cd ..",
    "crypto pki ...",
    "clear gap",
    "ping 10.0.0.1",
    "ssh 10.0.0.1",
    "",
    "   ",
]


@pytest.mark.parametrize("cmd", SAFE)
def test_safe_commands_allowed(cmd):
    assert_safe(cmd)  # should not raise
    assert is_safe(cmd) is True


@pytest.mark.parametrize("cmd", UNSAFE)
def test_unsafe_commands_rejected(cmd):
    assert is_safe(cmd) is False
    with pytest.raises(UnsafeCommandError):
        assert_safe(cmd)


def test_none_command_rejected():
    with pytest.raises(UnsafeCommandError):
        assert_safe(None)  # type: ignore[arg-type]


def test_every_catalog_command_is_safe():
    # Construction calls assert_safe, but assert explicitly for clarity.
    assert len(COMMAND_CATALOG) > 0
    for spec in COMMAND_CATALOG:
        assert isinstance(spec, CommandSpec)
        assert_safe(spec.command)
        for alt in spec.alternates:
            assert_safe(alt)


def test_catalog_keys_unique():
    keys = [s.key for s in COMMAND_CATALOG]
    assert len(keys) == len(set(keys)), "duplicate evidence keys in COMMAND_CATALOG"
