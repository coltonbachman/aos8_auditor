"""exit_kind classification keys off AOS8 *output text*, not SSH status."""

import pytest

from aos8_auditor.collection.classify import classify_exit_kind
from aos8_auditor.model.evidence import ExitKind


@pytest.mark.parametrize("output,expected", [
    ("You do not have permission to run this command", ExitKind.DENIED),
    ("% Permission denied.", ExitKind.DENIED),
    ("Parse error", ExitKind.UNSUPPORTED),
    ("% Invalid input detected at '^' marker.", ExitKind.UNSUPPORTED),
    ("Unrecognized command", ExitKind.UNSUPPORTED),
    ("", ExitKind.EMPTY),
    ("    \n   \n", ExitKind.EMPTY),
    ("FIPS Settings:\n--------------\nMode    Enabled\n", ExitKind.OK),
])
def test_classify(output, expected):
    kind, _sig = classify_exit_kind(output)
    assert kind == expected


def test_prompt_only_output_is_empty():
    # Output that is just a returned prompt has no content.
    kind, _ = classify_exit_kind("(JITC7240) [mynode] #")
    assert kind == ExitKind.EMPTY


def test_echoed_command_does_not_count_as_content():
    kind, _ = classify_exit_kind("show fips\n", echoed_command="show fips")
    assert kind == ExitKind.EMPTY


def test_denied_takes_precedence_over_unsupported():
    kind, sig = classify_exit_kind("Parse error: you do not have permission")
    assert kind == ExitKind.DENIED
    assert sig is not None


# --- Regression: must NOT misread real config as an error (red-team) ---
def test_banner_with_denial_phrase_is_not_denied():
    out = (
        "banner motd ^\n"
        "WARNING: Unauthorized access prohibited. You do not have permission.\n"
        "^\n"
        "version 8.6.0.4\nhostname controller1\nvlan 1\nvlan 100\n"
        "interface gigabitethernet 0/0/0\n trusted\n"
    )
    kind, _ = classify_exit_kind(out)
    assert kind != ExitKind.DENIED


def test_large_config_with_signature_phrase_in_quotes_is_ok():
    body = "\n".join(f"vlan {i}" for i in range(50))
    out = f'netdestination "parse error block"\n host 10.0.0.1\n{body}\n'
    assert classify_exit_kind(out)[0] == ExitKind.OK


def test_short_permission_errors_are_denied():
    assert classify_exit_kind("You do not have permission to run this command")[0] == ExitKind.DENIED
    assert classify_exit_kind("You are not allowed to run this command")[0] == ExitKind.DENIED


def test_short_unsupported_is_unsupported():
    assert classify_exit_kind("Command not supported on this platform")[0] == ExitKind.UNSUPPORTED
    assert classify_exit_kind("% This command is only available on Mobility Master")[0] == ExitKind.UNSUPPORTED


def test_quoted_name_with_signature_is_ok():
    assert classify_exit_kind('netdestination "parse error block"\n host 10.0.0.1\n')[0] == ExitKind.OK


def test_interface_counter_internal_error_is_not_error():
    out = (
        "Interface stats:\n internal error count: 0\n crc errors: 5\n"
        " rx packets: 100\n tx packets: 99\n"
    )
    assert classify_exit_kind(out)[0] == ExitKind.OK
