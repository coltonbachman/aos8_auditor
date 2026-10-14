"""The two opt-in flags, driven through the real entry point.

Everything else in this tool is read-only, and the tests for it can rely on that
by construction. These cannot: --remediate-apply is the one flag that reaches a
code path able to send configuration. So the fake is installed at the *netmiko*
boundary — the same place a real connection would be made — and what the tests
assert is what came out the far end of it.

If the gate at any layer regressed, these tests fail by recording a command in
``device.sent``, not by changing a controller.
"""

import json
import sys
import types
from pathlib import Path

import pytest

from aos8_auditor.cli import main
from aos8_auditor.remediate.apply import ATTEMPT_NAME, TRANSCRIPT_NAME
from aos8_auditor.remediate.approve import APPROVAL_NAME, RESULT_NAME
from test_remediate_apply import SAFE, FakeController, _artifact
from test_remediate_approve import READY, _rewrite, _sub_line


@pytest.fixture
def device(monkeypatch):
    """One controller, wired in where netmiko would be."""
    controller = FakeController()
    module = types.ModuleType("netmiko")
    module.ConnectHandler = lambda **kwargs: controller
    monkeypatch.setitem(sys.modules, "netmiko", module)
    return controller


def _apply(directory, *flags, host="10.0.0.1"):
    return main(["--remediate-apply", str(directory),
                 "--host", host, "--username", "admin", *flags])


# -- the export has to hold up before anything is dialled -----------------

def test_an_edited_export_is_refused_and_says_how_to_proceed(tmp_path, device, capsys):
    """The refusal has to name the way forward, or the operator's next move is to
    paste the file by hand — which has no gate on it at all."""
    artifact = _artifact(tmp_path, READY)
    _rewrite(artifact.directory,
             _sub_line("ssh mgmt-auth public-key", "ssh mgmt-auth username/password"))

    assert _apply(artifact.directory, "--remediate-yes") == 4
    assert device.sent == []
    assert "--remediate-approve" in capsys.readouterr().err


def test_a_directory_that_is_not_an_export_is_a_plain_error(tmp_path, device):
    assert _apply(tmp_path / "nowhere", "--remediate-yes") == 1
    assert device.sent == []


def test_applying_without_a_host_is_a_usage_error(tmp_path, device):
    artifact = _artifact(tmp_path, READY)
    assert main(["--remediate-apply", str(artifact.directory),
                 "--remediate-yes"]) == 2
    assert device.sent == []


# -- confirmation ---------------------------------------------------------

def test_a_non_interactive_run_will_not_apply_by_default(tmp_path, device,
                                                         monkeypatch):
    """A pipeline that happens to invoke this must not quietly reconfigure a
    controller because nobody was there to say no."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")

    assert _apply(_artifact(tmp_path, READY).directory) == 4
    assert device.sent == []


def test_typing_anything_other_than_apply_sends_nothing(tmp_path, device,
                                                        monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "yes")

    assert _apply(_artifact(tmp_path, READY).directory) == 4
    assert device.sent == []


def test_with_no_terminal_and_no_flag_it_refuses_rather_than_assuming(tmp_path,
                                                                     device,
                                                                     monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    assert _apply(_artifact(tmp_path, READY).directory) == 4
    assert device.sent == []


def test_a_lockout_risky_change_is_confirmed_line_by_line(tmp_path, device,
                                                          monkeypatch, capsys):
    """The second prompt shows the actual commands. Confirming a control id
    without seeing what it expands to is not consent to anything in particular."""
    answers = iter(["apply", "y"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    assert _apply(_artifact(tmp_path, READY).directory) == 0
    err = capsys.readouterr().err
    assert "can cut off your own access" in err
    assert "ssh mgmt-auth public-key" in err


# -- the run --------------------------------------------------------------

def test_a_confirmed_run_applies_and_reports_where_the_record_is(tmp_path, device,
                                                                 capsys):
    artifact = _artifact(tmp_path, READY)
    assert _apply(artifact.directory, "--remediate-yes") == 0

    assert "ssh mgmt-auth public-key" in device.sent
    out = capsys.readouterr().out
    assert "outcome: applied" in out
    assert RESULT_NAME in out
    assert (artifact.directory / RESULT_NAME).exists()
    assert (artifact.directory / TRANSCRIPT_NAME).exists()


def test_a_run_that_stopped_part_way_exits_differently_from_one_that_refused(
        tmp_path, device):
    """0/4/5 have to mean three different things to whatever is watching: it
    worked, we did not touch it, and someone needs to go and look."""
    device.fail_on["session-timeout 360"] = "% Invalid input detected at '^' marker."
    artifact = _artifact(tmp_path, READY, SAFE)

    assert _apply(artifact.directory, "--remediate-yes") == 5


def test_a_staged_run_does_not_exit_zero(tmp_path, device, capsys):
    """Nothing failed and nothing is in effect. Anything reading the exit code
    to decide whether the controller is hardened would get the wrong answer from
    a success, so this run has a code of its own."""
    device.stages = True
    artifact = _artifact(tmp_path, READY)

    assert _apply(artifact.directory, "--remediate-yes") == 6
    out = capsys.readouterr()
    assert "outcome: staged" in out.out
    assert "NOT IN EFFECT YET" in out.out
    assert not any("write" in c for c in device.sent)


def test_the_worst_node_is_the_one_the_caller_hears_about():
    """A Mobility Master applies per node, and the codes are identifiers rather
    than a scale — the larger number is the smaller problem here, so the summary
    cannot be max()."""
    from aos8_auditor.cli import _worst_apply_code

    assert _worst_apply_code([0, 6]) == 6      # one node needs a commit
    assert _worst_apply_code([6, 5]) == 5      # ...and another stopped part-way
    assert _worst_apply_code([0, 0]) == 0
    assert _worst_apply_code([4, 6]) == 4      # a refusal outranks a commit


def test_the_second_apply_of_the_same_export_is_refused(tmp_path, device, capsys):
    artifact = _artifact(tmp_path, READY)
    assert _apply(artifact.directory, "--remediate-yes") == 0

    device.sent.clear()
    assert _apply(artifact.directory, "--remediate-yes") == 4
    assert device.sent == []
    assert "already applied in full" in capsys.readouterr().err


def test_the_wrong_controller_is_refused_after_a_read_only_look(tmp_path, device):
    """It has to connect to find out, so 'sent nothing' here means sent nothing
    that changes anything — which is the property worth pinning."""
    from aos8_auditor.collection.command_catalog import assert_safe

    artifact = _artifact(tmp_path, READY, target={"serial": "CX0001111"})
    assert _apply(artifact.directory, "--remediate-yes") == 4

    assert device.sent
    for command in device.sent:
        assert_safe(command)


# -- the rehearsal --------------------------------------------------------

def test_a_dry_run_dials_nothing_and_asks_nothing(tmp_path, device, monkeypatch):
    """No socket at all is the cheapest guarantee that a rehearsal cannot send.
    It also must not block on a prompt, or --remediate-dry-run is unusable from
    the place it is most useful: a change-review pipeline."""
    monkeypatch.setattr("builtins.input", _no_input)

    artifact = _artifact(tmp_path, READY)
    assert _apply(artifact.directory, "--remediate-dry-run") == 0
    assert device.sent == []


def test_a_dry_run_prints_what_would_be_sent(tmp_path, device, capsys):
    artifact = _artifact(tmp_path, READY)
    _apply(artifact.directory, "--remediate-dry-run")

    text = (artifact.directory / TRANSCRIPT_NAME).read_text()
    assert "THIS WAS A DRY RUN" in text
    assert "ssh mgmt-auth public-key" in text
    assert "outcome: dry_run" in capsys.readouterr().out


def test_a_dry_run_leaves_the_export_appliable(tmp_path, device):
    """A rehearsal that consumed the artifact would be worse than no rehearsal."""
    artifact = _artifact(tmp_path, READY)
    assert _apply(artifact.directory, "--remediate-dry-run") == 0
    assert (artifact.directory / ATTEMPT_NAME).exists()
    assert not (artifact.directory / RESULT_NAME).exists()

    assert _apply(artifact.directory, "--remediate-yes") == 0
    assert "ssh mgmt-auth public-key" in device.sent


def _no_input(_prompt=""):
    raise AssertionError("a dry run must not prompt")


# -- re-approval ----------------------------------------------------------

def test_approving_an_edited_export_makes_it_appliable_again(tmp_path, device):
    """The supported edit path. Refusing it would push operators back to pasting
    by hand, which is the thing this whole feature is trying to improve on."""
    artifact = _artifact(tmp_path, READY)
    _rewrite(artifact.directory,
             _sub_line("ssh mgmt-auth public-key",
                       "ssh mgmt-auth public-key username/password"))

    assert main(["--remediate-approve", str(artifact.directory),
                 "--operator", "tester", "--remediate-note", "CHG-1234"]) == 0
    approval = json.loads((artifact.directory / APPROVAL_NAME).read_text())
    assert approval["operator"] == "tester"
    assert approval["note"] == "CHG-1234"
    assert approval["supersedes_sha256"] != approval["remediation_cfg_sha256"]

    assert _apply(artifact.directory, "--remediate-yes") == 0
    assert "ssh mgmt-auth public-key username/password" in device.sent


def test_approval_is_not_a_way_to_sign_off_on_a_destructive_command(tmp_path):
    """An approval supersedes the hash pin and nothing else. If it could bless
    anything the emitter refuses to write, the pin would be the only check left."""
    artifact = _artifact(tmp_path, READY)
    _rewrite(artifact.directory, _sub_line("ssh mgmt-auth public-key", "reload"))

    assert main(["--remediate-approve", str(artifact.directory)]) == 4
    assert not (artifact.directory / APPROVAL_NAME).exists()


def test_a_failed_approval_leaves_no_file_behind(tmp_path):
    """A directory holding an approval.json that does not verify reads as
    approved to anyone who looks at the file listing."""
    artifact = _artifact(tmp_path, READY)
    _rewrite(artifact.directory, _sub_line("end", "! end"))

    main(["--remediate-approve", str(artifact.directory)])
    assert not (artifact.directory / APPROVAL_NAME).exists()


def test_approving_contacts_nothing(tmp_path, device):
    artifact = _artifact(tmp_path, READY)
    _rewrite(artifact.directory,
             _sub_line("ssh mgmt-auth public-key",
                       "ssh mgmt-auth public-key username/password"))

    assert main(["--remediate-approve", str(artifact.directory),
                 "--host", "10.0.0.1", "--username", "admin"]) == 0
    assert device.sent == []
