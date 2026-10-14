"""--password-env, checked before anything dials.

A variable that never made it into the shell is the most common way these
commands fail, and the failure used to surface from inside paramiko as "No
authentication methods available" — which reads like a broken account on the
controller. Every test here asserts the check happens locally, early, and says
which variable it looked for.
"""

import pytest

from aos8_auditor.cli import _env_password, main
from test_remediate_apply import _artifact
from test_remediate_approve import READY


def test_a_variable_that_is_not_set_stops_the_run_before_connecting(monkeypatch,
                                                                    capsys):
    monkeypatch.delenv("AOS_NOPE", raising=False)

    assert main(["--host", "10.0.0.1", "--username", "admin",
                 "--password-env", "AOS_NOPE"]) == 2
    err = capsys.readouterr().err
    assert "AOS_NOPE" in err and "not set" in err


def test_an_empty_variable_is_reported_as_empty_not_missing(monkeypatch, capsys):
    """`export AOS_PW=` and forgetting to export at all are different mistakes
    with different fixes, so they get different messages."""
    monkeypatch.setenv("AOS_PW", "")

    assert main(["--host", "10.0.0.1", "--username", "admin",
                 "--password-env", "AOS_PW"]) == 2
    assert "set but empty" in capsys.readouterr().err


def test_a_key_file_makes_a_missing_password_a_warning(monkeypatch, capsys):
    """Key auth can still carry the session. Saying nothing at all could not:
    a named variable that is silently ignored is how the next hour gets spent."""
    monkeypatch.delenv("AOS_NOPE", raising=False)

    password, problem = _env_password("AOS_NOPE", key_file="/tmp/id_ed25519")
    assert password is None and problem is None
    assert "AOS_NOPE" in capsys.readouterr().err


def test_no_password_env_at_all_is_not_an_error():
    assert _env_password(None, key_file=None) == (None, None)


# -- the apply path -------------------------------------------------------

def test_apply_checks_the_variable_before_asking_for_confirmation(tmp_path,
                                                                  monkeypatch,
                                                                  capsys):
    """Typing 'apply' and then being told about a shell variable spends the one
    decision that matters on a run that was never going to start."""
    monkeypatch.delenv("AOS_NOPE", raising=False)
    monkeypatch.setattr("builtins.input", _no_input)
    artifact = _artifact(tmp_path, READY)

    assert main(["--remediate-apply", str(artifact.directory),
                 "--host", "10.0.0.1", "--username", "admin",
                 "--password-env", "AOS_NOPE"]) == 2
    assert "AOS_NOPE" in capsys.readouterr().err


def test_a_dry_run_needs_no_credentials(tmp_path, monkeypatch):
    """A rehearsal opens no socket, so requiring a password to run one would be
    a check with nothing behind it."""
    monkeypatch.delenv("AOS_NOPE", raising=False)
    artifact = _artifact(tmp_path, READY)

    assert main(["--remediate-apply", str(artifact.directory),
                 "--host", "10.0.0.1", "--username", "admin",
                 "--password-env", "AOS_NOPE", "--remediate-dry-run"]) == 0


def _no_input(_prompt=""):
    raise AssertionError("nothing should be asked before the credentials check")
