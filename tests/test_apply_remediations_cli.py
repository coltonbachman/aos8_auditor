"""--apply-remediations: audit, generate and push in one command.

The flag exists because the two-command shape (write an export, then apply it)
is the right default and the wrong ceremony when the operator generating the
change is the operator making it. What has to stay true is that the shortcut is
a shortcut through the *prompts*, not through the checks: the same artifact is
written, hash-pinned and verified, and the same per-block gates run.

netmiko is faked at the import boundary, so a regression here fails by recording
a command in ``device.sent`` rather than by reconfiguring anything.
"""

import sys
import types

import pytest
import yaml

from aos8_auditor.cli import main
from aos8_auditor.collection.classify import classify_exit_kind
from aos8_auditor.collection.collector import Collector
from aos8_auditor.collection.redaction import redact
from aos8_auditor.model.evidence import CommandResult
from aos8_auditor.remediate.approve import RESULT_NAME
from test_remediate_apply import SAFE, FakeController
from test_remediate_preflight import RUNNING_CONFIG, SHOW_VERSION

READY = "AOS8-MGMT-SSH-PUBKEY-001"


class _Replay:
    """Serves the same config the fake controller will serve. Shape of Session.run."""

    def run(self, command, *, timeout_s=None):
        raw = {"show version": SHOW_VERSION,
               "show running-config": RUNNING_CONFIG}.get(command, "")
        rr = redact(raw)
        kind, sig = classify_exit_kind(raw, echoed_command=command)
        r = CommandResult(command=command, redacted_output=rr.text, exit_kind=kind,
                          error_signature=sig, redaction_count=rr.count,
                          redaction_kinds=rr.kinds,
                          started_at="2026-05-29T00:00:00+00:00", duration_ms=1)
        r.sha256 = r.compute_sha256()
        return r


@pytest.fixture
def evidence(tmp_path):
    c = Collector(_Replay(), out_root=tmp_path / "runs", run_id="apply-now")
    return c.write_bundle(c.collect(host="10.0.0.1"))


@pytest.fixture
def device(monkeypatch):
    controller = FakeController()
    module = types.ModuleType("netmiko")
    module.ConnectHandler = lambda **kwargs: controller
    monkeypatch.setitem(sys.modules, "netmiko", module)
    return controller


def _values(evidence, tmp_path, *control_ids):
    """A values file accepting the named controls, via the real template flag."""
    out = tmp_path / "rem"
    main(["--from-evidence", str(evidence), "--out", str(tmp_path / "o"),
          "--remediate-template", "--remediate-out", str(out)])
    path = out / "remediation_values.yaml"
    doc = yaml.safe_load(path.read_text())
    for entry in doc["changes"]:
        if entry["control_id"] in control_ids:
            entry["accept"] = True
    path.write_text(yaml.safe_dump(doc))
    return out, path


def _generate(evidence, tmp_path, *flags, controls=(READY,)):
    out, values = _values(evidence, tmp_path, *controls)
    rc = main(["--from-evidence", str(evidence), "--out", str(tmp_path / "o"),
               "--remediate-from", str(values), "--remediate-out", str(out),
               "--host", "10.0.0.1", "--username", "admin", *flags])
    return out, rc


# -- the flag -------------------------------------------------------------

def test_without_the_flag_the_run_still_stops_at_the_files(evidence, tmp_path,
                                                           device, capsys):
    """The default has not moved. Everything else here is opt-in on top of it."""
    out, rc = _generate(evidence, tmp_path)

    assert rc == 0
    assert device.sent == []
    assert "NOT APPLIED" in capsys.readouterr().out


def test_the_flag_generates_and_then_pushes(evidence, tmp_path, device):
    out, rc = _generate(evidence, tmp_path, "--apply-remediations", "--remediate-yes")

    assert rc == 0
    assert "ssh mgmt-auth public-key" in device.sent
    assert (out / RESULT_NAME).exists()


def test_the_pushed_bytes_are_the_ones_that_were_written(evidence, tmp_path, device):
    """The shortcut skips prompts, not the pin. What lands has to be what the
    export says, or 'review the file' stops meaning anything."""
    out, _ = _generate(evidence, tmp_path, "--apply-remediations", "--remediate-yes")

    written = (out / "remediation.cfg").read_text()
    configured = [c for c in device.sent
                  if not c.startswith(("show ", "cd ")) and c not in
                  ("configure terminal", "end", "no paging")]
    for command in configured:
        assert command in written


def test_write_memory_is_never_sent(evidence, tmp_path, device):
    """The whole escape hatch is that a reboot undoes this."""
    _generate(evidence, tmp_path, "--apply-remediations", "--remediate-yes")

    assert not any("write" in c and "memory" in c for c in device.sent)


def test_a_dry_run_generates_the_files_and_sends_nothing(evidence, tmp_path, device):
    out, rc = _generate(evidence, tmp_path, "--apply-remediations",
                        "--remediate-dry-run")

    assert rc == 0
    assert device.sent == []
    assert (out / "remediation.cfg").exists()
    assert not (out / RESULT_NAME).exists()


def test_a_run_that_stopped_part_way_reports_it_through_the_exit_code(
        evidence, tmp_path, device):
    """--apply-remediations must not swallow the outcome: the remediation half
    succeeded, and reporting 0 because of that would hide a half-applied run."""
    device.fail_on["session-timeout 360"] = "% Invalid input detected at '^' marker."

    _out, rc = _generate(evidence, tmp_path, "--apply-remediations", "--remediate-yes",
                         controls=(READY, SAFE))

    assert rc == 5


def test_applying_without_a_host_is_refused_after_the_files_are_written(
        evidence, tmp_path, device, capsys):
    out, values = _values(evidence, tmp_path, READY)
    rc = main(["--from-evidence", str(evidence), "--out", str(tmp_path / "o"),
               "--remediate-from", str(values), "--remediate-out", str(out),
               "--apply-remediations"])

    assert rc == 2
    assert device.sent == []
    assert (out / "remediation.cfg").exists()   # the export half still happened
    assert "--host" in capsys.readouterr().err


# -- the confirmation -----------------------------------------------------

def test_the_confirmation_names_the_controller_and_defaults_to_yes(
        evidence, tmp_path, device, monkeypatch, capsys):
    """[Y/n], not a typed word: the operator built this change set on screen in
    this run. Enter is the answer they already gave."""
    prompts = []
    answers = iter(["", "y"])          # bare Enter at the gate, then the block

    def answer(prompt=""):
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", answer)

    _out, rc = _generate(evidence, tmp_path, "--apply-remediations")

    assert rc == 0
    assert any("Apply changes to 10.0.0.1? [Y/n]" in p for p in prompts)
    assert "ssh mgmt-auth public-key" in device.sent


def test_answering_no_sends_nothing(evidence, tmp_path, device, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")

    _out, rc = _generate(evidence, tmp_path, "--apply-remediations")

    assert rc == 4
    assert device.sent == []


def test_a_lockout_risky_block_is_still_confirmed_on_its_own(evidence, tmp_path,
                                                             device, monkeypatch,
                                                             capsys):
    """One yes to 'apply this change set' is not a yes to 'lock yourself out'.
    The shortcut removes the typed word, not the per-block gate."""
    answers = iter(["", "y"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    _generate(evidence, tmp_path, "--apply-remediations")

    err = capsys.readouterr().err
    assert "can cut off your own access" in err
    assert "ssh mgmt-auth public-key" in err


def test_no_terminal_and_no_yes_flag_refuses(evidence, tmp_path, device,
                                             monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    _out, rc = _generate(evidence, tmp_path, "--apply-remediations")

    assert rc == 4
    assert device.sent == []
