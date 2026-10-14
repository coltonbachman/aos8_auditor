"""The remediation flags, driven through the real entry point.

Everything here replays an evidence bundle, so no test in this file can reach a
controller even if the read-only guarantee were broken — which is also the point
being asserted: remediation is a step that runs *after* an audit, on files, and
adds no device access of its own.
"""

import json
import stat
from pathlib import Path

import pytest
import yaml

from aos8_auditor.cli import main
from aos8_auditor.collection.classify import classify_exit_kind
from aos8_auditor.collection.collector import Collector
from aos8_auditor.collection.redaction import redact
from aos8_auditor.model.evidence import CommandResult

CONFIG = Path(__file__).parent.parent / "fixtures" / "sample_running_config.txt"
# Fails on the fixture and needs no answers, so it can be accepted from a values
# file without inventing values the test would then have to keep valid.
READY = "AOS8-MGMT-SSH-PUBKEY-001"


class _Replay:
    """Serves the fixture without a device. Same shape as Session.run."""

    def __init__(self, outputs):
        self.outputs = outputs

    def run(self, command, *, timeout_s=None):
        raw = self.outputs.get(command, "")
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
    outputs = {
        "show version": "ArubaOS (MODEL: Aruba7240), Version 8.6.0.4",
        "show running-config": CONFIG.read_text(),
    }
    c = Collector(_Replay(outputs), out_root=tmp_path / "runs", run_id="cli-remediate")
    return c.write_bundle(c.collect(host="10.0.0.9"))


def _run(evidence, tmp_path, *flags):
    return main(["--from-evidence", str(evidence), "--out", str(tmp_path / "out"),
                 *flags])


def _values(path, control_id, **entry):
    doc = yaml.safe_load(path.read_text())
    for e in doc["changes"]:
        if e["control_id"] == control_id:
            e.update({"accept": True, **entry})
    path.write_text(yaml.safe_dump(doc))
    return path


# -- the template ---------------------------------------------------------

def test_the_template_flag_writes_a_values_file(evidence, tmp_path, capsys):
    out = tmp_path / "rem"
    assert _run(evidence, tmp_path, "--remediate-template", "--remediate-out", str(out)) == 0
    path = out / "remediation_values.yaml"
    assert path.exists()
    assert READY in {e["control_id"] for e in yaml.safe_load(path.read_text())["changes"]}
    assert str(path) in capsys.readouterr().out


def test_the_template_flag_writes_no_config(evidence, tmp_path):
    """Asking what the questions are must not produce something pasteable."""
    out = tmp_path / "rem"
    _run(evidence, tmp_path, "--remediate-template", "--remediate-out", str(out))
    assert not (out / "remediation.cfg").exists()


# -- the round trip -------------------------------------------------------

def test_template_then_values_produces_the_three_artifacts(evidence, tmp_path):
    out = tmp_path / "rem"
    _run(evidence, tmp_path, "--remediate-template", "--remediate-out", str(out))
    values = _values(out / "remediation_values.yaml", READY)

    assert _run(evidence, tmp_path, "--remediate-from", str(values),
                "--remediate-out", str(out)) == 0
    cfg = out / "remediation.cfg"
    assert cfg.exists() and (out / "rollback.cfg").exists()
    record = json.loads((out / "remediation.json").read_text())
    assert [c["control_id"] for c in record["changes"]] == [READY]
    assert "ssh mgmt-auth public-key" in cfg.read_text()


def test_the_artifacts_are_owner_only(evidence, tmp_path):
    out = tmp_path / "rem"
    _run(evidence, tmp_path, "--remediate-template", "--remediate-out", str(out))
    values = _values(out / "remediation_values.yaml", READY)
    _run(evidence, tmp_path, "--remediate-from", str(values), "--remediate-out", str(out))
    for name in ("remediation.cfg", "rollback.cfg", "remediation.json"):
        assert stat.S_IMODE((out / name).stat().st_mode) == 0o600, name


def test_the_output_says_nothing_was_applied(evidence, tmp_path, capsys):
    """The one line an operator skims. It has to say the tool stopped short."""
    out = tmp_path / "rem"
    _run(evidence, tmp_path, "--remediate-template", "--remediate-out", str(out))
    values = _values(out / "remediation_values.yaml", READY)
    _run(evidence, tmp_path, "--remediate-from", str(values), "--remediate-out", str(out))
    assert "NOT APPLIED" in capsys.readouterr().out


def test_an_untouched_template_writes_nothing(evidence, tmp_path, capsys):
    """Round-tripping the template unedited must be a no-op, not a full export."""
    out = tmp_path / "rem"
    _run(evidence, tmp_path, "--remediate-template", "--remediate-out", str(out))
    rc = _run(evidence, tmp_path, "--remediate-from",
              str(out / "remediation_values.yaml"), "--remediate-out", str(out))
    assert rc == 0
    assert not (out / "remediation.cfg").exists()
    assert "nothing accepted" in capsys.readouterr().out


# -- failure paths --------------------------------------------------------

def test_a_bad_answer_fails_the_run_and_writes_no_config(evidence, tmp_path, capsys):
    out = tmp_path / "rem"
    _run(evidence, tmp_path, "--remediate-template", "--remediate-out", str(out))
    values = _values(out / "remediation_values.yaml", "AOS8-NET-VLAN-STATICIP-001",
                     values={"id": 9000})

    assert _run(evidence, tmp_path, "--remediate-from", str(values),
                "--remediate-out", str(out)) == 1
    assert not (out / "remediation.cfg").exists()
    assert "out of range" in capsys.readouterr().err


def test_a_missing_values_file_is_an_error_not_a_traceback(evidence, tmp_path, capsys):
    assert _run(evidence, tmp_path, "--remediate-from", str(tmp_path / "nope.yaml")) == 1
    assert "--remediate-from" in capsys.readouterr().err


def test_a_stale_values_file_still_runs(evidence, tmp_path, capsys):
    """A control that has since been fixed is a note on stderr, not a failure."""
    out = tmp_path / "rem"
    out.mkdir()
    values = out / "values.yaml"
    values.write_text(yaml.safe_dump({"changes": [
        {"control_id": "AOS8-DOES-NOT-EXIST-001", "accept": True},
        {"control_id": READY, "accept": True}]}))

    assert _run(evidence, tmp_path, "--remediate-from", str(values),
                "--remediate-out", str(out)) == 0
    assert "AOS8-DOES-NOT-EXIST-001" in capsys.readouterr().err
    assert (out / "remediation.cfg").exists()


# -- staying out of the way ----------------------------------------------

def test_an_ordinary_audit_writes_no_remediation_artifacts(evidence, tmp_path):
    """The flags are opt-in. A plain run must not start producing config files."""
    assert _run(evidence, tmp_path) == 0
    assert not list(tmp_path.rglob("remediation.cfg"))
    assert not list(tmp_path.rglob("remediation_values.yaml"))


def test_remediation_defaults_to_the_run_directory(evidence, tmp_path):
    """Without --remediate-out the artifacts land beside the report they explain
    — which under --from-evidence is the replayed bundle, not --out."""
    assert _run(evidence, tmp_path, "--remediate-template") == 0
    assert (evidence / "remediation_values.yaml").exists()
