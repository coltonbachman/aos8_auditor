"""Asking the controller whether the plan still applies to it.

An artifact is a file. It can be carried to the wrong controller, and it can sit
for a week while somebody fixes half of what it describes — the second is the
ordinary case when an apply stops part-way and is resumed. Both questions are
asked with read-only commands only, which is the property the last test here
pins directly.
"""

import json
from pathlib import Path

import pytest

from aos8_auditor.collection.command_catalog import assert_safe
from aos8_auditor.remediate.approve import load_artifact
from aos8_auditor.remediate.preflight import Drift, preflight
from aos8_auditor.transport.apply_session import ApplySession
from aos8_auditor.transport.connection import SSHConfig
from test_remediate_approve import READY, _export

CONFIG = SSHConfig(host="10.0.0.1", username="admin", password="x")
RUNNING_CONFIG = (Path(__file__).parent.parent / "fixtures"
                  / "sample_running_config.txt").read_text()

# What the fixture's audit was recorded against. detect_identity reads model,
# version and serial straight out of this.
SHOW_VERSION = """Aruba Operating System Software.
ArubaOS (MODEL: Aruba7240), Version 8.6.0.4
Serial Number: CX0009999
switch role: standalone
"""


class FakeDevice:
    """Answers the read-only catalog. Anything not listed replies with nothing,
    which is what a controller does for a feature that is not configured."""

    def __init__(self, running_config=RUNNING_CONFIG, version=SHOW_VERSION,
                 overrides=None):
        self.sent = []
        self.replies = {
            "show running-config": running_config,
            "show version": version,
            **(overrides or {}),
        }

    def send_command(self, command, read_timeout=None, **kw):
        self.sent.append(command)
        reply = self.replies.get(command, "")
        if isinstance(reply, Exception):
            raise reply
        return reply

    def disconnect(self):
        pass


def _session(tmp_path, *control_ids, device=None, dry_run=False, record_edit=None,
             **kw):
    d = _export(tmp_path, *(control_ids or (READY,)), **kw)
    if record_edit:
        record = json.loads((d / "remediation.json").read_text())
        record_edit(record)
        (d / "remediation.json").write_text(json.dumps(record))
    session = ApplySession(CONFIG, load_artifact(d), dry_run=dry_run)
    device = device or FakeDevice()
    if not dry_run:
        session._connection._conn = device
    return session, device


def _stamp(record, **target):
    """Record the identity the audit supposedly saw."""
    record.setdefault("source_run", {}).setdefault("target", {}).update(target)


MATCHING = dict(host="10.0.0.1", model="7240", aos_version="8.6.0.4",
                serial="CX0009999")


# -- question 1: the same controller? -------------------------------------

def test_the_right_controller_passes(tmp_path):
    session, _ = _session(tmp_path, record_edit=lambda r: _stamp(r, **MATCHING))
    report = preflight(session, session.artifact)
    assert report.ok, report.errors
    assert report.apply_ids == [READY]


def test_a_different_serial_stops_the_run(tmp_path):
    """The strongest identity signal there is, and the one that catches the
    artifact being carried to a sibling controller."""
    session, _ = _session(tmp_path,
                          record_edit=lambda r: _stamp(r, **{**MATCHING,
                                                            "serial": "CX0001111"}))
    report = preflight(session, session.artifact)
    assert not report.ok
    assert any("not the controller the audit ran against" in e for e in report.errors)


def test_a_different_model_stops_the_run(tmp_path):
    session, _ = _session(tmp_path,
                          record_edit=lambda r: _stamp(r, **{**MATCHING,
                                                            "model": "7010"}))
    report = preflight(session, session.artifact)
    assert not report.ok
    assert any("7010" in e for e in report.errors)


def test_a_different_train_stops_the_run(tmp_path):
    """Syntax and defaults move between trains; the plan was written for one."""
    session, _ = _session(tmp_path,
                          record_edit=lambda r: _stamp(r, **{**MATCHING,
                                                            "aos_version": "8.10.0.0"}))
    report = preflight(session, session.artifact)
    assert not report.ok
    assert any("re-audit and generate a fresh plan" in e for e in report.errors)


def test_a_patch_upgrade_is_a_warning_not_a_refusal(tmp_path):
    """Refusing here would mean any maintenance window invalidates a plan made
    the same morning."""
    session, _ = _session(tmp_path,
                          record_edit=lambda r: _stamp(r, **{**MATCHING,
                                                            "aos_version": "8.6.0.9"}))
    report = preflight(session, session.artifact)
    assert report.ok, report.errors
    assert any("upgraded since the audit" in w for w in report.warnings)


def test_a_weak_identity_check_says_so(tmp_path):
    """Model and version match on every controller in a rack."""
    session, _ = _session(
        tmp_path, device=FakeDevice(version=SHOW_VERSION.replace(
            "Serial Number: CX0009999", "")),
        record_edit=lambda r: _stamp(r, **{**MATCHING, "serial": None}))
    report = preflight(session, session.artifact)
    assert report.ok, report.errors
    assert any("could not confirm this is the same controller" in w
               for w in report.warnings)


def test_connecting_by_a_different_address_is_only_a_warning(tmp_path):
    session, _ = _session(tmp_path,
                          record_edit=lambda r: _stamp(r, **{**MATCHING,
                                                            "host": "wlc-a.example"}))
    report = preflight(session, session.artifact)
    assert report.ok, report.errors
    assert any("Addresses and names change" in w for w in report.warnings)


def test_the_wrong_controller_is_not_also_described_as_drift(tmp_path):
    """Every line of a drift report about the wrong device is about the wrong
    device, and reads as though it were about the right one."""
    session, _ = _session(tmp_path,
                          record_edit=lambda r: _stamp(r, **{**MATCHING,
                                                            "serial": "CX0001111"}))
    report = preflight(session, session.artifact)
    assert report.drift == []
    assert report.report is None


# -- question 2: still failing? -------------------------------------------

def test_a_finding_someone_else_already_fixed_is_dropped(tmp_path):
    """The resume case, and the someone-beat-you-to-it case, are the same case."""
    fixed = RUNNING_CONFIG + "\nssh mgmt-auth public-key\n"
    session, _ = _session(tmp_path, device=FakeDevice(running_config=fixed),
                          record_edit=lambda r: _stamp(r, **MATCHING))
    report = preflight(session, session.artifact)

    assert report.ok, report.errors
    assert report.apply_ids == []
    assert report.verdict_for(READY).verdict is Drift.ALREADY_SATISFIED
    assert any("no longer needed" in w for w in report.warnings)
    assert any("nothing in this artifact still needs applying" in w
               for w in report.warnings)


def test_a_finding_that_cannot_be_evaluated_is_dropped(tmp_path):
    """Applying a change whose precondition could not be checked is how a fix
    lands on a configuration it was not written for.

    FIPS is manual against this fixture — the controller alone cannot say whether
    FIPS is required here — so the re-audit has no verdict to offer.
    """
    session, _ = _session(tmp_path, "AOS8-GLOBAL-FIPS-001",
                          record_edit=lambda r: _stamp(r, **MATCHING))
    report = preflight(session, session.artifact)

    verdict = report.verdict_for("AOS8-GLOBAL-FIPS-001")
    assert verdict.verdict is Drift.UNDETERMINED
    assert "could not decide" in verdict.reason
    assert report.apply_ids == []
    assert any("could not be determined" in w for w in report.warnings)


def test_a_control_missing_from_the_re_audit_is_undetermined(tmp_path):
    """A control id that no longer exists — the artifact outlived a controls
    update — must not be silently treated as still failing."""
    session, _ = _session(tmp_path, record_edit=lambda r: _stamp(r, **MATCHING))
    report = preflight(session, session.artifact, controls=[])

    verdict = report.verdict_for(READY)
    assert verdict.verdict is Drift.UNDETERMINED
    assert "not evaluated" in verdict.reason
    assert report.apply_ids == []


def test_a_finding_that_changed_shape_is_flagged_but_still_applied(tmp_path):
    """Still broken, but not in the way the plan describes it. Worth reading the
    block again; not worth refusing, since the finding does still stand."""
    def edit(r):
        _stamp(r, **MATCHING)
        r["changes"][0]["observed"] = "something the controller no longer says"

    session, _ = _session(tmp_path, record_edit=edit)
    report = preflight(session, session.artifact)

    assert READY in report.apply_ids
    assert report.verdict_for(READY).changed_but_still_failing
    assert any("no longer looks the way the plan describes it" in w
               for w in report.warnings)


# -- refusing to guess ----------------------------------------------------

def test_a_capture_without_the_running_config_stops_the_run(tmp_path):
    """A control that could not be read would otherwise be reported as fixed.

    This is the failure mode the whole check exists for: a read-only command
    reports its failure in the result rather than raising, which is right for an
    audit and dangerous here.
    """
    session, _ = _session(
        tmp_path,
        device=FakeDevice(running_config="You do not have permission to run this command"),
        record_edit=lambda r: _stamp(r, **MATCHING))
    report = preflight(session, session.artifact)
    assert not report.ok
    assert any("cannot re-audit this controller" in e for e in report.errors)


def test_a_dropped_link_stops_the_run(tmp_path):
    """Half a capture is not something to plan a change from."""
    class ReadTimeout(Exception):
        pass

    session, _ = _session(
        tmp_path,
        device=FakeDevice(overrides={"show switches": ReadTimeout("timed out")}),
        record_edit=lambda r: _stamp(r, **MATCHING))
    report = preflight(session, session.artifact)
    assert not report.ok
    assert any("did not come back" in e for e in report.errors)


def test_an_unreachable_node_stops_the_run(tmp_path):
    """The blocks navigate to that node. If 'cd' does not work, they cannot."""
    session, _ = _session(
        tmp_path, node_path="/md/Campus/wlc-1",
        device=FakeDevice(overrides={"cd /md/Campus/wlc-1": "% Invalid input"}),
        record_edit=lambda r: _stamp(r, **MATCHING))
    report = preflight(session, session.artifact)
    assert not report.ok
    assert any("cannot reach node /md/Campus/wlc-1" in e for e in report.errors)


def test_the_node_is_reached_before_anything_is_read(tmp_path):
    """Reading the running-config from the wrong node then applying to the right
    one would compare a plan against a config that is not the one being changed."""
    session, device = _session(tmp_path, node_path="/md/Campus/wlc-1",
                               record_edit=lambda r: _stamp(r, **MATCHING))
    preflight(session, session.artifact)
    assert device.sent[0] == "cd /md/Campus/wlc-1"


# -- the property that matters --------------------------------------------

def test_preflight_sends_nothing_that_is_not_read_only(tmp_path):
    """Preflight runs before the operator has confirmed anything, so it has to be
    as safe as an audit — it *is* an audit."""
    session, device = _session(tmp_path, node_path="/md/Campus/wlc-1",
                               record_edit=lambda r: _stamp(r, **MATCHING))
    preflight(session, session.artifact)

    assert device.sent
    for command in device.sent:
        assert_safe(command)


# -- dry run --------------------------------------------------------------

def test_a_dry_run_contacts_nothing(tmp_path):
    session, device = _session(tmp_path, dry_run=True)
    report = preflight(session, session.artifact)

    assert device.sent == []
    assert report.skipped is True
    assert report.apply_ids == [READY]  # a rehearsal of the whole artifact
    assert any("the controller was not contacted" in w for w in report.warnings)
