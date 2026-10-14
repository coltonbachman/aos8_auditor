"""The gate between a reviewed file and a controller.

Phase 2's permission model is "these exact bytes, and a human read them", so the
tests that matter here are the ones that prove a *different* set of bytes cannot
get through: an edited file, a truncated file, a file whose record disagrees with
it, a file carrying a half-finished block.

Everything in this module is offline. Nothing here can reach a device.
"""

import json
from pathlib import Path

import pytest

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.impact import impact_for
from aos8_auditor.engine.models import Finding, Severity, Status
from aos8_auditor.remediate import ExportOptions, build_plan, context_from_config, write_artifacts
from aos8_auditor.remediate.approve import (
    ArtifactError,
    approval_document,
    load_artifact,
    parse_blocks,
    sha256_text,
    verify,
)
from aos8_auditor.remediate.fields import FieldType
from aos8_auditor.remediate.plan import ChangeState, RemediationPlan, build_change
from support import make_collection

CONFIG = Path(__file__).parent.parent / "fixtures" / "sample_running_config.txt"
CONTROLS = load_controls()
# Fails on the fixture, needs no answers, and is lockout-risky — the combination
# the apply path treats most carefully.
READY = "AOS8-MGMT-SSH-PUBKEY-001"
# Has a secret field, so it exercises the withheld-secret / FILL IN path.
VRRP = "AOS8-NET-VRRP-AUTH-001"
# The only control whose block is not a list of commands: 'banner motd' opens raw
# text entry, and the two lines under it are the banner, not configuration.
BANNER = "AOS8-GLOBAL-BANNER-001"

BANNER_TEXT = "Authorized use only."
_ANSWERS = {FieldType.SECRET: "correct-horse-battery-staple",
            FieldType.DELIMITER: "^",
            FieldType.TEXT: BANNER_TEXT}


def _plan(*control_ids, node_path="/"):
    rc = CONFIG.read_text()
    report = audit(make_collection(rc), CONTROLS, tool_version="test")
    ctx = context_from_config(rc, host="10.0.0.1")
    by_id = {c.id: c for c in CONTROLS}
    changes = [build_change(Finding(
        control_id=cid, title=by_id[cid].title, category=by_id[cid].category,
        status=Status.FAIL, severity=Severity.HIGH,
        remediation_hint=by_id[cid].remediation_hint, impact=impact_for(cid)))
        for cid in control_ids]
    plan = RemediationPlan(report=report, context=ctx, changes=changes,
                           node_path=node_path)
    for c in plan.changes:
        for f in c.fields:
            f.value = _ANSWERS.get(f.type, "7")
        c.state = ChangeState.ACCEPTED
        c.selected = True
    return plan


def _export(tmp_path, *control_ids, **kw):
    plan = _plan(*control_ids, **{k: v for k, v in kw.items() if k == "node_path"})
    opts = ExportOptions(operator="tester",
                         include_secrets=kw.get("include_secrets", True))
    write_artifacts(plan, tmp_path, opts)
    return tmp_path


def _rewrite(directory, transform):
    """Edit remediation.cfg the way a person with an editor would."""
    cfg = Path(directory) / "remediation.cfg"
    cfg.write_text(transform(cfg.read_text()), encoding="utf-8")


def _sub_line(old, new):
    """Replace a whole live line. Anchored, because these commands also appear
    inside the block's own explanatory comments and a loose replace would edit
    prose instead of the command under test."""
    def transform(text):
        return "\n".join(new if line == old else line
                         for line in text.splitlines()) + "\n"
    return transform


# -- parsing --------------------------------------------------------------

def test_only_live_lines_become_commands(tmp_path):
    """Comments outnumber commands roughly ten to one in these files."""
    art = load_artifact(_export(tmp_path, READY))
    block = art.blocks[0]
    assert block.control_id == READY
    assert block.lines == ["configure terminal", "ssh mgmt-auth public-key", "end"]


def test_a_skipped_block_contributes_no_commands(tmp_path):
    """Skipped blocks are written commented-out so the change ticket shows what
    was declined. Parsing one as live would apply a change the operator refused."""
    plan = _plan(READY, VRRP)
    plan.changes[1].state = ChangeState.SKIPPED
    plan.changes[1].selected = False
    plan.changes[1].skip_reason = "next window"
    write_artifacts(plan, tmp_path, ExportOptions(include_secrets=True))

    art = load_artifact(tmp_path)
    assert [b.control_id for b in art.blocks] == [READY]
    assert "SKIPPED by the operator" in art.cfg_text  # it is in the file, just not live


def test_a_manual_block_contributes_no_commands(tmp_path):
    """Manual findings are appended as prose. They have no command form at all."""
    rc = CONFIG.read_text()
    report = audit(make_collection(rc), CONTROLS, tool_version="test")
    plan = build_plan(report, context_from_config(rc, host="10.0.0.1"))
    for c in plan.actionable:
        c.state, c.selected = ChangeState.SKIPPED, False
    write_artifacts(plan, tmp_path, ExportOptions())

    art = load_artifact(tmp_path)
    assert art.blocks == []
    assert "MANUAL" in art.cfg_text


def test_the_node_path_is_read_back_off_the_block(tmp_path):
    art = load_artifact(_export(tmp_path, READY, node_path="/md/Campus/wlc-1"))
    assert art.blocks[0].node_path == "/md/Campus/wlc-1"
    assert art.blocks[0].lines[0] == "cd /md/Campus/wlc-1"


def test_a_header_with_no_live_lines_does_not_capture_the_next_block():
    """The parser must consume every header, not just interesting ones — an
    ignored header would attribute the following commands to the wrong control."""
    text = "\n".join([
        "! [1/2] AOS8-EMPTY-001 — nothing live here",
        "! configure terminal",
        "! end",
        "! [2/2] AOS8-REAL-001 — has commands",
        "configure terminal",
        "ssh mgmt-auth public-key",
        "end",
    ])
    blocks = parse_blocks(text)
    assert [b.control_id for b in blocks] == ["AOS8-REAL-001"]
    assert blocks[0].lines[1] == "ssh mgmt-auth public-key"


# -- the pin --------------------------------------------------------------

def test_an_untouched_export_verifies(tmp_path):
    report = verify(load_artifact(_export(tmp_path, READY)))
    assert report.ok, report.errors
    assert report.pinned_by == "record"


def test_an_edited_cfg_is_refused(tmp_path):
    """The entire security model in one test: bytes nobody reviewed do not go."""
    d = _export(tmp_path, READY)
    _rewrite(d, _sub_line("ssh mgmt-auth public-key",
                          "ssh mgmt-auth username/password"))
    report = verify(load_artifact(d))
    assert not report.ok
    assert any("does not match the export" in e for e in report.errors)


def test_even_a_whitespace_edit_is_refused(tmp_path):
    """No 'harmless edit' carve-out. A pin with exceptions is not a pin."""
    d = _export(tmp_path, READY)
    _rewrite(d, lambda t: t + "\n")
    assert not verify(load_artifact(d)).ok


def test_a_missing_pin_is_refused(tmp_path):
    d = _export(tmp_path, READY)
    record = json.loads((d / "remediation.json").read_text())
    record["artifacts"]["remediation.cfg"].pop("sha256")
    (d / "remediation.json").write_text(json.dumps(record))
    report = verify(load_artifact(d))
    assert any("records no sha256" in e for e in report.errors)


def test_a_record_from_a_future_schema_is_refused(tmp_path):
    """An older build must not guess at a newer record's meaning."""
    d = _export(tmp_path, READY)
    record = json.loads((d / "remediation.json").read_text())
    record["schema_version"] = "9.0"
    (d / "remediation.json").write_text(json.dumps(record))
    assert any("schema_version" in e for e in verify(load_artifact(d)).errors)


# -- re-approval ----------------------------------------------------------

def test_an_edit_can_be_re_approved(tmp_path):
    """The supported path for filling in a withheld secret by hand."""
    d = _export(tmp_path, READY)
    _rewrite(d, _sub_line("ssh mgmt-auth public-key",
                          "ssh mgmt-auth public-key username/password"))
    art = load_artifact(d)
    (d / "approval.json").write_text(json.dumps(
        approval_document(art, operator="tester", note="added password fallback")))

    report = verify(load_artifact(d))
    assert report.ok, report.errors
    assert report.pinned_by == "approval"
    assert any("edited after export and re-approved" in w for w in report.warnings)


def test_re_approval_does_not_rewrite_the_record(tmp_path):
    """A record that rewrites its own pin to match the current file is not a pin."""
    d = _export(tmp_path, READY)
    before = (d / "remediation.json").read_text()
    _rewrite(d, lambda t: t + "! edited\n")
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))
    assert (d / "remediation.json").read_text() == before


def test_an_approval_records_what_it_approved(tmp_path):
    """A hash alone is unreviewable after the fact — you cannot tell from it what
    the person actually said yes to."""
    d = _export(tmp_path, READY)
    doc = approval_document(load_artifact(d), operator="tester")
    assert doc["blocks"][0]["control_id"] == READY
    assert "ssh mgmt-auth public-key" in doc["blocks"][0]["commands"]


def test_a_stale_approval_does_not_carry_over_to_a_new_export(tmp_path):
    """Approving one edit must not silently bless the next one."""
    d = _export(tmp_path, READY)
    _rewrite(d, lambda t: t + "! first edit\n")
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))
    _rewrite(d, lambda t: t + "! second edit, never approved\n")

    report = verify(load_artifact(d))
    assert not report.ok
    assert any("does not match the export" in e for e in report.errors)


def test_an_approval_from_a_different_export_is_refused(tmp_path):
    """Copying an approval.json next to someone else's artifacts must not work."""
    d = _export(tmp_path, READY)
    _rewrite(d, lambda t: t + "! edited\n")
    doc = approval_document(load_artifact(d), operator="tester")
    doc["supersedes_sha256"] = "0" * 64  # approved against some other export
    (d / "approval.json").write_text(json.dumps(doc))

    report = verify(load_artifact(d))
    assert not report.ok
    assert any("written against a different export" in e for e in report.errors)


# -- coherence between the two files --------------------------------------

def _delete_block(text, control_id):
    """Remove a whole block's live lines, the way someone striking a change would."""
    out, inside = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("!") and control_id in stripped and "[" in stripped:
            inside = True
        elif inside and stripped == "end":
            inside = False
            continue
        if not (inside and stripped and not stripped.startswith("!")):
            out.append(line)
    return "\n".join(out) + "\n"


def test_a_block_deleted_during_an_edit_is_caught(tmp_path):
    """The pin alone would accept this once re-approved; the record would not."""
    d = _export(tmp_path, READY, VRRP)
    _rewrite(d, lambda t: _delete_block(t, READY))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))

    report = verify(load_artifact(d))
    assert not report.ok
    assert any("disagree about what this change set contains" in e
               for e in report.errors)


# -- the shape of a block -------------------------------------------------

def test_a_block_emptied_of_its_commands_is_refused(tmp_path):
    """Deleting the command but leaving the frame is the likelier slip, and the
    quieter one: it applies clean and changes nothing."""
    d = _export(tmp_path, READY)
    _rewrite(d, _sub_line("ssh mgmt-auth public-key", "! removed"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))

    report = verify(load_artifact(d))
    assert not report.ok
    assert any("no commands left in it" in e for e in report.errors)


def test_a_block_that_lost_its_closing_end_is_refused(tmp_path):
    """The session would still be in configuration mode when the next block's
    'cd' arrives, where 'cd' is not a navigation command."""
    d = _export(tmp_path, READY)
    _rewrite(d, _sub_line("end", "! end removed"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))

    report = verify(load_artifact(d))
    assert not report.ok
    assert any("self-contained" in e for e in report.errors)


def test_a_block_redirected_to_another_node_is_refused(tmp_path):
    """The multi-node hazard arriving by hand-edit rather than by values file."""
    d = _export(tmp_path, READY, node_path="/md/Campus/wlc-1")
    _rewrite(d, _sub_line("ssh mgmt-auth public-key",
                          "cd /md/Campus/wlc-2\nssh mgmt-auth public-key"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))

    report = verify(load_artifact(d))
    assert not report.ok
    assert any("changes context part-way through" in e for e in report.errors)


# -- half-changes ---------------------------------------------------------

def test_a_withheld_secret_makes_the_block_unappliable(tmp_path):
    """The one that would actually hurt someone.

    With the secret withheld, 'authentication <secret>' is written commented out
    while the lines around it stay live. Applying the block would enable VRRP with
    no authentication at all — strictly worse than the finding being open.
    """
    d = _export(tmp_path, VRRP, include_secrets=False)
    art = load_artifact(d)
    assert art.blocks[0].incomplete

    report = verify(art)
    assert not report.ok
    assert any("would apply as a partial change" in e for e in report.errors)


def test_the_same_block_is_fine_once_the_secret_is_there(tmp_path):
    d = _export(tmp_path, VRRP, include_secrets=True)
    art = load_artifact(d)
    assert not art.blocks[0].incomplete
    assert verify(art).ok


def test_an_unanswered_placeholder_makes_the_block_unappliable(tmp_path):
    """Same failure, different cause: a field nobody filled in."""
    plan = _plan(VRRP)
    for f in plan.changes[0].fields:
        if not f.is_secret:
            f.value = ""  # what the wizard leaves for a field nobody touched
    write_artifacts(plan, tmp_path, ExportOptions(include_secrets=True))

    report = verify(load_artifact(tmp_path))
    assert not report.ok
    assert any("partial change" in e for e in report.errors)


# -- destructive commands -------------------------------------------------

def test_a_destructive_line_added_by_hand_is_refused(tmp_path):
    """emit refuses these at build time. This is the same check on the bytes about
    to be sent, because an approval is a human saying 'send these', not a human who
    read every line looking for a reload."""
    d = _export(tmp_path, READY)
    _rewrite(d, _sub_line("ssh mgmt-auth public-key",
                          "ssh mgmt-auth public-key\nreload"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))

    report = verify(load_artifact(d))
    assert not report.ok
    assert any("destructive command" in e for e in report.errors)


def test_a_destructive_line_in_the_rollback_is_refused(tmp_path):
    """The rollback runs unattended when a block fails, so it is the *more*
    dangerous of the two files to leave unchecked."""
    d = _export(tmp_path, READY)
    rb = d / "rollback.cfg"
    rb.write_text(rb.read_text().replace("no ssh mgmt-auth public-key",
                                         "write erase all"))
    report = verify(load_artifact(d))
    assert not report.ok
    assert any("destructive command" in e for e in report.errors)


def test_a_command_that_asks_a_question_is_refused(tmp_path):
    """Worse than a command that fails: the block's next line is read as the
    answer, so the run continues having silently skipped a command and told a
    controller 'yes' to a question nobody saw."""
    d = _export(tmp_path, READY)
    _rewrite(d, _sub_line("ssh mgmt-auth public-key",
                          "controller-ip vlan 200\nssh mgmt-auth public-key"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))

    report = verify(load_artifact(d))
    assert not report.ok
    assert any("asks for confirmation" in e for e in report.errors)


# -- raw text entry --------------------------------------------------------

def test_banner_text_is_not_tidied_the_way_config_is():
    """Indentation, blank lines and a leading '!' are all meaningful inside a
    banner. Stripping them is not cosmetic — it silently rewrites the text the
    controller shows at every login."""
    text = "\n".join([
        "! [1/1] AOS8-GLOBAL-BANNER-001 — Login banner",
        "configure terminal",
        "banner motd ^",
        "    Authorized use only.",
        "",
        "! -- not a comment: this line is part of the banner",
        "^",
        "end",
    ])
    block = parse_blocks(text)[0]
    assert block.lines == [
        "configure terminal", "banner motd ^", "    Authorized use only.", "",
        "! -- not a comment: this line is part of the banner", "^", "end"]
    assert block.text_indexes == {2, 3, 4, 5}


def test_a_banner_that_never_closes_is_refused(tmp_path):
    """Without the closing delimiter the banner swallows the 'end' below it and
    every block after that, so nothing downstream can recover."""
    d = _export(tmp_path, BANNER)
    _rewrite(d, _sub_line("^", "! the delimiter, deleted"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))

    report = verify(load_artifact(d))
    assert not report.ok
    assert any("never closed" in e for e in report.errors)


def test_an_end_inside_a_banner_is_a_word_not_a_mode_change(tmp_path):
    d = _export(tmp_path, BANNER)
    _rewrite(d, _sub_line(BANNER_TEXT, f"{BANNER_TEXT}\nend"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))

    report = verify(load_artifact(d))
    assert report.ok, report.errors


def test_a_reload_in_the_banner_text_is_a_sentence_not_a_command(tmp_path):
    """The destructive check has to skip banner text or a perfectly ordinary
    message becomes unexportable."""
    d = _export(tmp_path, BANNER)
    _rewrite(d, _sub_line(BANNER_TEXT, "reload requests go to the service desk"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))

    report = verify(load_artifact(d))
    assert report.ok, report.errors


# -- rollback availability ------------------------------------------------

def test_a_missing_rollback_is_a_warning_not_a_refusal(tmp_path):
    d = _export(tmp_path, READY)
    (d / "rollback.cfg").unlink()
    report = verify(load_artifact(d))
    assert report.ok
    assert any("cannot be reversed automatically" in w for w in report.warnings)


def test_an_edited_rollback_warns_that_the_safety_net_is_not_the_generated_one(tmp_path):
    d = _export(tmp_path, READY)
    rb = d / "rollback.cfg"
    rb.write_text(rb.read_text() + "! edited\n")
    report = verify(load_artifact(d))
    assert report.ok  # the undo file being edited must not block the change
    assert any("edited since export" in w for w in report.warnings)


# -- re-applying ----------------------------------------------------------

def test_a_fully_applied_artifact_is_refused(tmp_path):
    """It was planned against a configuration the controller no longer has."""
    d = _export(tmp_path, READY)
    (d / "apply_result.json").write_text(json.dumps(
        {"outcome": "applied", "finished_at": "2026-08-20T10:00:00+00:00"}))
    report = verify(load_artifact(d))
    assert not report.ok
    assert any("already applied in full" in e for e in report.errors)


def test_an_apply_that_stopped_early_can_be_resumed(tmp_path):
    """Refusing here would strand a half-applied controller, which is the state
    that most needs the tool to finish the job."""
    d = _export(tmp_path, READY)
    (d / "apply_result.json").write_text(json.dumps(
        {"outcome": "stopped", "finished_at": "2026-08-20T10:00:00+00:00"}))
    report = verify(load_artifact(d))
    assert report.ok
    assert any("stopped early" in w for w in report.warnings)


# -- loading --------------------------------------------------------------

def test_a_missing_directory_is_an_error_not_a_traceback(tmp_path):
    with pytest.raises(ArtifactError, match="not a directory"):
        load_artifact(tmp_path / "nope")


def test_a_directory_without_a_record_is_an_error(tmp_path):
    (tmp_path / "remediation.cfg").write_text("configure terminal\nend\n")
    with pytest.raises(ArtifactError, match="remediation record"):
        load_artifact(tmp_path)


def test_a_corrupt_record_is_an_error(tmp_path):
    d = _export(tmp_path, READY)
    (d / "remediation.json").write_text("{not json")
    with pytest.raises(ArtifactError, match="not readable JSON"):
        load_artifact(d)


def test_the_hash_is_taken_over_the_bytes_on_disk(tmp_path):
    """Guards against the pin being computed from something other than the file —
    an in-memory copy, a re-render — which would make it check nothing."""
    d = _export(tmp_path, READY)
    record = json.loads((d / "remediation.json").read_text())
    on_disk = (d / "remediation.cfg").read_text(encoding="utf-8")
    assert record["artifacts"]["remediation.cfg"]["sha256"] == sha256_text(on_disk)
