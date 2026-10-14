"""Applying an artifact: what lands, what stops it, and what gets written down.

The lower layers already refuse the wrong bytes (test_apply_session.py) and the
wrong controller (test_remediate_preflight.py). What is pinned here is the part
that only exists at this level — the *sequencing*. A run that stops at the right
moment leaves a controller someone can still log into; a run that stops one
block late does not.

No network. The controller is faked at the netmiko boundary and remembers what
was configured, so a re-check after a change reads a config that actually
changed — which is the only way a test of "did the fix take" means anything.
"""

import json
import os

from aos8_auditor.engine.models import Status
from aos8_auditor.remediate.apply import (
    APPLIED,
    ATTEMPT_NAME,
    DRY_RUN,
    NOTHING_TO_DO,
    PENDING_COMMAND,
    REFUSED,
    STAGED,
    STOPPED,
    ApplyOptions,
    apply_artifact,
    next_steps,
    transcript,
    write_result,
)
from aos8_auditor.remediate.approve import RESULT_NAME, load_artifact, verify
from aos8_auditor.transport.apply_session import HEARTBEAT_COMMAND, ApplySession
from aos8_auditor.transport.connection import SSHConfig
from test_remediate_approve import READY, VRRP, _export
from test_remediate_preflight import MATCHING, RUNNING_CONFIG, SHOW_VERSION, _stamp

CONFIG = SSHConfig(host="10.0.0.1", username="admin", password="x")
SECRET = "correct-horse-battery-staple"

# A second finding on the same fixture that cannot lock anybody out. Paired with
# READY it gives a two-block artifact where emit's ordering is visible: the
# lockout-risky block goes last, so the fallback path survives as long as it can.
SAFE = "AOS8-GLOBAL-TIMEOUT-002"

_FRAME = {"configure terminal", "end"}


NO_PENDING_BUFFER = "% Invalid input detected at '^' marker."


class FakeController:
    """Remembers configuration. Replies to reads out of what it remembers.

    Crude, but the one behaviour that matters is real: a command that lands
    changes what 'show running-config' says afterwards. Without that, every
    post-change verification in this file would be checking a constant.

    ``stages`` models the other kind of AOS 8 box — the ones carrying the
    Mobility-Master configuration hierarchy, which do not apply what you type in
    config mode at all. It goes into a pending buffer and takes effect on 'write
    memory'. A controller without that buffer does not merely report an empty
    one; it does not recognise the command.
    """

    def __init__(self, running_config=RUNNING_CONFIG, fail_on=None, dies_on=None,
                 reconnects=False, stages=False, pending=""):
        self.sent = []
        self.config = running_config
        self.fail_on = fail_on or {}     # command -> error text the CLI returns
        self.dies_on = dies_on           # after this command, stop answering
        self.reconnects = reconnects     # ...but a fresh session would work
        self.dead = False
        self.stages = stages
        self.pending = pending

    def send_command(self, command, read_timeout=None, **kw):
        self.sent.append(command)
        if self.dead:
            raise OSError("socket closed")
        if command in self.fail_on:
            return self.fail_on[command]
        if command == self.dies_on:
            self.dead = True
            return ""
        if command == "show running-config":
            return self.config
        if command == "show version":
            return SHOW_VERSION
        if command == HEARTBEAT_COMMAND:
            return "Tue Aug 20 09:00:00 PDT 2026"
        if command == PENDING_COMMAND:
            return self.pending if self.stages else NO_PENDING_BUFFER
        if command.startswith("show ") or command.startswith("cd ") or command in _FRAME:
            return ""
        if self.stages:  # accepted, and not in effect
            self.pending += ("\n" if self.pending else "") + command
            return ""
        self.config += "\n" + command + "\n"  # a configuration line landing
        return ""

    def disconnect(self):
        pass

    @property
    def configured(self):
        """Only the lines this run put there."""
        return [c for c in self.sent
                if not c.startswith(("show ", "cd ")) and c not in _FRAME]


def _artifact(tmp_path, *control_ids, target=None, **kw):
    d = _export(tmp_path, *(control_ids or (READY,)), **kw)
    record = json.loads((d / "remediation.json").read_text())
    _stamp(record, **{**MATCHING, **(target or {})})
    (d / "remediation.json").write_text(json.dumps(record))
    return load_artifact(d)


def _session(artifact, device, *, dry_run=False):
    session = ApplySession(CONFIG, artifact, dry_run=dry_run)
    if dry_run:
        return session

    def reopen():
        """Stand in for the SSH server. A device that reconnects hands back a
        working session; one that does not is a controller that has stopped
        listening, which is what a real lockout looks like from here."""
        if not device.reconnects:
            raise OSError("connection refused")
        device.dead = False
        session._connection._conn = device

    session._connection._conn = device
    session._connection.open = reopen
    return session


def _run(tmp_path, *control_ids, device=None, dry_run=False, options=None,
         target=None, **kw):
    artifact = _artifact(tmp_path, *control_ids, target=target, **kw)
    device = device or FakeController()
    session = _session(artifact, device, dry_run=dry_run)
    return apply_artifact(session, artifact, options=options), device, artifact


# -- the happy path -------------------------------------------------------

def test_a_change_is_sent_and_then_confirmed_against_the_controller(tmp_path):
    """Accepted is not the same as fixed — the CLI says nothing to a command it
    merely parsed. The run re-reads and asks the control itself."""
    result, device, _ = _run(tmp_path)

    assert result.outcome == APPLIED
    assert result.applied_ids == [READY]
    assert device.configured == ["ssh mgmt-auth public-key"]
    assert result.blocks[0].confirmed is Status.PASS


def test_a_command_that_parsed_but_did_not_fix_anything_is_not_reported_as_fixed(tmp_path):
    """The failure this catches is the quiet one: every line accepted, control
    still failing, and a report that says the change was applied."""
    class Amnesiac(FakeController):
        def send_command(self, command, read_timeout=None, **kw):
            reply = super().send_command(command, read_timeout)
            self.config = RUNNING_CONFIG  # forgets, the way a no-op command would
            return reply

    result, _, _ = _run(tmp_path, device=Amnesiac())
    assert result.blocks[0].result.ok        # the controller accepted it
    assert result.blocks[0].confirmed is Status.FAIL
    assert any("still reports fail" in n for n in result.blocks[0].notes)


def test_nothing_is_saved_to_flash_ever(tmp_path):
    """The escape hatch from a lockout is that the change is one reboot from
    gone. Saving on the operator's behalf would take that away."""
    result, device, artifact = _run(tmp_path)

    assert not any("write" in c for c in device.sent)
    from aos8_auditor.remediate.apply import result_document
    assert result_document(artifact, result)["saved_to_flash"] is False


# -- controllers that stage configuration ---------------------------------
#
# Found on a real controller: every command accepted, exit 0, transcript clean,
# and the control still failing afterwards — because the box had put the whole
# change in a pending buffer and would not act on it until 'write memory'. On
# that platform "we never save anything" stops meaning "your change is one reboot
# from gone" and starts meaning "your change never happened", and a report that
# says 'applied' is true about the commands and false about the controller.

class ImmediateWithBuffer(FakeController):
    """Answers the pending query, and still applies what you type.

    Its buffer holds somebody else's uncommitted work and holds it unchanged
    across the run. "This platform has a pending buffer" and "what we just sent
    is in it" are different claims, and only the second one means the operator's
    change has not happened.
    """

    def send_command(self, command, read_timeout=None, **kw):
        if command == PENDING_COMMAND:
            self.sent.append(command)
            return self.pending
        return super().send_command(command, read_timeout)


def test_a_staged_change_is_not_reported_as_applied(tmp_path):
    result, _, _ = _run(tmp_path, device=FakeController(stages=True))

    assert result.stages_config is True
    assert result.staged_not_applied is True
    assert result.outcome != APPLIED
    assert result.outcome == STAGED


def test_the_staged_run_says_what_is_needed_to_make_it_happen(tmp_path):
    result, _, _ = _run(tmp_path, device=FakeController(stages=True))

    assert any("none of them is in effect" in w for w in result.warnings)
    assert next_steps(result)[0].startswith("NOT IN EFFECT YET")
    assert any("write memory" in s for s in next_steps(result))


def test_a_staged_change_explains_the_control_that_still_fails(tmp_path):
    """Staged and broken read identically — accepted commands, failing control.
    Telling the operator to go and debug a command that was fine wastes their
    afternoon."""
    result, _, _ = _run(tmp_path, device=FakeController(stages=True))

    assert result.blocks[0].result.ok
    assert result.blocks[0].confirmed is Status.FAIL
    assert any("staged change" in n for n in result.blocks[0].notes)


def test_pending_configuration_that_was_not_ours_is_reported_before_we_add_to_it(tmp_path):
    """A 'write memory' commits somebody else's uncommitted work too, so the
    operator has to hear about it while it is still separable from ours."""
    device = FakeController(stages=True, pending="ip access-list session someone-else")
    result, device, _ = _run(tmp_path, device=device)

    assert any("had uncommitted configuration pending before this run"
               in w for w in result.warnings)
    assert device.sent.index(PENDING_COMMAND) < device.sent.index("configure terminal")


def test_write_memory_is_still_not_sent_on_a_controller_that_needs_it(tmp_path):
    """The tool's answer to "your change needs a commit" is to say so, not to
    commit it. On this platform the uncommitted state is the way back."""
    _, device, _ = _run(tmp_path, device=FakeController(stages=True))

    assert not any("write" in c for c in device.sent)


def test_a_staged_run_can_be_run_again(tmp_path):
    """The interlock exists to stop a change set being pushed at a controller it
    was not planned against. A staged run did not change the controller."""
    result, _, artifact = _run(tmp_path, device=FakeController(stages=True))
    write_result(artifact, result)

    report = verify(load_artifact(artifact.directory))
    assert not any("already applied in full" in e for e in report.errors)


def test_the_transcript_leads_with_the_part_that_did_not_happen(tmp_path):
    result, _, artifact = _run(tmp_path, device=FakeController(stages=True))
    text = transcript(artifact, result)

    assert "STAGES CONFIGURATION" in text
    assert text.index("STAGES CONFIGURATION") < text.index(READY)


def test_the_result_records_both_facts_separately(tmp_path):
    """Whether the platform has a buffer, and whether this run's change is in
    it, are answered separately because they are separately wrong."""
    from aos8_auditor.remediate.apply import result_document
    result, _, artifact = _run(tmp_path, device=FakeController(stages=True))
    doc = result_document(artifact, result)

    assert doc["stages_config"] is True
    assert doc["staged_not_applied"] is True


def test_an_ordinary_controller_is_never_described_as_staging(tmp_path):
    """It does not have the buffer at all, which is not the same as having an
    empty one — it answers the question with a parse error."""
    result, _, artifact = _run(tmp_path)

    assert result.stages_config is False
    assert result.staged_not_applied is False
    assert result.outcome == APPLIED
    assert not any("write memory" in w for w in result.warnings)
    assert "STAGES CONFIGURATION" not in transcript(artifact, result)


def test_a_buffer_the_change_did_not_go_into_is_not_a_staged_change(tmp_path):
    """The claim is about this run's commands, not about the platform. Telling
    an operator their working change did nothing is its own kind of wrong."""
    device = ImmediateWithBuffer(pending="ip access-list session someone-else")
    result, _, _ = _run(tmp_path, device=device)

    assert result.stages_config is True       # the buffer exists
    assert result.staged_not_applied is False  # our change is not in it
    assert result.blocks[0].confirmed is Status.PASS
    assert result.outcome == APPLIED


def test_a_dry_run_makes_no_claim_about_staging(tmp_path):
    """It never opened the socket, so it never asked."""
    result, _, _ = _run(tmp_path, dry_run=True)

    assert result.stages_config is False
    assert result.staged_not_applied is False


# -- ...and when a staged run does not finish -----------------------------
#
# The two claims that carry the clean staged run — everything was accepted, so
# commit it when you are ready — are both false once a block has failed, and the
# operator who acts on them commits a half-applied plan. Reported from a real
# run: the second block was rejected, its reversal was rejected too, and the
# transcript still ended with "Commit it when you are ready: 'write memory'".

INVALID = "% Invalid input detected at '^' marker."


def _stopped_staged(tmp_path):
    """One block into the buffer, the next one rejected. Nothing in effect."""
    device = FakeController(stages=True, fail_on={"ssh mgmt-auth public-key": INVALID})
    return _run(tmp_path, READY, SAFE, device=device)


def test_a_stopped_staged_run_does_not_say_the_commands_were_accepted(tmp_path):
    result, _, _ = _stopped_staged(tmp_path)

    assert result.outcome == STOPPED
    assert result.staged_not_applied is True
    staged = [w for w in result.warnings if "stages configuration" in w]
    assert staged and not any("were accepted" in w for w in staged)
    assert any("did not finish" in w for w in staged)


def test_a_stopped_staged_run_is_not_told_to_commit_it_when_ready(tmp_path):
    """The buffer holds part of a plan. Reading it comes before committing it."""
    result, _, _ = _stopped_staged(tmp_path)
    steps = next_steps(result)

    assert steps[0].startswith("NOT IN EFFECT, AND NOT FINISHED")
    assert not any("Commit it when you are ready" in s for s in steps)
    assert any("Do NOT 'write memory'" in s for s in steps)
    assert any(PENDING_COMMAND in s for s in steps)


def test_a_stopped_staged_run_does_not_promise_a_re_run_will_skip_what_landed(tmp_path):
    """Nothing landed, so there is nothing for the next run to detect and skip."""
    result, _, _ = _stopped_staged(tmp_path)
    steps = next_steps(result)

    assert not any("are detected and skipped" in s for s in steps)
    assert any("nothing landed" in s for s in steps)


def test_the_transcript_of_a_stopped_staged_run_says_it_did_not_finish(tmp_path):
    result, _, artifact = _stopped_staged(tmp_path)
    text = transcript(artifact, result)

    assert "DID NOT FINISH" in text
    assert "Everything below was accepted" not in text


def test_a_failed_reversal_on_a_staging_controller_is_not_a_live_mess(tmp_path):
    """Both the half-applied block and the failed reversal are in the buffer, so
    the controller is running exactly what it was running before. Sending someone
    to firefight it would be sending them to firefight nothing."""
    device = FakeController(stages=True, fail_on={
        "ssh mgmt-auth public-key": INVALID, "no ssh mgmt-auth public-key": INVALID})
    result, _, _ = _run(tmp_path, device=device)

    assert result.blocks[0].result.partial and result.blocks[0].rolled_back is False
    reversal = [w for w in result.warnings if "reversal of" in w]
    assert reversal and not any("neither the plan nor the rollback" in w
                                for w in reversal)
    assert any("Neither the change nor its reversal is in effect" in w
               for w in reversal)


def test_a_failed_reversal_on_an_ordinary_controller_still_is_one(tmp_path):
    device = FakeController(fail_on={
        "ssh mgmt-auth public-key": INVALID, "no ssh mgmt-auth public-key": INVALID})
    result, _, _ = _run(tmp_path, device=device)

    assert any("neither the plan nor the rollback" in w for w in result.warnings)


# -- stopping ------------------------------------------------------------

def test_a_rejected_command_stops_the_run_before_the_next_block(tmp_path):
    """Pushing more configuration on top of a rejected line is how a plan that
    was reviewed as a sequence gets applied as something else."""
    device = FakeController(fail_on={
        "session-timeout 360": "% Invalid input detected at '^' marker."})
    result, device, artifact = _run(tmp_path, READY, SAFE, device=device)

    assert [b.control_id for b in artifact.blocks] == [SAFE, READY]
    assert result.outcome == STOPPED
    assert [b.control_id for b in result.blocks] == [SAFE]
    assert "ssh mgmt-auth public-key" not in device.sent


def test_the_half_applied_block_is_reversed(tmp_path):
    """'configure terminal' landed and the command after it did not. Leaving
    that is how a controller ends up in a state no file describes."""
    device = FakeController(fail_on={
        "ssh mgmt-auth public-key": "% Invalid input detected at '^' marker."})
    result, _, _ = _run(tmp_path, device=device)

    assert result.blocks[0].result.partial
    assert result.blocks[0].rolled_back is True


def test_a_block_that_failed_on_its_first_line_is_not_reversed(tmp_path):
    """Nothing landed, so a reversal would be a change made for no reason."""
    device = FakeController(fail_on={"configure terminal": "% Access denied"})
    result, _, _ = _run(tmp_path, device=device)

    assert result.blocks[0].result.partial is False
    assert result.blocks[0].rolled_back is False
    assert result.blocks[0].rollback_result is None


def test_rollback_can_be_turned_off_and_says_so(tmp_path):
    device = FakeController(fail_on={
        "ssh mgmt-auth public-key": "% Invalid input detected at '^' marker."})
    result, _, _ = _run(tmp_path, device=device,
                        options=ApplyOptions(rollback_on_error=False))

    assert result.blocks[0].rolled_back is False
    assert any("half-applied" in w and "rollback.cfg" in w for w in result.warnings)


# -- the heartbeat and the lockout ---------------------------------------

def test_the_heartbeat_runs_immediately_after_every_block(tmp_path):
    """Not only after the ones flagged lockout_risk. The flag decides how loudly
    the operator is warned; it must not decide whether the net exists, or the net
    is only as good as the curation of a YAML file."""
    result, device, _ = _run(tmp_path, READY, SAFE)

    assert result.outcome == APPLIED
    ends = [i for i, c in enumerate(device.sent) if c == "end"]
    assert len(ends) == 2
    assert all(device.sent[i + 1] == HEARTBEAT_COMMAND for i in ends)


def test_a_controller_that_stops_answering_stops_the_run(tmp_path):
    """The heartbeat is what notices. The block itself reported success — a
    change that cuts off management takes effect after the command is accepted,
    not instead of accepting it."""
    device = FakeController(dies_on="end")
    result, _, _ = _run(tmp_path, READY, SAFE, device=device)

    assert result.lockout_suspected is True
    assert len(result.blocks) == 1
    assert result.blocks[0].result.ok  # it landed; we just cannot reach it now
    assert any("did not come back" in e for e in result.errors)


def test_the_lockout_message_says_how_to_get_back_in(tmp_path):
    """This is the text someone reads at 2am with one console cable."""
    result, _, artifact = _run(tmp_path, device=FakeController(dies_on="end"))

    text = transcript(artifact, result)
    assert "power cycle" in text
    assert "Do NOT run 'write memory'" in text
    assert "console" in text


def test_a_session_that_drops_and_comes_back_is_not_a_lockout(tmp_path):
    """An SSH session dying and a controller locking you out look identical from
    here. One attempt to reconnect is what tells them apart."""
    device = FakeController(dies_on="end", reconnects=True)
    result, _, _ = _run(tmp_path, READY, SAFE, device=device)

    assert result.lockout_suspected is False
    assert any("re-established" in w for w in result.warnings)
    assert len(result.blocks) == 2  # it carried on


# -- confirmation --------------------------------------------------------

def test_a_lockout_risky_change_is_confirmed_first(tmp_path):
    asked = []
    result, device, _ = _run(tmp_path, options=ApplyOptions(
        confirm=lambda block, detail: asked.append(block.control_id) or True))

    assert asked == [READY]
    assert result.outcome == APPLIED


def test_declining_stops_the_run_and_keeps_what_already_landed(tmp_path):
    """Not 'skip this one and carry on': the plan was reviewed as a sequence, and
    the operator declining the risky part of it is a reason to stop and look."""
    result, device, _ = _run(tmp_path, READY, SAFE, options=ApplyOptions(
        confirm=lambda block, detail: False))

    assert result.outcome == STOPPED
    assert result.applied_ids == [SAFE]     # what ran before the prompt stands
    assert any("declined" in why for _, why in result.skipped)
    assert "ssh mgmt-auth public-key" not in device.sent


def test_a_change_that_cannot_lock_you_out_is_not_prompted_for(tmp_path):
    """Prompting for everything is how a prompt stops being read."""
    asked = []
    result, _, _ = _run(tmp_path, READY, SAFE, options=ApplyOptions(
        confirm=lambda block, detail: asked.append(block.control_id) or True))

    assert result.applied_ids == [SAFE, READY]
    assert asked == [READY]


# -- preflight decides what is even attempted ----------------------------

def test_a_run_against_the_wrong_controller_sends_nothing(tmp_path):
    result, device, _ = _run(tmp_path, target={"serial": "CX0001111"})

    assert result.outcome == REFUSED
    assert device.configured == []
    assert result.errors


def test_a_change_the_controller_no_longer_needs_is_skipped(tmp_path):
    """The resume case. Re-running after a stop must not re-send what landed."""
    fixed = RUNNING_CONFIG + "\nssh mgmt-auth public-key\n"
    result, device, _ = _run(tmp_path, device=FakeController(running_config=fixed))

    assert result.outcome == NOTHING_TO_DO
    assert device.configured == []
    assert result.skipped and result.skipped[0][0] == READY


# -- the dry run ---------------------------------------------------------

def test_a_dry_run_reaches_nothing_and_rehearses_everything(tmp_path):
    result, device, _ = _run(tmp_path, READY, SAFE, dry_run=True)

    assert result.outcome == DRY_RUN
    assert device.sent == []
    assert len(result.blocks) == 2
    assert all(not ln.sent for b in result.blocks for ln in b.result.lines)


def test_a_dry_run_does_not_write_the_file_that_blocks_a_real_run(tmp_path):
    """apply_result.json is an interlock, not a log. A rehearsal has nothing to
    interlock against, and dropping one there would make 'we thought about this'
    look like 'some of this is on the controller now'."""
    result, _, artifact = _run(tmp_path, dry_run=True)
    write_result(artifact, result)

    assert not (artifact.directory / RESULT_NAME).exists()
    assert (artifact.directory / ATTEMPT_NAME).exists()
    assert verify(load_artifact(artifact.directory)).ok


# -- what is written down ------------------------------------------------

def test_a_completed_apply_blocks_a_second_one(tmp_path):
    """The change set was planned against a configuration the controller no
    longer has."""
    result, _, artifact = _run(tmp_path)
    write_result(artifact, result, operator="tester")

    report = verify(load_artifact(artifact.directory))
    assert not report.ok
    assert any("already applied in full" in e for e in report.errors)


def test_a_run_that_stopped_early_can_be_resumed(tmp_path):
    """Refusing here would leave the operator hand-finishing a plan the tool
    generated, which is worse than either extreme."""
    device = FakeController(fail_on={
        "ssh mgmt-auth public-key": "% Invalid input detected at '^' marker."})
    result, _, artifact = _run(tmp_path, READY, SAFE, device=device)
    write_result(artifact, result)

    report = verify(load_artifact(artifact.directory))
    assert report.ok, report.errors
    assert any("stopped early" in w for w in report.warnings)


def test_the_result_is_not_world_readable(tmp_path):
    result, _, artifact = _run(tmp_path)
    for path in write_result(artifact, result):
        assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_the_secret_is_not_in_anything_written_down(tmp_path):
    """It has to reach the controller and nowhere else.

    Built by hand rather than through apply_artifact, because the control that
    carries a secret on this fixture is one preflight correctly declines to
    apply. What is under test here is the pair of functions that turn results
    into files, and they get a real BlockResult carrying a real secret.
    """
    from aos8_auditor.remediate.apply import AppliedBlock, ApplyResult

    artifact = _artifact(tmp_path, VRRP)
    device = FakeController()
    session = _session(artifact, device)
    sent = session.send_block(artifact.blocks[0])
    assert any(SECRET in c for c in device.configured)  # it reached the device

    result = ApplyResult(outcome=APPLIED, started_at="now", finished_at="now",
                         blocks=[AppliedBlock(control_id=VRRP, result=sent)])
    for path in write_result(artifact, result, operator="tester"):
        assert SECRET not in path.read_text()
    assert "authentication" in transcript(artifact, result)


def test_the_transcript_reads_as_a_change_record(tmp_path):
    result, _, artifact = _run(tmp_path)
    text = transcript(artifact, result)

    assert "ssh mgmt-auth public-key" in text
    assert "saved       : no" in text
    assert "NEXT: " in text
    assert "write memory" in text  # the step the operator still owns


def test_the_transcript_of_a_dry_run_says_so_at_the_top(tmp_path):
    """Filed in a change ticket, a rehearsal and a real run must not look alike."""
    result, _, artifact = _run(tmp_path, dry_run=True)
    text = transcript(artifact, result)

    assert "THIS WAS A DRY RUN" in text.splitlines()[9]


def test_the_result_records_why_each_change_was_skipped(tmp_path):
    from aos8_auditor.remediate.apply import result_document

    fixed = RUNNING_CONFIG + "\nssh mgmt-auth public-key\n"
    result, _, artifact = _run(tmp_path, device=FakeController(running_config=fixed))
    doc = result_document(artifact, result)

    assert doc["skipped"][0]["control_id"] == READY
    assert doc["skipped"][0]["reason"]
    assert doc["counts"]["applied"] == 0


def test_the_result_is_json_serialisable(tmp_path):
    """It is written to a file. An enum or a datetime in there is a crash at the
    end of a run that already changed the controller."""
    from aos8_auditor.remediate.apply import result_document

    result, _, artifact = _run(tmp_path, READY, SAFE)
    json.dumps(result_document(artifact, result, operator="tester"))


# -- the property that matters -------------------------------------------

def test_only_verified_block_lines_are_ever_configured(tmp_path):
    """Everything sent is either a read-only command or a line out of the
    reviewed file. There is no third category."""
    from aos8_auditor.collection.command_catalog import assert_safe

    result, device, artifact = _run(tmp_path, READY, SAFE)
    reviewed = {line for block in artifact.blocks + artifact.rollback_blocks
                for line in block.lines}

    for command in device.sent:
        if command in reviewed:
            continue
        assert_safe(command)
