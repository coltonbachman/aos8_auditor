"""The only class that can write, and the reasons it refuses to.

Read this alongside tests/test_transport_session.py: that file pins "the auditor
cannot write", this one pins "the applier can write exactly one artifact's
verified blocks and nothing else".

No network. The connection is faked at the netmiko boundary, so a test that
regressed the gate would show up as a command in ``fake.sent`` rather than as a
change on a controller.
"""

import json
from pathlib import Path

import pytest

from aos8_auditor.model.evidence import ExitKind
from aos8_auditor.remediate.approve import (
    CfgBlock,
    approval_document,
    load_artifact,
)
from aos8_auditor.transport.apply_session import (
    HEARTBEAT_COMMAND,
    ApplyRefused,
    ApplySession,
    transcript_lines,
)
from aos8_auditor.transport.connection import SSHConfig, TransportError, prompt_pattern
from test_remediate_approve import (
    BANNER,
    BANNER_TEXT,
    READY,
    VRRP,
    _export,
    _rewrite,
    _sub_line,
)

CONFIG = SSHConfig(host="10.0.0.1", username="admin", password="x")
SECRET = "correct-horse-battery-staple"  # what the fixtures fill secret fields with


class FakeNetmiko:
    """Commands and raw channel writes are recorded separately, on purpose.

    A ``banner motd`` block is the one case where the two differ: the opener and
    the closing delimiter are commands, and the lines between them are text
    written to the channel. A regression that sent the banner text as commands
    would be invisible if both landed in the same list.
    """

    def __init__(self, replies=None, default=""):
        self.sent = []
        self.written = []
        self.replies = replies or {}
        self.default = default

    def send_command(self, command, read_timeout=None, **kw):
        self.sent.append(command)
        reply = self.replies.get(command, self.default)
        if isinstance(reply, Exception):
            raise reply
        return reply

    def send_command_timing(self, command, read_timeout=None, **kw):
        return self.send_command(command, read_timeout=read_timeout)

    def write_channel(self, text):
        self.written.append(text)

    def read_channel(self):
        return ""

    def disconnect(self):
        pass


def _session(tmp_path, *control_ids, replies=None, dry_run=False, **kw):
    d = _export(tmp_path, *(control_ids or (READY,)), **kw)
    session = ApplySession(CONFIG, load_artifact(d), dry_run=dry_run)
    fake = FakeNetmiko(replies=replies)
    if not dry_run:
        session._connection._conn = fake
    return session, fake


# -- you cannot get one without a verified artifact -----------------------

def test_an_unverified_artifact_cannot_open_a_session(tmp_path):
    """The constructor verifies. There is no 'trust me, I checked' parameter."""
    d = _export(tmp_path, READY)
    _rewrite(d, _sub_line("ssh mgmt-auth public-key", "ssh mgmt-auth username/password"))
    with pytest.raises(ApplyRefused, match="does not verify"):
        ApplySession(CONFIG, load_artifact(d))


def test_an_incomplete_artifact_cannot_open_a_session(tmp_path):
    """A withheld secret makes every block in the file unappliable, not just the
    block that carries it — the check runs before the session exists."""
    d = _export(tmp_path, VRRP, include_secrets=False)
    with pytest.raises(ApplyRefused, match="does not verify"):
        ApplySession(CONFIG, load_artifact(d))


def test_a_re_approved_artifact_can_open_a_session(tmp_path):
    """The supported edit path still works — refusing it would push operators
    back to pasting by hand, which has no gate at all."""
    d = _export(tmp_path, READY)
    _rewrite(d, _sub_line("ssh mgmt-auth public-key",
                          "ssh mgmt-auth public-key username/password"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))
    session = ApplySession(CONFIG, load_artifact(d))
    assert session.verify_report.pinned_by == "approval"


# -- what it will and will not send ---------------------------------------

def test_a_verified_block_is_sent_line_by_line(tmp_path):
    session, fake = _session(tmp_path)
    result = session.send_block(session.artifact.blocks[0])
    assert result.ok
    assert fake.sent == ["configure terminal", "ssh mgmt-auth public-key", "end"]


def test_a_block_that_is_not_in_the_artifact_is_refused(tmp_path):
    """The check is on the commands, not on the object — a hand-built block that
    looks the part is still not the reviewed one."""
    session, fake = _session(tmp_path)
    forged = CfgBlock(control_id=READY, index=1, total=1,
                      lines=["configure terminal", "reload", "end"])
    with pytest.raises(ApplyRefused, match="not part of the verified artifact"):
        session.send_block(forged)
    assert fake.sent == []


def test_editing_the_artifact_after_verification_does_not_get_it_sent(tmp_path):
    """Verification happens once, at construction. Without a snapshot of what was
    verified, anything appended afterwards would inherit that verdict."""
    session, fake = _session(tmp_path)
    session.artifact.blocks.append(
        CfgBlock(control_id="AOS8-SNUCK-IN-001", index=2, total=2,
                 lines=["configure terminal", "no firewall cp", "end"]))
    with pytest.raises(ApplyRefused):
        session.send_block(session.artifact.blocks[-1])
    assert fake.sent == []


def test_mutating_a_verified_block_does_not_get_it_sent(tmp_path):
    session, fake = _session(tmp_path)
    block = session.artifact.blocks[0]
    block.lines.insert(1, "no firewall cp")
    with pytest.raises(ApplyRefused):
        session.send_block(block)
    assert fake.sent == []


def test_nothing_is_sent_when_any_line_of_a_block_is_refused(tmp_path):
    """Refusing part-way through would leave the half-applied state the whole
    design exists to avoid."""
    session, fake = _session(tmp_path)
    block = session.artifact.blocks[0]
    block.lines.append("reload")
    session._allowed = frozenset([tuple(block.lines)])  # pretend it verified
    with pytest.raises(ApplyRefused, match="destructive"):
        session.send_block(block)
    assert fake.sent == []


def test_an_incomplete_block_is_refused_at_send_time_too(tmp_path):
    """Already refused at construction. Checked again here because this is the
    failure that half-applies a change, and it costs one comparison."""
    session, _ = _session(tmp_path)
    block = session.artifact.blocks[0]
    block.incomplete = True
    with pytest.raises(ApplyRefused, match="partial change"):
        session.send_block(block)


def test_sending_without_a_connection_is_an_error(tmp_path):
    d = _export(tmp_path, READY)
    session = ApplySession(CONFIG, load_artifact(d))
    with pytest.raises(TransportError, match="not connected"):
        session.send_block(session.artifact.blocks[0])


# -- stopping on failure --------------------------------------------------

def test_a_failed_line_stops_the_block(tmp_path):
    """AOS8 rejects a line and carries on accepting the next one. Pushing more
    config on top of a rejected line is how a block half-lands."""
    session, fake = _session(tmp_path, replies={
        "ssh mgmt-auth public-key": "% Invalid input detected at '^' marker."})
    result = session.send_block(session.artifact.blocks[0])

    assert not result.ok
    assert result.failed_at == 1
    assert result.partial is True  # 'configure terminal' already landed
    assert "end" not in fake.sent


def test_a_timeout_mid_block_is_a_failure_not_a_crash(tmp_path):
    class ReadTimeout(Exception):
        pass

    session, _ = _session(tmp_path, replies={
        "ssh mgmt-auth public-key": ReadTimeout("read timed out")})
    result = session.send_block(session.artifact.blocks[0])
    assert not result.ok
    assert result.lines[1].exit_kind is ExitKind.TIMEOUT


def test_an_empty_reply_is_success_not_emptiness(tmp_path):
    """Inverted from collection, where an empty 'show' means the feature is
    absent. A config command that worked says nothing at all."""
    session, _ = _session(tmp_path)
    result = session.send_block(session.artifact.blocks[0])
    assert all(ln.exit_kind is ExitKind.EMPTY for ln in result.lines)
    assert result.ok


# -- the heartbeat --------------------------------------------------------

def test_the_heartbeat_uses_a_read_only_command(tmp_path):
    session, fake = _session(tmp_path, replies={HEARTBEAT_COMMAND: "Tue Aug 20"})
    assert session.alive() is True
    assert fake.sent == [HEARTBEAT_COMMAND]


def test_a_dead_session_reports_dead_rather_than_raising(tmp_path):
    """It runs immediately after a change that may have cut us off, so it has to
    survive the connection being gone."""
    session, _ = _session(tmp_path, replies={HEARTBEAT_COMMAND: OSError("socket closed")})
    assert session.alive() is False


def test_a_probe_must_still_be_read_only(tmp_path):
    """The applier's read-only side is the auditor's gate, not a relaxed copy."""
    from aos8_auditor.collection.command_catalog import UnsafeCommandError

    session, fake = _session(tmp_path)
    with pytest.raises(UnsafeCommandError):
        session.probe("write memory")
    assert fake.sent == []


# -- secrets --------------------------------------------------------------

def test_the_secret_reaches_the_device(tmp_path):
    """The point of --include-secrets. If this broke, the tool would quietly
    configure an authentication string of '********'."""
    session, fake = _session(tmp_path, VRRP)
    session.send_block(session.artifact.blocks[0])
    assert any(SECRET in line for line in fake.sent)


def test_the_secret_is_not_in_anything_written_down(tmp_path):
    """apply_result.json and the transcript are built from these results."""
    session, _ = _session(tmp_path, VRRP)
    result = session.send_block(session.artifact.blocks[0])
    recorded = json.dumps([{"command": ln.command, "output": ln.output}
                           for ln in result.lines])
    assert SECRET not in recorded
    assert any("authentication" in ln.command for ln in result.lines)


def test_a_refusal_message_does_not_quote_the_secret(tmp_path):
    """Exception text ends up in logs and on screens."""
    session, _ = _session(tmp_path, VRRP)
    block = session.artifact.blocks[0]
    block.lines.append("reload")
    session._allowed = frozenset([tuple(block.lines)])
    with pytest.raises(ApplyRefused) as excinfo:
        session.send_block(block)
    assert SECRET not in str(excinfo.value)


def test_a_command_carrying_no_secret_is_recorded_verbatim(tmp_path):
    """Masking everything would make the transcript useless as a change record."""
    session, _ = _session(tmp_path)
    result = session.send_block(session.artifact.blocks[0])
    assert [ln.command for ln in result.lines] == [
        "configure terminal", "ssh mgmt-auth public-key", "end"]


def test_transcript_lines_fall_back_to_redaction_when_positions_shift(tmp_path):
    """Position matching only holds for an unedited file. On a re-approved one it
    has to degrade to redaction rather than to the raw line."""
    d = _export(tmp_path, VRRP)
    _rewrite(d, _sub_line("configure terminal", "configure terminal\nvrrp 7"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))
    artifact = load_artifact(d)
    lines = transcript_lines(artifact, artifact.blocks[0])
    assert SECRET not in "\n".join(lines)


# -- dry run --------------------------------------------------------------

def test_a_dry_run_never_opens_a_connection(tmp_path):
    """Cheapest possible guarantee that --dry-run cannot send: no socket."""
    session, _ = _session(tmp_path, dry_run=True)
    session.connect()
    assert session._connection.is_open is False


def test_a_dry_run_reports_what_it_would_have_sent(tmp_path):
    session, _ = _session(tmp_path, dry_run=True)
    result = session.send_block(session.artifact.blocks[0])
    assert result.dry_run is True
    assert [ln.command for ln in result.lines] == [
        "configure terminal", "ssh mgmt-auth public-key", "end"]
    assert all(ln.sent is False for ln in result.lines)
    assert result.ok  # nothing failed, because nothing happened


def test_a_dry_run_still_refuses_what_a_real_run_would(tmp_path):
    """A dry run that accepted a forged block would be a useless rehearsal."""
    session, _ = _session(tmp_path, dry_run=True)
    forged = CfgBlock(control_id=READY, index=1, total=1,
                      lines=["configure terminal", "reload", "end"])
    with pytest.raises(ApplyRefused):
        session.send_block(forged)


# -- node tracking --------------------------------------------------------

def test_the_session_follows_the_block_to_its_node(tmp_path):
    """Later probes have to run where the change landed, not at the root."""
    session, _ = _session(tmp_path, node_path="/md/Campus/wlc-1")
    session.send_block(session.artifact.blocks[0])
    assert session.node_path == "/md/Campus/wlc-1"


def test_a_failed_block_does_not_move_the_session(tmp_path):
    session, _ = _session(tmp_path, node_path="/md/Campus/wlc-1",
                          replies={"cd /md/Campus/wlc-1": "% Invalid input"})
    session.send_block(session.artifact.blocks[0])
    assert session.node_path == "/"


# -- raw text entry -------------------------------------------------------

# What a controller says when 'banner motd ^' is accepted and the CLI stops
# interpreting what follows as commands.
INVITE = ("Enter TEXT message [maximum of 4095 characters].\n"
          "End with the character '^'.\n")
# ...and what it says to the one-line form, which is the failure this whole path
# exists to make impossible.
REJECTED = "% Invalid input detected at '^' marker."


def test_a_banner_is_sent_as_text_not_as_commands(tmp_path):
    """The opener and the closing delimiter are commands. What is between them
    is text written to the channel — sending it as a command would wait for a
    prompt the controller is not going to print until the banner closes."""
    session, fake = _session(tmp_path, BANNER, replies={"banner motd ^": INVITE})
    result = session.send_block(session.artifact.blocks[0])

    assert result.ok, [ln.output for ln in result.lines]
    assert fake.sent == ["configure terminal", "banner motd ^", "^", "end"]
    assert fake.written == [BANNER_TEXT + "\n"]
    # One result per physical line, so the block's line accounting still matches
    # the block that was reviewed.
    assert len(result.lines) == len(session.artifact.blocks[0].lines)


def test_a_rejected_banner_opener_sends_none_of_the_text(tmp_path):
    """The dangerous direction. If the opener is refused the CLI is still at a
    config prompt, so the banner's own words would be run as configuration."""
    session, fake = _session(tmp_path, BANNER,
                             replies={"banner motd ^": REJECTED})
    result = session.send_block(session.artifact.blocks[0])

    assert not result.ok
    assert result.failed_at == 1
    assert fake.written == []
    assert "^" not in fake.sent and "end" not in fake.sent


def test_a_banner_opener_that_hands_the_prompt_back_is_not_success(tmp_path):
    """A quieter version of the same failure: no error text, but the CLI never
    entered text mode. Reporting that as applied would leave a controller with
    no banner and a run that thinks it set one."""
    session, fake = _session(tmp_path, BANNER,
                             replies={"banner motd ^": "(WLC) [mynode] (config) #"})
    session._connection._prompt = prompt_pattern("(WLC) [mynode] (config) #")
    result = session.send_block(session.artifact.blocks[0])

    assert not result.ok
    assert result.lines[1].exit_kind is ExitKind.ERROR
    assert fake.written == []


def test_a_reload_in_the_banner_text_is_not_refused(tmp_path):
    """Banner text is data. A message that mentions rebooting is a message."""
    d = _export(tmp_path, BANNER)
    _rewrite(d, _sub_line(BANNER_TEXT, "reload requests go to the service desk"))
    (d / "approval.json").write_text(json.dumps(
        approval_document(load_artifact(d), operator="tester")))
    session = ApplySession(CONFIG, load_artifact(d))
    fake = FakeNetmiko(replies={"banner motd ^": INVITE})
    session._connection._conn = fake

    result = session.send_block(session.artifact.blocks[0])
    assert result.ok
    assert fake.written == ["reload requests go to the service desk\n"]


def test_a_command_that_asks_a_question_is_refused_before_line_one(tmp_path):
    """Same shape as the destructive refusal, for the same reason: the block's
    next line would be read as the answer rather than run."""
    session, fake = _session(tmp_path)
    block = session.artifact.blocks[0]
    block.lines.insert(1, "controller-ip vlan 200")
    session._allowed = frozenset([tuple(block.lines)])  # pretend it verified
    with pytest.raises(ApplyRefused, match="asks for confirmation"):
        session.send_block(block)
    assert fake.sent == []


def test_a_timeout_cancels_whatever_the_cli_is_waiting_for(tmp_path):
    """A read timeout may mean the device asked a question, in which case the
    next thing written to the channel — including the rollback — becomes the
    answer. Ctrl-C first, so that thing is a cancellation."""
    class ReadTimeout(Exception):
        pass

    session, fake = _session(tmp_path, replies={
        "ssh mgmt-auth public-key": ReadTimeout("read timed out")})
    session.send_block(session.artifact.blocks[0])
    assert fake.written[:1] == ["\x03"]


# -- commands that ask instead of failing ---------------------------------
#
# The failure that motivated this section did not look like a failure. On
# ArubaOS several configuration keywords share a first token with an exec
# command, and an argument the config form does not accept makes the parser fall
# through to the exec one:
#
#     (config) #ssh disable-ciphers hmac-sha1-96
#     Password:
#
# Nothing was rejected. The SSH *client* is now asking for a password, the read
# runs out its full timeout and is reported as a dead controller, and the next
# line of the block is typed in as the password. Observed on 8.13.3.0.

PASSWORD_PROMPT = "Password:"


def test_a_command_that_falls_through_to_a_prompt_is_not_a_timeout(tmp_path):
    """Reported as INTERACTIVE, which is a statement about the command. TIMEOUT
    is a statement about the device, and it sends the operator to go and check a
    controller that is working perfectly well."""
    session, fake = _session(tmp_path, replies={
        "ssh mgmt-auth public-key": PASSWORD_PROMPT})
    result = session.send_block(session.artifact.blocks[0])

    assert not result.ok
    assert result.lines[1].exit_kind is ExitKind.INTERACTIVE
    assert result.lines[1].exit_kind is not ExitKind.TIMEOUT
    assert "Password:" in (result.lines[1].error_signature or "")


def test_a_prompt_is_cancelled_at_the_line_that_opened_it(tmp_path):
    """Not one line later. While the question is open the channel is captured,
    so 'end' would be submitted as the password rather than run."""
    session, fake = _session(tmp_path, replies={
        "ssh mgmt-auth public-key": PASSWORD_PROMPT})
    session.send_block(session.artifact.blocks[0])

    assert fake.written[:1] == ["\x03"]
    assert "end" not in fake.sent


def test_output_that_merely_mentions_a_question_is_not_a_prompt(tmp_path):
    """The controller may print 'Are you sure?' and then hand the prompt back,
    which means it already finished. Only a reply that *stops* at the question
    has the session captured, so the prompt is checked first."""
    session, fake = _session(tmp_path, replies={
        "ssh mgmt-auth public-key":
            "Are you sure you want to continue?\n(WLC) [mynode] (config) #"})
    session._connection._prompt = prompt_pattern("(WLC) [mynode] (config) #")
    result = session.send_block(session.artifact.blocks[0])

    assert result.lines[1].exit_kind is not ExitKind.INTERACTIVE
    assert fake.written == []  # nothing was cancelled


def test_a_banner_opener_that_asks_a_question_stores_no_text(tmp_path):
    """The worst version of this: text entry and a password prompt both swallow
    the next line without saying anything. Telling them apart is the difference
    between storing a banner and typing it into a login."""
    session, fake = _session(tmp_path, BANNER,
                             replies={"banner motd ^": PASSWORD_PROMPT})
    result = session.send_block(session.artifact.blocks[0])

    assert not result.ok
    assert result.lines[1].exit_kind is ExitKind.INTERACTIVE
    assert fake.written[:1] == ["\x03"]
    assert BANNER_TEXT + "\n" not in fake.written
