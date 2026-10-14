"""Waiting for a prompt that the controller has stopped printing.

ArubaOS 8 rewrites its own prompt as you move around the box:

    (WLC) [mynode] #                    exec
    (WLC) [mynode] (config) #           after 'configure terminal'
    (WLC) [00:1a:1e:...] #              after 'cd /md/...'

netmiko's default is to wait for the prompt it saw *before* the command, which
neither of the last two contains. The first line of every remediation block is
'configure terminal', so every apply run failed there — reported as
"the controller rejected 'configure terminal' (timeout: ReadTimeout)", which is
two wrong statements: it did not reject it, and it very likely carried it out.

The prompts below are transcribed from a real 8.x controller, and the fake
device models the one behaviour that caused the bug: it answers only when the
pattern the caller is waiting for will actually appear.
"""

import re

import pytest

from aos8_auditor.model.evidence import ExitKind
from aos8_auditor.remediate.apply import (
    AppliedBlock,
    ApplyOptions,
    ApplyResult,
    _handle_failure,
)
from aos8_auditor.transport.apply_session import ApplySession
from aos8_auditor.transport.connection import Connection, SSHConfig, prompt_pattern
from test_remediate_apply import _artifact
from test_remediate_approve import READY

CONFIG = SSHConfig(host="10.0.0.1", username="admin", password="x")

EXEC = "(ArubaMC-VA_7F_57_17) [mynode] #"
CONFIG_MODE = "(ArubaMC-VA_7F_57_17) [mynode] (config) #"
OTHER_NODE = "(ArubaMC-VA_7F_57_17) [00:1a:1e:00:00:01] #"
UNSAVED = "(ArubaMC-VA_7F_57_17) ^[mynode] (config) #"
STANDALONE = "(Aruba7005) #"


class ReadTimeout(Exception):
    """Named to match netmiko's, which is how _send_line tells a timeout apart."""


class Controller:
    """A netmiko stand-in that only answers when the caller's pattern will match.

    Faking the socket is not enough to catch this: the bug was never about what
    the controller said, it was about what the client was waiting to hear.
    """

    HOST = "ArubaMC-VA_7F_57_17"

    def __init__(self):
        self.sent = []
        self.node = "mynode"
        self.in_config = False

    def find_prompt(self):
        tail = " (config)" if self.in_config else ""
        return f"({self.HOST}) [{self.node}]{tail} #"

    def send_command(self, command, read_timeout=None, expect_string=None,
                     strip_prompt=True):
        before = self.find_prompt()
        self.sent.append(command)

        reply = ""
        if command == "configure terminal":
            self.in_config = True
            reply = "Enter Configuration commands, one per line. End with CNTL/Z"
        elif command == "end":
            self.in_config = False
        elif command.startswith("cd "):
            self.node = command.split(None, 1)[1]
        elif command == "show clock":
            reply = "Tue Aug 20 09:00:00 PDT 2026"

        # What netmiko sees on the wire, and what it is waiting for. With no
        # expect_string it waits for the prompt from before the command ran.
        seen = f"{reply}\n{self.find_prompt()}" if reply else self.find_prompt()
        if not re.search(expect_string or re.escape(before), seen):
            raise ReadTimeout(f"Pattern not detected: {expect_string!r} in output.")
        # netmiko strips the prompt it recognised; one it does not stays put, and
        # a caller that asked to keep it keeps it either way.
        return reply if (expect_string and strip_prompt) else seen

    def disconnect(self):
        pass


def _connection(device=None):
    """A Connection that has learned its prompt, without opening a socket."""
    conn = Connection(CONFIG)
    conn._conn = device or Controller()
    conn._learn_prompt()
    return conn


# -- the pattern ----------------------------------------------------------

@pytest.mark.parametrize("prompt", [EXEC, CONFIG_MODE, OTHER_NODE, UNSAVED])
def test_the_pattern_learned_at_login_survives_every_mode(prompt):
    """The hostname in the leading parentheses is the only part that holds
    still, so it is the only part worth anchoring on."""
    assert re.search(prompt_pattern(EXEC), prompt)


def test_the_pattern_netmiko_derives_is_the_one_that_breaks():
    """The regression, stated as the thing it is not. Without this the fix above
    looks like a preference rather than a fix."""
    assert not re.search(re.escape(EXEC), CONFIG_MODE)


def test_a_prompt_with_nothing_to_anchor_on_falls_back_to_any_prompt():
    assert re.search(prompt_pattern("switch>"), "switch>")
    assert re.search(prompt_pattern("switch>"), "switch(config)#")


def test_a_controller_with_no_node_in_its_prompt_works_too():
    assert re.search(prompt_pattern(STANDALONE), "(Aruba7005) (config) #")


# -- the connection -------------------------------------------------------

def test_entering_config_mode_no_longer_times_out():
    conn = _connection()
    assert conn.send("configure terminal").startswith("Enter Configuration")


def test_without_the_learned_pattern_it_times_out_exactly_as_reported():
    """Same fake, same command, pattern left to netmiko: the original bug."""
    conn = Connection(CONFIG)
    conn._conn = Controller()          # no _learn_prompt(), so no expect_string
    with pytest.raises(ReadTimeout):
        conn.send("configure terminal")


def test_changing_node_no_longer_times_out_either():
    """The same fault on the read-only path: a Mobility Master audit walks its
    managed nodes with 'cd', which moves the prompt just as much."""
    conn = _connection()
    conn.send("cd /md/Campus/00:1a:1e:00:00:01")
    assert conn.send("show clock").strip() == "Tue Aug 20 09:00:00 PDT 2026"


def test_a_prompt_netmiko_did_not_recognise_is_not_kept_as_output():
    """netmiko strips the prompt it was expecting. One that changed shape comes
    back attached to the output and would be stored as part of the evidence."""
    conn = _connection()
    assert "ArubaMC" not in conn.send("cd /md/Campus/00:1a:1e:00:00:01")


def test_the_pattern_is_forgotten_when_the_connection_closes():
    """A reconnect can land on a different controller — the applier reconnects
    after a change that dropped the session."""
    conn = _connection()
    conn.close()
    assert conn._prompt is None


# -- the block that could not be sent -------------------------------------

def test_a_block_gets_all_the_way_through_configure_terminal(tmp_path):
    """The end-to-end shape of the failure: block one, line one, every run."""
    artifact = _artifact(tmp_path)
    session = ApplySession(CONFIG, artifact)
    device = Controller()
    session._connection._conn = device
    session._connection._learn_prompt()

    result = session.send_block(artifact.blocks[0])

    assert result.ok, [(ln.command, ln.exit_kind) for ln in result.lines]
    assert result.control_id == READY
    assert device.sent == ["configure terminal", "ssh mgmt-auth public-key", "end"]
    assert not device.in_config, "the block has to leave the controller in exec mode"


def test_the_same_block_without_the_fix_reports_a_timeout_not_a_rejection(tmp_path):
    """What the operator saw, pinned so the wording stays honest if it recurs."""
    artifact = _artifact(tmp_path)
    session = ApplySession(CONFIG, artifact)
    session._connection._conn = Controller()   # unlearned, so netmiko's pattern

    result = session.send_block(artifact.blocks[0])
    assert result.lines[0].exit_kind is ExitKind.TIMEOUT

    applied = AppliedBlock(control_id=READY, result=result)
    report = ApplyResult()
    _handle_failure(session, artifact, applied, ApplyOptions(), report, lambda _m: None)

    assert "no reply to" in report.errors[0]
    assert "rejected" not in report.errors[0]


# -- prompts that are waiting for an answer -------------------------------
#
# The other way a line stops coming back. Some ArubaOS configuration keywords
# share their first token with an exec command, and an argument the config form
# does not take drops the parser into the exec one:
#
#     (config) #ssh disable-ciphers hmac-sha1-96
#     Password:
#
# The SSH client is asking now. Waiting for a config prompt that will not arrive
# until someone answers is a full read timeout followed by a report that the
# controller is dead, and the next line written is read as the password.

class Asker:
    """A controller that answers one command with a question and then waits."""

    HOST = "ArubaMC-VA_7F_57_17"

    def __init__(self, asks_on, question="Password:"):
        self.asks_on, self.question = asks_on, question
        self.sent, self.written = [], []

    def find_prompt(self):
        return f"({self.HOST}) [mynode] (config) #"

    def send_command(self, command, read_timeout=None, expect_string=None,
                     strip_prompt=True):
        self.sent.append(command)
        if command == self.asks_on:
            # No prompt after it: that is what "still waiting" looks like.
            if not (expect_string and re.search(expect_string, self.question)):
                raise ReadTimeout(f"Pattern not detected: {expect_string!r}")
            return self.question
        seen = self.find_prompt()
        return "" if (expect_string and strip_prompt) else seen

    def write_channel(self, text):
        self.written.append(text)

    def read_channel(self):
        return ""

    def disconnect(self):
        pass


def test_a_line_that_opens_a_prompt_comes_back_instead_of_timing_out():
    """The reply is the question. Without this the read waits out its whole
    timeout for a prompt that only appears once someone answers."""
    conn = _connection(Asker("ssh disable-ciphers hmac-sha1-96"))
    reply, asked = conn.send_line("ssh disable-ciphers hmac-sha1-96")
    assert asked == "Password:"
    assert "Password:" in reply


def test_an_ordinary_line_is_not_read_as_a_question():
    conn = _connection(Asker("something else"))
    reply, asked = conn.send_line("ssh mgmt-auth public-key")
    assert asked is None


@pytest.mark.parametrize("question", [
    "Password:", "password: ", "Login:", "Username:",
    "Are you sure you want to continue?", "[y/n]:", "(y/n)",
])
def test_the_shapes_a_waiting_prompt_takes(question):
    conn = _connection(Asker("x", question=question))
    assert conn.interactive_prompt(question) is not None


def test_a_question_the_controller_already_answered_itself_is_not_one():
    """'Are you sure?' followed by the prompt means it finished. The difference
    between that and a captured session is exactly one line, which is the line
    netmiko removes — so this is checked before the reply is stripped."""
    conn = _connection()
    assert conn.interactive_prompt(f"Are you sure?\n{CONFIG_MODE}") is None
    assert conn.interactive_prompt("Are you sure?") is not None


def test_the_word_password_inside_output_is_not_a_prompt():
    """A config dump says 'password' constantly. Only a reply that *ends* at the
    question, with nothing after it, has the session waiting."""
    conn = _connection()
    dump = "mgmt-user admin root\nwpa-passphrase:\nvlan 100\n" + CONFIG_MODE
    assert conn.interactive_prompt(dump) is None


def test_the_read_only_path_does_not_shorten_its_reads():
    """send() is untouched: 'show' output arrives in blocks that can contain the
    word 'password:' part-way through, and returning early truncates evidence."""
    captured = {}

    class Recorder(Controller):
        def send_command(self, command, read_timeout=None, expect_string=None,
                         strip_prompt=True):
            captured["expect"] = expect_string
            return super().send_command(command, read_timeout, expect_string,
                                        strip_prompt)

    conn = _connection(Recorder())
    conn.send("show clock")
    assert "Password" not in (captured["expect"] or "")
