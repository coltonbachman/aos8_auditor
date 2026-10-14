"""Where the read-only gate lives, now that something else can write.

Until Phase 2 the auditor was read-only because it was the only thing in the
package that could open a session. That is no longer the argument, so the
property needs a test of its own: whatever else exists, nothing a ``Session``
sends can be anything but a safelisted read-only command.

Nothing here touches a network. The connection is faked at the netmiko boundary.
"""

import pytest

from aos8_auditor.collection.command_catalog import UnsafeCommandError, assert_safe
from aos8_auditor.model.evidence import ExitKind
from aos8_auditor.transport.connection import Connection, SSHConfig, TransportError
from aos8_auditor.transport.ssh_session import Session

CONFIG = SSHConfig(host="10.0.0.1", username="auditor", password="x")


class FakeNetmiko:
    """Stands in for netmiko's BaseConnection, recording what it was asked to send."""

    def __init__(self, reply="ok", fail_on=()):
        self.sent = []
        self.reply = reply
        self.fail_on = fail_on
        self.disconnected = False

    def send_command(self, command, read_timeout=None, **kw):
        self.sent.append(command)
        if command in self.fail_on:
            raise RuntimeError("device said no")
        return self.reply

    def disconnect(self):
        self.disconnected = True


def _connected(reply="ok", fail_on=()):
    """A Session wired to a fake, skipping open() and therefore netmiko."""
    session = Session(CONFIG)
    fake = FakeNetmiko(reply=reply, fail_on=fail_on)
    session._connection._conn = fake
    return session, fake


# -- the gate -------------------------------------------------------------

def test_an_unsafe_command_never_reaches_the_wire():
    session, fake = _connected()
    with pytest.raises(UnsafeCommandError):
        session.run("write erase all")
    assert fake.sent == []


@pytest.mark.parametrize("command", [
    "configure terminal",
    "reload",
    "write memory",
    "ssh mgmt-auth public-key",
    "no spanning-tree",
    "copy running-config tftp: 10.0.0.9 x.cfg",
])
def test_the_things_the_apply_path_sends_are_refused_here(command):
    """The apply path's whole vocabulary, offered to the auditor's session."""
    session, fake = _connected()
    with pytest.raises(UnsafeCommandError):
        session.run(command)
    assert fake.sent == []


def test_everything_a_session_does_send_is_safelisted():
    """Rather than trusting that run() is the only door, drive the session the way
    the collector does and check every byte that came out the other side."""
    session, fake = _connected()
    session._disable_paging()
    session.set_node("/md/Campus/wlc-1")
    session.run("show running-config")
    session.run("show version")

    assert fake.sent  # the test would pass vacuously if nothing was sent
    for command in fake.sent:
        assert_safe(command)  # raises if any of them were not allowed


def test_the_session_offers_no_way_to_send_arbitrary_text():
    """A public passthrough would make the gate above a formality."""
    passthroughs = [name for name in dir(Session)
                    if not name.startswith("_")
                    and name in {"send", "send_command", "send_config_set",
                                 "write", "execute", "raw", "send_raw"}]
    assert passthroughs == []


# -- reporting a failed session setup -------------------------------------

def test_paging_off_is_only_claimed_when_it_worked():
    session, _ = _connected()
    session._disable_paging()
    assert session.paging_disabled is True
    assert session.connect_warnings == []


def test_a_device_error_on_no_paging_is_surfaced_not_swallowed():
    """run() reports device-level failure in the result rather than raising, so a
    session that read the exit kind wrong would claim paging was off and then
    silently collect truncated output for the rest of the run."""
    session, _ = _connected(reply="% Invalid input detected at '^' marker.")
    session._disable_paging()
    assert session.paging_disabled is False
    assert any("could not disable paging" in w for w in session.connect_warnings)


def test_a_transport_failure_on_no_paging_is_surfaced():
    session, _ = _connected(fail_on=("no paging",))
    session._disable_paging()
    # run() converts a netmiko-level exception into an ERROR result, which is
    # still not a working 'no paging'.
    assert session.paging_disabled is False
    assert session.connect_warnings


def test_running_without_a_connection_is_an_error_not_a_crash():
    session = Session(CONFIG)
    with pytest.raises(TransportError, match="not connected"):
        session.run("show version")


# -- the split ------------------------------------------------------------

def test_the_connection_layer_holds_no_policy():
    """Deliberate, and worth pinning so nobody adds half a gate here later.

    A Connection sends what it is given. The point of the split is that a caller
    must hold a *policy* object to get anything sent: the auditor's Session, which
    gates on the read-only catalog, or the apply path, which gates on a
    hash-verified artifact. A partial check in the middle would give a false
    sense that holding a bare Connection is safe.
    """
    conn = Connection(CONFIG)
    conn._conn = FakeNetmiko()
    conn.send("show version")
    assert conn._conn.sent == ["show version"]
    assert not hasattr(conn, "run")  # no result-shaping, no redaction, no gate


def test_closing_is_idempotent():
    """disconnect() runs in a finally on paths that may not have connected."""
    conn = Connection(CONFIG)
    fake = FakeNetmiko()
    conn._conn = fake
    conn.close()
    conn.close()
    assert fake.disconnected is True
    assert conn.is_open is False


def test_the_session_redacts_before_returning_output():
    """Redaction is the session's job, not the caller's — a caller that forgot
    would write secrets to disk."""
    session, _ = _connected(reply="mgmt-user admin root 1a2b3c4d5e6f7a8b9c0d\n")
    result = session.run("show running-config")
    assert "1a2b3c4d5e6f7a8b9c0d" not in result.redacted_output
    assert result.redaction_count > 0


def test_the_node_path_is_recorded_on_every_result():
    """Findings are attributed per node; a result that lost its node would be
    scored against the wrong controller."""
    session, _ = _connected()
    session.set_node("/md/Campus/wlc-1")
    assert session.run("show version").node_path == "/md/Campus/wlc-1"


def test_a_timeout_is_a_result_not_an_exception():
    class Timeout(Exception):
        pass

    session, fake = _connected()

    def boom(command, read_timeout=None):
        raise Timeout("read timed out")

    fake.send_command = boom
    result = session.run("show running-config")
    assert result.exit_kind is ExitKind.TIMEOUT
    assert result.redacted_output == ""
