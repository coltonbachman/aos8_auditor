"""Read-only SSHv2 session to an ArubaOS 8 controller.

Every command is run through the command-catalog safelist before being sent, and
every output is redacted before it is ever returned in a :class:`CommandResult`.
There is no method here that sends a raw or arbitrary command: the only way text
reaches the wire through this class is :meth:`Session.run`, and the first thing
it does is ``assert_safe``.

The socket itself lives in :mod:`.connection`, which the apply path also uses.
That module holds no policy at all — this one is where "read-only" is enforced,
and the split exists so the applier cannot get its permissions by inheriting
from an auditor.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from ..collection.classify import classify_exit_kind
from ..collection.command_catalog import assert_safe
from ..collection.redaction import redact
from ..model.evidence import CommandResult, ExitKind
from .connection import Connection, SSHConfig, TransportError

__all__ = ["SSHConfig", "Session", "TransportError", "run_readonly"]


def run_readonly(connection: Connection, command: str, *, node_path: str = "/",
                 timeout_s: int | None = None,
                 redact_output: bool = True) -> CommandResult:
    """Run one safelisted read-only command over ``connection``.

    Module-level rather than a method because the apply path needs read-only
    commands too — it re-audits before it starts and checks its own work after
    every block — and it has to do that on the *same* connection, at the same
    config node. Giving it its own copy of this function would mean two
    implementations of "read-only", which is one more than can be kept honest.
    """
    assert_safe(command)  # hard gate: unsafe commands never reach the wire
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.monotonic()
    try:
        raw = connection.send(command, read_timeout=timeout_s)
        exit_kind, sig = classify_exit_kind(raw, echoed_command=command)
    except TransportError:
        raise
    except Exception as e:  # netmiko ReadTimeout etc.
        etype = type(e).__name__
        kind = ExitKind.TIMEOUT if "timeout" in etype.lower() else ExitKind.ERROR
        return CommandResult(
            command=command,
            redacted_output="",
            exit_kind=kind,
            node_path=node_path,
            error_signature=etype,
            started_at=started,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )

    out = raw
    rcount, rkinds = 0, []
    if redact_output:
        rr = redact(raw)
        out, rcount, rkinds = rr.text, rr.count, rr.kinds

    result = CommandResult(
        command=command,
        redacted_output=out,
        exit_kind=exit_kind,
        node_path=node_path,
        error_signature=sig,
        started_at=started,
        duration_ms=int((time.monotonic() - t0) * 1000),
        redaction_count=rcount,
        redaction_kinds=rkinds,
    )
    result.sha256 = result.compute_sha256()
    return result


class Session:
    """A live, reusable SSH session. Use as a context manager.

    The session is read-only: only commands accepted by ``assert_safe`` are ever
    transmitted, and there is no method that sends a raw/arbitrary command.
    """

    def __init__(self, config: SSHConfig):
        self.config = config
        self._connection = Connection(config)
        self.connect_warnings: list[str] = self._connection.warnings
        self.paging_disabled = False
        self.node_path = "/"

    # -- lifecycle ---------------------------------------------------------
    def connect(self) -> "Session":
        self._connection.open()
        self._disable_paging()
        return self

    def _disable_paging(self) -> None:
        # 'no paging' is session-scoped and read-only (writes no config). It is
        # the AOS8 idiom — NOT IOS 'terminal length 0'. It goes through run() like
        # everything else, so it is safelisted rather than exempt.
        try:
            result = self.run("no paging")
        except Exception as e:  # pragma: no cover - network dependent
            self.connect_warnings.append(f"could not disable paging ('no paging' failed: {e})")
            return
        # run() reports a device-level failure in the result rather than raising,
        # so the warning has to come off the exit kind. Claiming paging is off when
        # it is not turns every long output into a truncated one.
        if result.exit_kind in (ExitKind.OK, ExitKind.EMPTY):
            self.paging_disabled = True
        else:
            self.connect_warnings.append(
                f"could not disable paging ('no paging' returned "
                f"{result.exit_kind.value}); long output may be truncated")

    def set_node(self, node_path: str) -> None:
        """Change the active config node (Mobility Master) read-only via 'cd'."""
        self.run(f"cd {node_path}")  # safelisted; navigation only
        self.node_path = node_path

    def disconnect(self) -> None:
        self._connection.close()

    def __enter__(self) -> "Session":
        return self.connect()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.disconnect()

    # -- command execution -------------------------------------------------
    def run(self, command: str, *, timeout_s: int | None = None, redact_output: bool = True) -> CommandResult:
        """Run one safelisted read-only command and return a redacted result."""
        return run_readonly(self._connection, command, node_path=self.node_path,
                            timeout_s=timeout_s, redact_output=redact_output)
