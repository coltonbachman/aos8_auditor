"""The one class in this package that can send a configuration command.

Its permission model is not a list of allowed verbs — a verb list is the wrong
shape for this, because "the right change" and "the change that locks you out"
are spelled with the same verbs. The model is instead:

    the only thing this session will send is a block of a remediation artifact
    whose bytes still hash to what a human reviewed.

That is enforced twice over. An ``ApplySession`` re-runs :func:`verify` itself in
its constructor — a caller cannot hand it an artifact plus a claim that the
artifact was checked — and it snapshots the verified command lines at that
moment, so mutating the artifact afterwards produces blocks it will not send.

Everything else the session does is read-only and goes through the same
``assert_safe`` gate as the auditor, via the shared
:func:`~.ssh_session.run_readonly`. So every byte this class emits is either a
verified block or a read-only command; there is no third category.

Secrets go to the device and nowhere else: a command that carries one is
recorded in results in its masked form, taken from the record, and every stored
line is passed through :func:`redact` on top of that.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..collection.classify import classify_exit_kind
from ..collection.redaction import redact
from ..model.evidence import CommandResult, ExitKind
from ..remediate.approve import Artifact, CfgBlock, VerifyReport, verify
from ..remediate.hints import is_destructive, prompts_for_confirmation, text_entry_regions
from .connection import Connection, SSHConfig, TransportError
from .ssh_session import run_readonly

# A configuration command that worked usually replies with nothing at all, so
# EMPTY is the ordinary success here — the opposite of what it means during
# collection, where an empty 'show' means the feature is absent.
_ACCEPTED = (ExitKind.OK, ExitKind.EMPTY)

# Cheap, universally available, and its reply proves the CLI is still answering.
HEARTBEAT_COMMAND = "show clock"


class ApplyRefused(RuntimeError):
    """The session declined to send something. Never a device-side failure.

    Deliberately not a :class:`TransportError`: "I would not send this" and "the
    device rejected this" have to stay distinguishable, or a refusal gets
    reported as a controller problem and someone goes looking at the controller.
    """


@dataclass
class LineResult:
    """One command, as it was sent and as it may be written down."""

    command: str  # masked/redacted — safe to persist
    output: str   # redacted
    exit_kind: ExitKind = ExitKind.OK
    error_signature: str | None = None
    sent: bool = True  # False on a dry run
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.exit_kind in _ACCEPTED


@dataclass
class BlockResult:
    """One block of the artifact, applied or attempted."""

    control_id: str
    reverse: bool = False
    lines: list[LineResult] = field(default_factory=list)
    dry_run: bool = False
    started_at: str = ""
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return all(ln.ok for ln in self.lines)

    @property
    def failed_at(self) -> int | None:
        """Index of the first line that failed, which is where sending stopped."""
        for i, ln in enumerate(self.lines):
            if not ln.ok:
                return i
        return None

    @property
    def partial(self) -> bool:
        """It failed after at least one line landed — the state to worry about."""
        i = self.failed_at
        return i is not None and i > 0


def transcript_lines(artifact: Artifact, block: CfgBlock) -> list[str]:
    """The block's commands in a form that is safe to write to disk.

    A command carrying a secret is replaced by the record's masked rendering of
    the same command, matched by position rather than guessed at by pattern. If
    the positions do not line up — only possible on an artifact that was edited
    and re-approved — every line falls back to :func:`redact`, which is the same
    primitive that guards every captured byte elsewhere in the tool.
    """
    record = artifact.change_record(block.control_id)
    masked = list(record.get("commands") or [])
    secret_indexes = {
        i for f in (record.get("fields") or [])
        if f.get("secret") for i in (f.get("used_in_lines") or [])
    }

    head = ([f"cd {artifact.node_path}"] if artifact.node_path not in (None, "/") else [])
    head.append("configure terminal")
    body_start = len(head) if block.lines[:len(head)] == head else 0
    body_end = len(block.lines) - 1 if block.lines[-1:] == ["end"] else len(block.lines)
    aligned = (body_end - body_start) == len(masked)

    out = []
    for i, line in enumerate(block.lines):
        text = line
        body_index = i - body_start
        if secret_indexes and aligned and body_start <= i < body_end:
            if body_index in secret_indexes:
                text = masked[body_index]
        out.append(redact(text).text)
    return out


class ApplySession:
    """A session that may send exactly one artifact's verified blocks.

    Use as a context manager. Construction verifies; it does not connect.
    """

    def __init__(self, config: SSHConfig, artifact: Artifact, *,
                 dry_run: bool = False, command_timeout_s: int | None = None):
        report = verify(artifact)
        if not report.ok:
            raise ApplyRefused(
                "refusing to open an apply session for an artifact that does not "
                "verify:\n  - " + "\n  - ".join(report.errors))

        self.config = config
        self.artifact = artifact
        self.verify_report: VerifyReport = report
        self.dry_run = dry_run
        self.command_timeout_s = command_timeout_s
        self.node_path = "/"
        # The bytes that were verified, snapshotted now. Comparing against this
        # rather than against the artifact means a block appended or edited after
        # verification is not sendable, even though it lives on a verified object.
        self._allowed: frozenset[tuple[str, ...]] = frozenset(
            tuple(b.lines) for b in artifact.blocks + artifact.rollback_blocks)
        self._connection = Connection(config)

    # -- lifecycle ---------------------------------------------------------
    @property
    def connect_warnings(self) -> list[str]:
        return self._connection.warnings

    def connect(self) -> "ApplySession":
        if self.dry_run:
            # A dry run must not be able to send anything by accident, and the
            # cheapest way to guarantee that is to never open the socket.
            return self
        self._connection.open()
        self._disable_paging()
        return self

    def _disable_paging(self) -> None:
        result = run_readonly(self._connection, "no paging", node_path=self.node_path)
        if result.exit_kind not in _ACCEPTED:
            self.connect_warnings.append(
                "could not disable paging; a long verification output may be "
                "truncated and read as a failure")

    def reconnect(self) -> bool:
        """Try once to get the session back after it stopped answering.

        A dropped SSH session and a controller that has just locked you out look
        identical from here, and the difference matters enormously — one is a
        blip, the other is the thing the operator needs to be told about right
        now. One attempt tells them apart without turning a real lockout into a
        retry loop against a controller that is never going to answer.
        """
        if self.dry_run:
            return True
        self._connection.close()
        try:
            self._connection.open()
        except Exception:
            return False
        self._disable_paging()
        if self.node_path != "/":
            self.probe(f"cd {self.node_path}")
        return self.alive()

    def disconnect(self) -> None:
        self._connection.close()

    def __enter__(self) -> "ApplySession":
        return self.connect()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.disconnect()

    # -- read-only ---------------------------------------------------------
    def probe(self, command: str, *, timeout_s: int | None = None) -> CommandResult:
        """Run a read-only command — re-audit, verification, heartbeat.

        Same gate as the auditor's, same implementation. On a dry run this is the
        only kind of command that is actually sent... except that a dry run never
        connects, so nothing is.
        """
        if self.dry_run:
            return CommandResult(
                command=command, redacted_output="", exit_kind=ExitKind.EMPTY,
                node_path=self.node_path, error_signature="dry-run")
        return run_readonly(self._connection, command, node_path=self.node_path,
                            timeout_s=timeout_s or self.command_timeout_s)

    def alive(self) -> bool:
        """Is the controller still answering us?

        Run after every block, not only the ones flagged ``lockout_risk``. The
        flag drives how loudly the operator is warned beforehand; it must not be
        what decides whether the safety net is deployed, because then the net is
        only as good as the curation of a YAML file.
        """
        if self.dry_run:
            return True
        try:
            return self.probe(HEARTBEAT_COMMAND).exit_kind in _ACCEPTED
        except TransportError:
            return False
        except Exception:  # a dead socket surfaces as any number of types
            return False

    # -- the write path ----------------------------------------------------
    def send_block(self, block: CfgBlock) -> BlockResult:
        """Send one verified block, stopping at the first line that fails."""
        self._check_sendable(block)
        safe = transcript_lines(self.artifact, block)
        started = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()
        result = BlockResult(control_id=block.control_id, reverse=block.reverse,
                             dry_run=self.dry_run, started_at=started)

        # A 'banner motd' region is one interaction, not N commands: the lines
        # inside it are text the controller stores, and sending them one at a
        # time — waiting for a prompt that will not come until the delimiter
        # closes the region — is how the block gets sent as config instead.
        opens = dict(text_entry_regions(block.lines))
        i = 0
        while i < len(block.lines):
            end = opens.get(i)
            span = 1 if end is None else (end - i + 1)
            if self.dry_run:
                result.lines += [LineResult(command=s, output="", sent=False)
                                 for s in safe[i:i + span]]
            elif end is None:
                result.lines.append(self._send_line(block.lines[i], safe[i]))
            else:
                result.lines += self._send_text_region(block.lines, safe, i, end)
            if not result.lines[-1].ok:
                break  # never push more config on top of a command that failed
            i += span

        if block.lines and block.lines[0].startswith("cd ") and result.ok:
            self.node_path = block.node_path
        result.duration_ms = int((time.monotonic() - t0) * 1000)
        return result

    def _send_line(self, line: str, shown: str) -> LineResult:
        t0 = time.monotonic()
        try:
            raw, asked = self._connection.send_line(
                line, read_timeout=self.command_timeout_s)
        except TransportError:
            raise
        except Exception as e:  # netmiko read timeout, dropped session, ...
            return self._failed_line(shown, e, t0)

        if asked is not None:
            return self._captured_line(shown, raw, asked, t0)

        exit_kind, sig = classify_exit_kind(raw, echoed_command=line)
        return LineResult(
            command=shown, output=redact(raw).text, exit_kind=exit_kind,
            error_signature=sig,
            duration_ms=int((time.monotonic() - t0) * 1000))

    def _captured_line(self, shown: str, raw: str, asked: str,
                       t0: float) -> LineResult:
        """A line that opened a prompt instead of running.

        Cancelled here and not one line later. The session is not idle — it is
        holding a question open, and the block's next line, or the rollback, would
        be typed into it as the answer. Ctrl-C now is the difference between one
        command that did not work and a controller being fed configuration as a
        password.
        """
        self._connection.cancel()
        return LineResult(
            command=shown, output=redact(raw).text,
            exit_kind=ExitKind.INTERACTIVE,
            error_signature=f"prompted for input: {asked}",
            duration_ms=int((time.monotonic() - t0) * 1000))

    def _failed_line(self, shown: str, error: Exception, t0: float) -> LineResult:
        """A line that never came back. On a timeout, resynchronise first.

        A read timeout has two causes that look identical from here: a device
        that is slow, and a device that asked a question. The second is the one
        that has to be handled, because the session is then sitting at a prompt
        waiting for an answer — and whatever is written next, including the
        rollback, becomes that answer instead of being run.
        """
        etype = type(error).__name__
        timed_out = "timeout" in etype.lower()
        if timed_out:
            self._connection.cancel()
        return LineResult(
            command=shown, output="",
            exit_kind=ExitKind.TIMEOUT if timed_out else ExitKind.ERROR,
            error_signature=etype,
            duration_ms=int((time.monotonic() - t0) * 1000))

    def _send_text_region(self, lines: list[str], safe: list[str],
                          start: int, end: int) -> list[LineResult]:
        """Send one ``banner motd`` region: opener, text, closing delimiter.

        Reported as one result per physical line so the block's line accounting —
        which is what tells a partial application from a clean refusal — still
        matches the block that was reviewed. They share one outcome because the
        region has one outcome: either the whole banner was stored or none of it
        was.
        """
        t0 = time.monotonic()
        opener, terminator = lines[start], lines[end]
        try:
            raw, wrote = self._connection.send_text_block(
                opener, lines[start + 1:end], terminator,
                entered=self._entered_text_mode,
                read_timeout=self.command_timeout_s)
        except TransportError:
            raise
        except Exception as e:
            failed = self._failed_line(safe[start], e, t0)
            return [failed] + [LineResult(command=s, output="",
                                          exit_kind=failed.exit_kind,
                                          error_signature=failed.error_signature)
                               for s in safe[start + 1:end + 1]]

        if not wrote and (asked := self._connection.interactive_prompt(raw)):
            # The opener fell through to something that asks rather than stores.
            # Nothing was written after it, which is the whole reason the opener's
            # reply is inspected before the text — but the question is still open,
            # so it is cancelled here exactly as a single line would be.
            head = self._captured_line(safe[start], raw, asked, t0)
            return [head] + [LineResult(command=s, output="",
                                        exit_kind=head.exit_kind,
                                        error_signature=head.error_signature,
                                        sent=False)
                             for s in safe[start + 1:end + 1]]

        exit_kind, sig = classify_exit_kind(
            raw, echoed_command=terminator if wrote else opener)
        if not wrote and exit_kind in _ACCEPTED:
            # The opener came back without the CLI entering text mode. Nothing
            # was written after it, and this must not be reported as success:
            # the banner is not set, and the lines that would have set it were
            # one prompt away from being run as configuration.
            exit_kind, sig = ExitKind.ERROR, "text entry was not entered"

        head = LineResult(command=safe[start], output=redact(raw).text,
                          exit_kind=exit_kind, error_signature=sig,
                          duration_ms=int((time.monotonic() - t0) * 1000))
        return [head] + [LineResult(command=s, output="", exit_kind=exit_kind,
                                    error_signature=sig, sent=wrote)
                         for s in safe[start + 1:end + 1]]

    def _entered_text_mode(self, reply: str) -> bool:
        """Did the opener actually put the CLI into text entry?

        Three ways to answer no, and all of them have to be checked: the
        controller said the command was wrong; it said nothing wrong but handed
        the prompt straight back, which is the same thing arriving quietly; or it
        asked a question, which looks the most like text entry of the three and is
        the worst to get wrong. Text entry and a password prompt both swallow
        whatever is written next without echoing a verdict — the difference is
        that one stores the banner and the other reads it as credentials.
        """
        kind, _ = classify_exit_kind(reply)
        if kind not in _ACCEPTED or self._connection.at_prompt(reply):
            return False
        return self._connection.interactive_prompt(reply) is None

    def _check_sendable(self, block: CfgBlock) -> None:
        """Everything that can refuse a block happens here, before line one.

        Refusing part-way through a block would leave exactly the half-applied
        state the whole design exists to avoid, so nothing is sent until every
        line has passed.
        """
        if tuple(block.lines) not in self._allowed:
            raise ApplyRefused(
                f"{block.control_id}: these commands are not part of the verified "
                "artifact. Only blocks read out of the reviewed file can be sent.")
        if block.incomplete:
            raise ApplyRefused(
                f"{block.control_id}: the block is incomplete and would apply as a "
                "partial change.")
        text = block.text_indexes
        for i, (line, shown) in enumerate(
                zip(block.lines, transcript_lines(self.artifact, block))):
            if i in text:
                continue  # banner text: stored, not run, so it is not a command
            if is_destructive(line):
                raise ApplyRefused(
                    f"{block.control_id}: refusing to send a destructive command: "
                    f"{shown!r}.")
            if prompts_for_confirmation(line):
                raise ApplyRefused(
                    f"{block.control_id}: refusing to send {shown!r} — it asks for "
                    "confirmation, and the next line of the block would answer it "
                    "rather than run. Apply this one by hand.")
        if not self.dry_run and not self._connection.is_open:
            raise TransportError("session is not connected")
