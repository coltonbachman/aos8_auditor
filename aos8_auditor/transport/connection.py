"""The SSH connection itself, with no opinion about what may be sent over it.

Split out of :mod:`ssh_session` when the apply path arrived. Two things now need
a connection — the read-only auditor and the remediation applier — and they have
opposite rules about what is allowed on it. Sharing the *policy* between them
would be a mistake; sharing the socket, the lazy netmiko import, the kwargs and
the error wrapping is just not writing it twice.

So this module holds none of the policy. It cannot decide whether a command is
safe and does not try; :class:`~.ssh_session.Session` gates on the read-only
catalog, and the apply path gates on a hash-verified artifact. A ``Connection``
on its own is a pipe, and the layer that holds it is what makes it an auditor or
an applier.

This is the only module that imports netmiko, and it does so lazily inside
:meth:`Connection.open` so the package and its tests import with no netmiko and
no device present.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ArubaOS 8 rewrites its own prompt as you move around the box, and netmiko's
# default is to wait for the prompt it saw *before* the command:
#
#     (WLC) [mynode] #                    exec
#     (WLC) [mynode] (config) #           after 'configure terminal'
#     (WLC) [00:1a:1e:...] #              after 'cd /md/...'
#
# So every command that changes mode or node times out waiting for a string the
# controller will never print again — reported as ReadTimeout, which reads like
# a slow or wedged device rather than a pattern that no longer matches. The
# hostname in the leading parentheses is the one part that does not move, so it
# is what we anchor on; everything after it is allowed to be whatever AOS feels
# like adding, including the '*'/'^' unsaved-configuration markers.
_PROMPT_TAIL = r"[>#]\s*$"
_HOSTNAME_RE = re.compile(r"\(([^)\n]+)\)")

# A configuration line with a bad argument does not always come back as an error.
# On ArubaOS some config keywords share a first token with an *exec* command, and
# the parser falls through to the exec one:
#
#     (WLC) (config) #ssh disable-ciphers hmac-sha1-96
#     Password:
#
# 'ssh' became the SSH client, which is now asking for a password. Nothing has
# failed — the CLI is holding the session open waiting for an answer, so the read
# runs out its full timeout and is reported as a dead device, and the next line
# written is consumed as the password. (Observed on 8.13.3.0; it is what turned a
# one-line syntax error into a stalled apply.)
#
# These patterns end the reply the way a real prompt does: last thing in the
# buffer, no newline after it. Anchoring on that is what keeps the word
# "password:" appearing *inside* a config dump from matching.
_INTERACTIVE_PROMPTS = (
    r"[Pp]assword\s*:",                       # ssh/telnet client, enable, ...
    r"(?:[Ll]ogin|[Uu]sername)\s*:",          # telnet client
    r"\[[Yy]/[Nn]\]\s*:?",                    # confirmation, bracketed
    r"\((?:[Yy]/[Nn]|[Yy]es/[Nn]o)\)\s*:?",   # confirmation, parenthesised
    r"[Aa]re you sure[^\n]*\?",               # confirmation, prose
)
_INTERACTIVE_RE = re.compile(
    r"(?:" + "|".join(_INTERACTIVE_PROMPTS) + r")[ \t]*\Z")


def interactive_prompt_pattern() -> str:
    """Regex matching a reply that ends at a prompt waiting for an answer."""
    return _INTERACTIVE_RE.pattern


def prompt_pattern(prompt: str) -> str:
    """A regex matching this controller's prompt in any mode it can be in."""
    found = _HOSTNAME_RE.search(prompt or "")
    if not found:
        # Nothing recognisable to anchor on; take any prompt-shaped line ending.
        # Looser than we would like, and still better than a pattern that is
        # guaranteed to stop matching the moment the operator enters config mode.
        return _PROMPT_TAIL
    return r"\(" + re.escape(found.group(1)) + r"\)[^\n]*" + _PROMPT_TAIL


@dataclass
class SSHConfig:
    host: str
    username: str
    key_file: str | None = None
    password: str | None = None
    port: int = 22
    device_type: str = "aruba_os"  # override per train if the prompt regex differs
    conn_timeout: int = 30
    default_read_timeout: int = 60
    proxy_jump: str | None = None  # bastion/jump host (wired through in a later phase)
    extra_netmiko_kwargs: dict = field(default_factory=dict)


class TransportError(RuntimeError):
    pass


def netmiko_kwargs(config: SSHConfig) -> dict:
    """Translate an :class:`SSHConfig` into netmiko's argument names."""
    kwargs = {
        "device_type": config.device_type,
        "host": config.host,
        "username": config.username,
        "port": config.port,
        "conn_timeout": config.conn_timeout,
        "read_timeout_override": config.default_read_timeout,
    }
    if config.key_file:
        kwargs["use_keys"] = True
        kwargs["key_file"] = config.key_file
    if config.password:
        kwargs["password"] = config.password
    kwargs.update(config.extra_netmiko_kwargs)
    return kwargs


class Connection:
    """An open SSH channel to one controller.

    Deliberately small: open, send text, read text, close. Every caller in this
    package wraps it in something that decides what is allowed to be sent.
    """

    def __init__(self, config: SSHConfig):
        self.config = config
        self._conn = None  # netmiko BaseConnection
        self.warnings: list[str] = []
        self._prompt: str | None = None  # regex; see prompt_pattern()

    @property
    def is_open(self) -> bool:
        return self._conn is not None

    def open(self) -> "Connection":
        try:
            from netmiko import ConnectHandler  # lazy: keeps package import-light
        except ImportError as e:  # pragma: no cover - depends on environment
            raise TransportError("netmiko is required for live collection") from e

        if self.config.proxy_jump:
            # ProxyJump via an ssh_config sock is wired in a later phase.
            self.warnings.append(
                "proxy_jump set but not yet implemented; connecting directly")

        try:
            self._conn = ConnectHandler(**netmiko_kwargs(self.config))
        except Exception as e:  # pragma: no cover - network dependent
            raise TransportError(f"failed to connect to {self.config.host}: {e}") from e
        self._learn_prompt()
        return self

    def _learn_prompt(self) -> None:
        """Ask the controller what its prompt looks like, once per connection."""
        try:
            self._prompt = prompt_pattern(self._conn.find_prompt())
        except Exception:  # pragma: no cover - depends on the device answering
            # Falling back to netmiko's own guess is fine for 'show' commands,
            # which is all this session can send unless it is an apply session.
            self._prompt = None

    def send(self, command: str, *, read_timeout: int | None = None) -> str:
        """Send one line and return the raw reply. No safety check happens here.

        Callers are expected to have decided already. The name has no underscore
        because hiding it would suggest this class enforces something it does not.
        """
        if self._conn is None:
            raise TransportError("session is not connected")
        extra = {"expect_string": self._prompt} if self._prompt else {}
        return self._strip_prompt(self._conn.send_command(
            command,
            read_timeout=read_timeout or self.config.default_read_timeout,
            **extra,
        ))

    def send_line(self, command: str, *,
                  read_timeout: int | None = None) -> tuple[str, str | None]:
        """Send one line; return ``(reply, the prompt it stopped at or None)``.

        Separate from :meth:`send` rather than a flag on it, because the answer
        depends on text that :meth:`send` throws away. "Ended at a question" and
        "asked a question and then finished" differ by exactly one line — the CLI
        prompt after it — and that is the line netmiko removes. Detecting this
        after the fact reads a controller that said "Are you sure?" and carried on
        as one that is sitting there waiting.

        It also widens what counts as a finished reply to include those prompts,
        so a command that fell through to an interactive one comes back at once
        instead of running out its full read timeout.

        Not used by the read-only path, and not worth switching on there: ``show``
        output arrives in multi-KB blocks that can contain the word "password:"
        part-way through, and returning early on that would truncate evidence.
        Replies here are one line of configuration.
        """
        if self._conn is None:
            raise TransportError("session is not connected")
        extra = {}
        if self._prompt:
            extra["expect_string"] = (
                f"(?:{self._prompt})|(?:{_INTERACTIVE_RE.pattern})")
        raw = self._conn.send_command(
            command,
            read_timeout=read_timeout or self.config.default_read_timeout,
            strip_prompt=False,
            **extra,
        )
        return self._strip_prompt(raw), self.interactive_prompt(raw)

    def send_text_block(self, opener: str, lines: list[str], terminator: str, *,
                        entered, read_timeout: int | None = None) -> tuple[str, bool]:
        """Send a command that opens raw text entry, then the text, then close it.

        ``banner motd ^`` does not take its text as an argument. It puts the CLI
        into a mode where every following line is stored verbatim until the
        delimiter appears alone, and the delimiter is one character — the
        one-line form is rejected outright.

        Returns ``(reply, wrote_text)``. The order of operations is the point:
        ``entered`` inspects the opener's reply *before* a byte of the text is
        written, because if the opener was rejected the CLI is still at a config
        prompt, and the banner's second line would be run as a command there. On
        a rejection nothing further is sent and ``wrote_text`` is False.

        ``entered`` is supplied by the caller: this module holds no policy about
        what a controller's reply means.
        """
        if self._conn is None:
            raise TransportError("session is not connected")
        timeout = read_timeout or self.config.default_read_timeout
        opened = self._conn.send_command_timing(
            opener, strip_prompt=False, strip_command=False, read_timeout=timeout)
        if not entered(opened):
            return self._strip_prompt(opened), False

        # Written without reading between them: from here the controller is
        # echoing text, not answering commands, so there is no per-line reply to
        # wait for. The terminator is the line that hands the prompt back.
        for line in lines:
            self._conn.write_channel(line + "\n")
        extra = {"expect_string": self._prompt} if self._prompt else {}
        closed = self._conn.send_command(
            terminator, read_timeout=timeout, cmd_verify=False, **extra)
        return self._strip_prompt(closed), True

    def cancel(self) -> None:
        """Interrupt whatever the CLI is waiting for and resynchronise.

        Sent after a read timeout, where the dangerous case is not a slow device
        but a device that asked a question. A pending prompt does not time out on
        the controller's side — it holds the session open, and the next thing
        written to the channel is read as the answer. Ctrl-C first means that
        thing is a cancellation rather than the next command.

        Best effort by construction: it runs when the session is already in an
        unknown state, so every failure here is swallowed.
        """
        if self._conn is None:
            return
        try:
            self._conn.write_channel("\x03")
            self._conn.write_channel("\n")
            self._conn.read_channel()
        except Exception:
            pass

    def interactive_prompt(self, text: str) -> str | None:
        """The prompt ``text`` ends at, if it is one waiting for an answer.

        Returns the matched prompt (for the operator's error message) or None.

        Checked *after* the CLI prompt, not instead of it: a controller is
        perfectly entitled to print "Are you sure?" as part of a reply and then
        hand the prompt back, and that has already finished. Only a reply that
        stops at the question is one where the session is still captured.
        """
        if self.at_prompt(text):
            return None
        found = _INTERACTIVE_RE.search((text or "").rstrip("\r\n") or "")
        return found.group(0).strip() if found else None

    def at_prompt(self, text: str) -> bool:
        """True if ``text`` ends at this controller's prompt.

        Which is to say: the CLI finished with that command and is waiting for
        the next one. False when there is no learned prompt to compare against —
        the callers of this treat "cannot tell" as "do not assume it finished".
        """
        if not self._prompt:
            return False
        lines = (text or "").splitlines()
        return bool(lines) and bool(re.search(self._prompt, lines[-1]))

    def _strip_prompt(self, text: str) -> str:
        """Drop a trailing prompt netmiko left behind.

        netmiko removes the prompt it was expecting, which it recognises by the
        one it learned at login. A command that moved the node — 'cd /md/...' —
        comes back with a prompt it does not recognise, and that line would then
        be stored as part of the command's output.
        """
        if not self._prompt:
            return text
        lines = text.splitlines()
        if lines and re.search(self._prompt, lines[-1]):
            return "\n".join(lines[:-1])
        return text

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            finally:
                self._conn = None
                self._prompt = None

    def __enter__(self) -> "Connection":
        return self.open()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
