"""Validate a command line against a controller's own CLI grammar, without
running it.

The trick is that '?' is answered by the ArubaOS parser immediately, on the
*unsubmitted* line: it prints the completions for what you have typed so far and
leaves your text in the input buffer. So this writes ``<line> ?`` with NO
newline, reads the answer, and sends ctrl-U to wipe the line. Nothing is ever
executed, and ``show configuration pending`` stays exactly as it was.

The one thing to know before trusting it: appending '?' to a *whole* line does
not report a bad argument. The parser answers the part it liked and ignores the
rest, so 'ssh disable-ciphers hmac-sha1-96 ?' looks healthy. Validation has to
walk the line token by token instead. The first version of this tool did the
whole-line check and reported the catalog clean; the token walk found six real
defects in the same catalog ten minutes later.
"""

from __future__ import annotations

import re
import time
from collections import Counter

# A numeric slot, in either spelling AOS uses: '<1-65535>' and '<-23 - 23>'.
_RANGE = re.compile(r"<\s*(-?\d+)\s*-\s*(-?\d+)\s*>")

# Stand-ins tried where the catalog wrote a placeholder. Which one is tried
# first is a hint read off what the parser said it wants; the hint is not
# trusted, each candidate is offered to the parser until one is accepted.
_SPECIMENS = ("aos8audit", "1", "10.0.0.1", "255.255.255.0")


class CliGrammar:
    """Asks a controller what it would accept, one token at a time."""

    def __init__(self, conn):
        self.conn = conn        # aos8_auditor.transport.connection.Connection
        self._c = conn._conn    # the netmiko handle

    # -- the primitive -----------------------------------------------------
    def _drain(self, settle: float = 0.45, first_byte: float = 6.0) -> str:
        """Read until the controller stops talking.

        Two clocks, deliberately. Waiting for the first byte is a different
        problem from deciding the reply has ended, and collapsing them into one
        settle window meant a controller that took longer than the window to
        begin rendering a 10 KB completion list came back as *empty*. That reads
        exactly like a legitimately empty list, which this tool interprets as
        'the grammar had nothing to say here' and waves the token through. A
        flaky read that fails toward 'valid' is the one failure mode a validator
        cannot have.
        """
        out, deadline = "", time.monotonic() + first_byte
        while not out and time.monotonic() < deadline:
            chunk = self._c.read_channel()
            if chunk:
                out += chunk
            else:
                time.sleep(0.05)
        last = time.monotonic()
        while time.monotonic() - last < settle:
            chunk = self._c.read_channel()
            if chunk:
                out += chunk
                last = time.monotonic()
            else:
                time.sleep(0.05)
        return out

    def _clear_line(self) -> None:
        """Ctrl-U wipes the pending input so nothing is left to be submitted."""
        self._c.write_channel("\x15")
        time.sleep(0.15)
        self._c.read_channel()

    def help_for(self, line: str) -> str:
        """Completions for ``line``, with nothing submitted.

        Note the absence of a newline. An earlier version of this used netmiko's
        send_command_timing, which appends one — so every probe also *ran* the
        line it was asking about, and the pending configuration filled up with
        half-finished commands.
        """
        for _ in range(2):
            self._clear_line()
            self._c.write_channel(line + " ?")
            raw = self._drain()
            self._clear_line()
            # The parser always echoes the line back before answering. Nothing
            # at all means the read failed, not that the grammar is empty;
            # asking twice costs a second and removes a silent false clear.
            if raw.strip():
                return raw
        return raw

    def completions(self, line: str) -> list[str]:
        """The token names the parser offers after ``line``."""
        return self._parse_completions(self.help_for(line))

    # -- the check ---------------------------------------------------------
    def check(self, line: str) -> tuple[bool | None, str]:
        """``(verdict, what the parser said)``. ``None`` means could not check.

        Walks the line token by token, asking at each boundary whether the next
        token is one the grammar offers there. Errs toward saying yes where the
        grammar is genuinely permissive - a position offering a free-form value
        accepts anything - but never toward saying yes because the read failed.
        False alarms cost a human ten minutes; false clears reach a controller.

        Every prefix of a real command answers with *something*: completions, or
        '<cr>', or both. A prefix the parser cannot make sense of answers with
        nothing at all. So silence is a verdict, not a gap - which is what
        catches an argument in the wrong place, where the offending token sits
        at a position the grammar left open and only the *next* probe reveals
        the line has stopped being a command.
        """
        tokens = line.split()
        if not tokens:
            return False, "empty"
        prefix, stood_in = "", []
        for i, tok in enumerate(tokens):
            raw = self.help_for(prefix)
            if not raw.strip():
                return None, ("could not read the controller's answer after "
                              f"{prefix.strip()!r}")
            rows = self._parse_rows(raw)
            offered = [n for n, _ in rows if n != "<cr>"]
            if not offered:
                if any(n == "<cr>" for n, _ in rows):
                    return False, (
                        f"token {i + 1} {tok!r} is one token too many: "
                        f"{prefix.strip()!r} is already a complete command and "
                        "takes no argument")
                return False, (
                    f"the parser offers nothing after {prefix.strip()!r} - not "
                    "even <cr>, which every prefix of a real command answers "
                    f"with. Token {i} is where this stops being a command.")

            if self._is_placeholder(tok):
                if not any(self._is_value_slot(o) for o in offered):
                    return False, (
                        f"token {i + 1} {tok!r} is a placeholder, but after "
                        f"{prefix.strip()!r} the grammar accepts only keywords: "
                        f"{sorted(offered)}")
                stand_in = self._resolve(prefix, tok, rows)
                if stand_in is None:
                    return None, (
                        f"no stand-in value for {tok!r} was accepted after "
                        f"{prefix.strip()!r}, so the rest of the line could not "
                        "be checked")
                stood_in.append(f"{tok}={stand_in}")
                prefix = f"{prefix} {stand_in}".strip()
                continue

            if not any(self._is_value_slot(o) for o in offered):
                if not any(o == tok or o.startswith(tok) for o in offered):
                    return False, (f"token {i + 1} {tok!r} is not valid after "
                                   f"{prefix.strip()!r}; offered: {sorted(offered)}")
            prefix = f"{prefix} {tok}".strip()

        note = f" (stand-ins: {', '.join(stood_in)})" if stood_in else ""
        tail = self.help_for(prefix)
        if not tail.strip():
            return None, "could not read the controller's answer at end of line" + note
        rows = self._parse_rows(tail)
        if not rows:
            # The last token sat in a slot the grammar left open, and the parser
            # has nothing to say about the result. Same silence, same verdict.
            return False, ("the parser offers nothing after the whole line: the "
                           "final token is not accepted where it stands" + note)
        if any(n == "<cr>" for n, _ in rows):
            return True, "complete" + note
        return True, "incomplete - the grammar wants more tokens" + note

    # -- standing in for the catalog's placeholders -------------------------
    @staticmethod
    def _is_placeholder(tok: str) -> bool:
        """A catalog stand-in like '<site-ip>', not something typed literally."""
        return tok.startswith("<") and tok.endswith(">") and len(tok) > 2

    def _resolve(self, prefix: str, placeholder: str,
                 rows: list[tuple[str, str]]) -> str | None:
        """A concrete value the parser accepts where the catalog wrote a slot.

        Tried against the controller, not guessed, because a stand-in that the
        parser rejects is worse than none: the prefix carrying it is unparseable
        from that point on, so every remaining token goes unexamined while the
        line still reports as walked. That is precisely how '<site-ip>' hid the
        rest of 'ip address <site-ip> <mask>' - and how a wrong argument order
        four tokens deep stayed invisible.
        """
        for candidate in self._specimen_order(rows, placeholder):
            raw = self.help_for(f"{prefix} {candidate}".strip())
            if raw.strip() and self._parse_rows(raw):
                return candidate
        return None

    @staticmethod
    def _specimen_order(rows: list[tuple[str, str]], placeholder: str) -> tuple[str, ...]:
        """``_SPECIMENS``, most-likely first for this slot. Only an ordering."""
        blob = " ".join(f"{n} {d}" for n, d in rows).lower()
        hint = placeholder.strip("<>").lower()
        if "mask" in blob or "mask" in hint:
            first = "255.255.255.0"
        elif re.search(r"\ba\.b\.c\.d\b|<ip", blob) or "ip address" in blob:
            first = "10.0.0.1"
        elif _RANGE.search(blob) or "number" in blob or "identifier" in blob:
            first = "1"
        else:
            first = "aos8audit"
        return (first, *[s for s in _SPECIMENS if s != first])

    # -- reading what the parser printed -----------------------------------
    @staticmethod
    def _is_value_slot(tok: str) -> bool:
        """A completion standing for 'any value here' rather than a literal.

        AOS spells these several ways - '<name>', 'A.B.C.D', 'WORD', '1-4094' -
        and getting it wrong produces false alarms, so the test is generous.
        """
        return (tok.startswith("<")
                or (tok.upper() == tok and any(ch.isalpha() for ch in tok))
                or bool(re.fullmatch(r"[A-Z](\.[A-Z])+", tok))
                or bool(re.fullmatch(r"\d+(-\d+)?", tok)))

    @staticmethod
    def _parse_rows(raw: str) -> list[tuple[str, str]]:
        """``(name, description)`` per row of the two-column help.

        The split is by *column*, not by gap width. ArubaOS pads each name into
        a fixed column, so a name long enough to fill it is followed by a single
        space -- 'deny-inter-user-traffic Disallow forwarding any frames...'.
        Requiring two spaces made every such name invisible and reported the
        commands that use them as rejected by the controller. That is the worst
        way for this tool to be wrong: it argues for breaking a correct line.

        A name can itself contain a space. 'cp-bandwidth-contract untrusted-ucast'
        answers with '<1-65535> pps' -- a number, in units of pps, not the word
        'pps' followed by a number. The gap-width version read that row as
        nothing at all, and silence was being counted as consent, so the catalog
        kept a line the parser refuses.
        """
        # Table rows are flush left. Description continuations are indented, and
        # the prompt line is bracketed.
        lines = [ln.rstrip() for ln in raw.splitlines()]
        rows = [ln for ln in lines
                if ln and not ln[0].isspace() and not ln.startswith("(")]

        # Where the description column starts, learned from the rows that show
        # it: the earliest run of two or more spaces that has a name in front.
        widths = Counter()
        for ln in rows:
            m = re.match(r"^.*?\S\s{2,}(?=\S)", ln)
            if m:
                widths[m.end()] += 1
        col = widths.most_common(1)[0][0] if widths else 0

        # The parser echoes the typed line back, both above the table and after
        # the prompt below it. Neither is a completion.
        tail = next((ln for ln in reversed(lines) if ln.lstrip().startswith("(")), "")

        out: list[tuple[str, str]] = []
        for ln in rows:
            if col and len(ln) > col and ln[col - 1] == " " and ln[col] != " ":
                name, desc = ln[:col].rstrip(), ln[col:]
            else:
                m = re.match(r"^(.*?\S)\s{2,}(\S.*)$", ln)
                if m:
                    name, desc = m.group(1), m.group(2)
                elif len(ln.split()) == 1:
                    # No description. Existing object names are listed this way
                    # ('default', 'internal'), and so is the echoed input line --
                    # hence the single-token test, since an echo is a whole typed
                    # line and is almost never one word.
                    name, desc = ln, ""
                else:
                    continue
            if not desc and tail.rstrip().endswith(name):
                continue                                 # a one-word echo
            out.append((name, desc.strip()))
        return out

    @staticmethod
    def _parse_completions(raw: str) -> list[str]:
        """The names the parser offers as a next token, '<cr>' excluded.

        '<cr>' means 'this line is already complete'. It is not a token that can
        be typed, and letting it through as a completion would make
        _is_value_slot treat the position as free-form and wave any argument
        past -- the exact false clear this tool exists to stop.
        """
        return [n for n, _ in CliGrammar._parse_rows(raw) if n != "<cr>"]
