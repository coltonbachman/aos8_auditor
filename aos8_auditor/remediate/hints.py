"""Split a control's ``remediation_hint`` into command lines and prose notes.

Hints were written for a human reader, so a single string mixes runnable config
with commentary::

    configure terminal ; firewall ; deny-inter-user-traffic   OR per-SSID:
    wlan virtual-ap <name> ; deny-inter-user-traffic. The less-restrictive
    'deny-inter-user-bridging' blocks only non-IP traffic ...

The exported file is meant to be pasted into a config session, so the cost of the
two failure modes is not symmetric:

  * prose emitted as a command  -> the operator pastes English at a config prompt
  * a command emitted as a note -> the line is commented out and does nothing

The second is visible and harmless; the first defeats the entire point of the
artifact. So this parser is deliberately conservative: a segment is a command
only when nothing about it looks like prose, anything ambiguous becomes a note,
and once a note interrupts a command run every following segment is demoted too
(a note breaks the config-mode context, so we can no longer say where the
following lines would land).

Where the heuristic is wrong, ``data/remediation_recipes.yaml`` overrides it with
explicit lines for that control — see :mod:`aos8_auditor.remediate.recipes`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class SegmentKind(str, Enum):
    COMMAND = "command"  # safe to emit as a bare config line
    NOTE = "note"        # emitted as a '!' comment, never executed


@dataclass(frozen=True)
class Segment:
    kind: SegmentKind
    text: str
    # Why a command-looking segment was demoted; surfaced in the wizard and the
    # exported file so a reviewer can see what the parser declined to trust.
    reason: str | None = None

    @property
    def is_command(self) -> bool:
        return self.kind is SegmentKind.COMMAND


# Tokens that never appear in an ArubaOS config command but are unavoidable in
# English. 'no', 'any', 'host', 'enable', 'set' and 'group' are deliberately
# absent — all four are real command words in this catalog.
_STOPWORDS = frozenset("""
a an and the or to via with without from into onto per than then so if unless
because before after while during each every only also still just for in on at
of as by is are be was were been being will would shall should must may can
cannot it its this that these those they them their your our you we what which
when where why how not other another first next last ensure ensures confirm
confirms review reviews retire retires avoid avoids use uses using used note
notes prefer prefers keep keeps place places assign assigns remove removes
""".split())

# Exec-mode actions. Real commands, but they do not belong inside a
# 'configure terminal' block, so the wizard surfaces them as guidance.
_EXEC_VERBS = frozenset({
    "backup", "copy", "tar", "license", "show", "ping", "traceroute", "clear",
    "dir", "write", "ap-regroup", "ap-rename", "restore", "export", "import",
})
_EXEC_PREFIXES = ("clock set", "crypto pki csr")

# Never emitted, under any circumstance, even as part of a hint that asks for it.
# Phase 1 has no apply path, but the artifact it produces is Phase 2's allowlist,
# so the destructive verbs are excluded at the point the artifact is built rather
# than at the point it would be sent.
_DESTRUCTIVE_VERBS = frozenset({
    "reload", "halt", "boot", "delete", "erase", "format", "rename", "upgrade",
    "poweroff", "reboot",
})
_DESTRUCTIVE_PREFIXES = ("write erase",)

# Commands that stop and ask the operator a question instead of returning to the
# prompt. They are excluded for the same reason as the destructive verbs and one
# more besides: the next line of a pasted block becomes the *answer*, so a
# confirmation prompt does not merely stall a run, it silently consumes the
# command after it. 'controller-ip vlan' asks "This configuration change requires
# a reboot. Do you want to continue[y/n]:" — hardening guide, "Using the CLI".
_CONFIRMATION_PREFIXES = ("controller-ip vlan",)

# Commands that switch the CLI out of command interpretation and into raw text
# entry: the delimiter is a *single character*, the text follows on the lines
# after it, and the CLI stays in text mode until the delimiter appears again.
# 'banner motd ^ Authorized use only ^' is not a long-winded way of writing this
# — it is rejected outright ("% Invalid input detected at '^' marker."), which is
# how the defect this guards against reached a live controller. Any banner type,
# not just motd: the guide only documents motd, but the shape is the same for all
# of them and misreading one as a command is the expensive direction to be wrong.
_TEXT_ENTRY_RE = re.compile(r"(?i)^\s*banner\s+[a-z0-9_-]+\s+(<[^>]*>|\S)\s*$")

# Mode plumbing the emitter supplies itself: every exported block opens with
# 'configure terminal' and closes with 'end', and persisting is left to the
# operator. Dropping these here keeps them from being mistaken for the fix.
_STRUCTURAL = frozenset({
    "configure terminal", "configure t", "configure", "end", "write memory", "write mem",
})

# Commands that enter a config sub-mode. A block that ends on one of these is a
# context with nothing in it — the setting itself was prose the parser declined
# to trust — so the dangling opener is dropped rather than exported as a fix.
_CONTEXT_OPENERS = (
    "aaa authentication dot1x", "aaa authentication mgmt", "aaa authentication-server",
    "aaa password-policy", "aaa profile", "aaa server-group", "ap system-profile",
    "control-plane-security", "crypto dynamic-map", "crypto isakmp policy",
    "firewall", "interface", "ip access-list", "lcd-menu", "netdestination",
    "user-role", "vrrp", "web-server profile", "wlan ",
)

# `<approved text>` is a single field despite the space, so placeholders are
# atomic when tokenizing.
_TOKEN_RE = re.compile(r"<[^>]*>|\S+")
_PAREN_RE = re.compile(r"\(([^()]*)\)")
# ' -- ' introduces trailing commentary in this catalog; so does a sentence break.
_DASH_SPLIT_RE = re.compile(r"\s+--+\s+")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[a-z0-9>)\]'\"])\.\s+(?=[A-Z])")
# An alternative branches the command stream; keep the part before the marker.
_ALT_SPLIT_RE = re.compile(r"\s+(OR|AND)\s+")

_MAX_COMMAND_TOKENS = 10


def tokenize(text: str) -> list[str]:
    """Whitespace tokens, with ``<placeholders>`` kept whole."""
    return _TOKEN_RE.findall(text)


def is_destructive(line: str) -> bool:
    """True if ``line`` reboots, wipes or renames something.

    The parser already refuses these, but a recipe ``lines:`` override and an
    operator's own ^E edit both bypass the parser. The emitter re-checks every
    physical line it is about to write, because the artifact is what Phase 2 would
    replay — this is the last place the guarantee can be enforced.
    """
    tokens = [t.lower().strip(".") for t in tokenize(line.strip()) if not t.startswith("<")]
    if not tokens:
        return False
    head = tokens[0]
    if head == "no":  # 'no boot ...' disables, it does not boot
        return False
    return head in _DESTRUCTIVE_VERBS or " ".join(tokens).startswith(_DESTRUCTIVE_PREFIXES)


def prompts_for_confirmation(line: str) -> bool:
    """True if ``line`` stops and asks the operator a question.

    Checked in the same places and for the same reason as :func:`is_destructive`:
    the parser refuses these, but a recipe override or a hand edit does not go
    through the parser, and a block that pastes past a ``[y/n]`` prompt answers
    it with whatever command came next.
    """
    tokens = [t.lower().strip(".") for t in tokenize(line.strip()) if not t.startswith("<")]
    return bool(tokens) and " ".join(tokens).startswith(_CONFIRMATION_PREFIXES)


def text_entry_delimiter(line: str) -> str | None:
    """The delimiter ``line`` opens raw text entry with, or None if it does not.

    Placeholders count, so a block reads the same before and after the wizard
    fills it in: ``banner motd <delim>`` opens a region terminated by a line
    holding ``<delim>``, exactly as ``banner motd ^`` is terminated by ``^``.
    """
    m = _TEXT_ENTRY_RE.match(line)
    return m.group(1) if m else None


def text_entry_regions(lines: list[str]) -> list[tuple[int, int | None]]:
    """Locate raw-text regions as ``(opener index, terminator index or None)``.

    The opener is still a command. Everything from the line after it through the
    terminator is text the controller stores verbatim — not config, not subject
    to the command checks, and not safe to strip, reindent or comment out. A
    region with no terminator runs to the end of the block, which is what the
    device would do with it and is why the emitter refuses to send one.
    """
    out: list[tuple[int, int | None]] = []
    i = 0
    while i < len(lines):
        delim = text_entry_delimiter(lines[i])
        if delim is None:
            i += 1
            continue
        end = next((j for j in range(i + 1, len(lines)) if lines[j].strip() == delim), None)
        out.append((i, end))
        if end is None:
            break
        i = end + 1
    return out


def text_entry_spans(lines: list[str]) -> set[int]:
    """Indexes of ``lines`` that are text rather than commands."""
    spans: set[int] = set()
    for start, end in text_entry_regions(lines):
        spans.update(range(start + 1, (end + 1) if end is not None else len(lines)))
    return spans


def _demotion_reason(text: str) -> str | None:
    """Why ``text`` cannot be trusted as a command line, or None if it can."""
    s = text.strip()
    if not s:
        return "empty"
    if "..." in s or "…" in s:
        return "elided command"
    if "'" in s or '"' in s:
        return "quoted prose"
    if any(c in s for c in "{}|"):
        return "syntax template"
    if "," in s:
        return "sentence punctuation"
    if ":" in s:
        return "prose punctuation"

    tokens = tokenize(s)
    if len(tokens) > _MAX_COMMAND_TOKENS:
        return "too long for a command"
    if tokens[0][:1].isupper():
        return "starts a sentence"
    if "/" in tokens[0] or "<" in tokens[0]:
        return "not a command word"

    lowered = [t.lower().strip(".") for t in tokens if not t.startswith("<")]
    if any(t in _STOPWORDS for t in lowered):
        return "reads as prose"

    head = lowered[0] if lowered else ""
    joined = " ".join(lowered)
    if head in _DESTRUCTIVE_VERBS or joined.startswith(_DESTRUCTIVE_PREFIXES):
        return "destructive command — never exported"
    if head in _EXEC_VERBS or joined.startswith(_EXEC_PREFIXES):
        return "exec-mode action, not a config line"
    if prompts_for_confirmation(s):
        return "prompts for confirmation — the next line would answer it"
    return None


def _pieces(segment: str) -> list[str]:
    """Break one ';'-delimited segment at sentence and alternative boundaries."""
    out: list[str] = []
    for sentence in _SENTENCE_SPLIT_RE.split(segment):
        parts = _ALT_SPLIT_RE.split(sentence)
        # re.split with a capture group interleaves the markers; rebuild so the
        # marker stays attached to the alternative it introduces.
        out.append(parts[0])
        for i in range(1, len(parts), 2):
            out.append(f"{parts[i]} {parts[i + 1]}" if i + 1 < len(parts) else parts[i])
    return out


def parse_hint(hint: str | None) -> list[Segment]:
    """Parse a ``remediation_hint`` into ordered command/note segments."""
    if not hint or not hint.strip():
        return []

    notes: list[str] = []

    # 1. Parentheticals are commentary and can themselves contain ';', so they
    #    come out before anything is split.
    def _capture(m: re.Match) -> str:
        body = m.group(1).strip()
        if body:
            notes.append(body)
        return " "

    body = hint
    for _ in range(4):  # nested parens are not used in this catalog; bound it anyway
        body, n = _PAREN_RE.subn(_capture, body)
        if not n:
            break
    # Removing a parenthetical can strand whitespace in front of the sentence
    # break that follows it; close the gap so the sentence splitter still anchors.
    body = re.sub(r"\s+([.;])", r"\1", body)

    # 2. ' -- ' introduces trailing commentary for the whole hint.
    head, *tail = _DASH_SPLIT_RE.split(body, maxsplit=1)
    if tail:
        notes.insert(0, tail[0].strip())

    segments: list[Segment] = []
    demoted = False
    for raw in head.split(";"):
        for piece in _pieces(raw):
            text = piece.strip().rstrip(".").strip()
            if not text or text.lower() in _STRUCTURAL:
                continue
            reason = _demotion_reason(text)
            if reason is None and demoted:
                reason = "follows a note — config context is no longer known"
            if reason is None:
                segments.append(Segment(SegmentKind.COMMAND, text))
            else:
                demoted = True
                segments.append(Segment(SegmentKind.NOTE, text, reason))

    segments = _trim_dangling_openers(segments)
    segments += [Segment(SegmentKind.NOTE, n, "commentary") for n in notes if n]
    return segments


def _trim_dangling_openers(segments: list[Segment]) -> list[Segment]:
    """Drop trailing sub-mode openers (and stray ``exit``) with nothing under them."""
    out = list(segments)
    while out:
        last = next((i for i in range(len(out) - 1, -1, -1) if out[i].is_command), None)
        if last is None:
            break
        text = out[last].text.lower()
        if text != "exit" and not text.startswith(_CONTEXT_OPENERS):
            break
        out[last] = Segment(SegmentKind.NOTE, out[last].text,
                            "opens a config context the hint never filled in")
    return out


def command_lines(segments: list[Segment]) -> list[str]:
    """The command text, in order. Mode plumbing is already gone — the emitter
    opens and closes config mode around every block itself."""
    return [s.text for s in segments if s.is_command]


def note_lines(segments: list[Segment]) -> list[str]:
    return [s.text for s in segments if not s.is_command]


def is_actionable(segments: list[Segment]) -> bool:
    """True when the hint yielded at least one line worth pasting."""
    return bool(command_lines(segments))


def is_partial(segments: list[Segment]) -> bool:
    """True when some of the hint could not be turned into commands.

    A partial parse still exports, but the block is flagged so a reviewer knows
    the commented notes underneath it are part of the fix, not decoration.
    """
    return is_actionable(segments) and any(
        s.reason and s.reason != "commentary" for s in segments if not s.is_command)
