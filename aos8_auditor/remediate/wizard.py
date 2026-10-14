"""The operator-facing wizard: one change per page, keyboard-driven.

Two front ends over the same :class:`~.session.Session`. The curses one is what an
operator uses at a terminal; the line-based one is what runs when stdout is a pipe,
a CI log, or a terminal curses cannot drive. Neither holds any decision logic —
they translate keystrokes into session calls and render what the session says.

``curses`` is in the standard library, which is the whole reason it is used here:
this tool is pasted onto jump hosts, and a hardening auditor that needs a package
index before it can run is a hardening auditor that does not get run.
"""

from __future__ import annotations

import curses
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path

from .emit import ExportOptions, ExportResult, write_artifacts
from .plan import BAND_TITLE, ChangeState, ImpactBand, RemediationPlan
from .session import DEFAULT_SUPPRESSION_DAYS, Session
from .suppress import entries_from_plan, write_suppressions

_STATE_MARK = {
    ChangeState.PENDING: " ",
    ChangeState.ACCEPTED: "+",
    ChangeState.SKIPPED: "-",
}

_HELP = [
    ("left / right", "previous / next change (p / n also work)"),
    ("up / down", "move between the values you supply (tab / shift-tab too)"),
    ("pgup / pgdn / space", "scroll a long page"),
    ("enter", "edit the highlighted value"),
    ("y", "accept this change"),
    ("s", "skip it, with a reason and optionally as expiring risk"),
    ("S", "skip it with no reason at all"),
    ("a", "accept every change that disrupts nothing"),
    ("^E", "unlock the generated lines for hand editing"),
    ("^R", "reset this change to what the guide says"),
    ("o", "overview"),
    ("r", "review and export"),
    ("e", "write the files (from the review page)"),
    ("^A", "write the files AND apply them to the controller"),
    ("esc", "back out of this page, or cancel what you are typing"),
    ("q", "quit without writing anything"),
]

# ncurses waits this long after an ESC to see whether a key sequence follows.
# The default is a full second, which is why ESC feels like it did not register.
_ESC_DELAY_MS = 25


def run(plan: RemediationPlan, out_dir: str | Path, *,
        operator: str | None = None,
        suppressions_path: str | Path | None = None,
        force_plain: bool = False,
        apply_hook: Callable[[Path], int] | None = None,
        apply_on_export: bool = False) -> ExportResult | None:
    """Walk the operator through ``plan`` and write the artifacts they approve.

    Returns the export result, or ``None`` if they quit without exporting.

    ``apply_hook`` is what ^A calls, and what an export calls when
    ``apply_on_export`` is set. It receives the directory that was just written
    and is expected to do its own asking; this module knows nothing about
    controllers and deliberately keeps it that way.
    """
    session = Session(plan)
    if not session.total and not plan.manual:
        print("Nothing to remediate: no failing or warning control has a fix.")
        return None
    if force_plain or not _interactive():
        return _run_plain(session, out_dir, operator, suppressions_path,
                          apply_hook, apply_on_export)
    try:
        return curses.wrapper(lambda scr: _Curses(
            scr, session, Path(out_dir), operator, suppressions_path,
            apply_hook, apply_on_export).loop())
    except curses.error as exc:
        print(f"terminal too limited for the full wizard ({exc}); "
              "falling back to prompts.\n", file=sys.stderr)
        return _run_plain(session, out_dir, operator, suppressions_path,
                          apply_hook, apply_on_export)


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


# --------------------------------------------------------------------------
# shared rendering
# --------------------------------------------------------------------------

def _wrap(text: str, width: int, indent: str = "") -> list[str]:
    return textwrap.wrap(text, width=max(20, width), initial_indent=indent,
                         subsequent_indent=indent) or [indent]


def _change_lines(session: Session, width: int) -> list[tuple[str, str]]:
    """The body of a change page as (style, text) pairs."""
    c = session.current
    if c is None:
        return [("dim", "no change selected")]
    out: list[tuple[str, str]] = []
    out.append(("title", f"{c.control_id} — {c.title}"))
    out.append(("dim", f"{c.severity.value} · {c.category_label} · "
                       f"change {session.position}"))
    out.append(("", ""))

    style = "ok" if c.band is ImpactBand.NONE else (
        "warn" if c.band is ImpactBand.CLIENT else "bad")
    out.append((style, BAND_TITLE[c.band]))
    if c.impact and c.impact.detail:
        out += [("dim", ln) for ln in _wrap(c.impact.detail, width - 2, "  ")]
    out.append(("", ""))

    if c.finding.observed:
        out += [("dim", ln) for ln in _wrap(f"Observed: {c.finding.observed}",
                                            width - 2, "  ")]
        out.append(("", ""))

    out.append(("head", "Configuration this will write"))
    for i in range(len(c.commands)):
        mark = " [hand-edited]" if c.is_hand_edited(i) else ""
        out.append(("cmd", f"  {c.line(i, mask_secrets=True)}{mark}"))
    out.append(("", ""))

    if c.fields:
        out.append(("head", "Values you supply"))
        for i, f in enumerate(c.fields):
            cursor = ">" if i == session.field_index else " "
            state = "" if f.filled else "  (empty)"
            style = "sel" if i == session.field_index else ""
            out.append((style, f" {cursor} {f.placeholder:<28} {f.display()}{state}"))
            if i == session.field_index:
                out += [("dim", ln) for ln in _wrap(f.hint, width - 6, "      ")]
                suggestions = session.suggestions()
                if suggestions:
                    joined = ", ".join(suggestions[:8])
                    if len(suggestions) > 8:
                        joined += f", … ({len(suggestions)} in the config)"
                    out += [("dim", ln) for ln in
                            _wrap(f"in this config: {joined}", width - 6, "      ")]
        out.append(("", ""))

    for note in c.notes:
        style = "warn" if note.strip().upper().startswith("RISK") else "dim"
        out += [(style, ln) for ln in _wrap(f"note: {note}", width - 2, "  ")]
    if c.partial:
        out += [("warn", ln) for ln in _wrap(
            "note: part of this control's guidance is prose that could not be "
            "turned into commands — read the notes above before applying.",
            width - 2, "  ")]

    out.append(("", ""))
    if c.state is ChangeState.ACCEPTED:
        out.append(("ok", "ACCEPTED — will be written to remediation.cfg"))
    elif c.state is ChangeState.SKIPPED:
        tail = f", suppressed until {c.suppress_expires}" if c.suppress_expires else ""
        out.append(("warn", f"SKIPPED{tail} — {c.skip_reason or 'no reason recorded'}"))
    else:
        blocked = c.blocking_reason(session.plan.context)
        out.append(("dim", f"undecided — {blocked}" if blocked
                    else "undecided — press y to accept, s to skip"))
    if session.summary()["pending"] == 0:
        out += [("", ""), ("head", "Every change is decided. Press r to review, "
                                   "then e to write the files.")]
    return out


def _overview_lines(session: Session, width: int) -> list[tuple[str, str]]:
    plan = session.plan
    s = session.summary()
    out: list[tuple[str, str]] = [
        ("title", "Guided remediation"),
        ("dim", f"{s['total']} change(s) with a command form · "
                f"{s['manual']} applied by hand"),
        ("", ""),
    ]
    if s["score_now"] is not None:
        out.append(("head", f"Posture {s['score_now']:.1f} → "
                            f"{s['score_projected']:.1f} if everything accepted lands"))
        out.append(("", ""))

    for band in (ImpactBand.NONE, ImpactBand.CLIENT, ImpactBand.AP, ImpactBand.CONTROLLER):
        group = [c for c in session.queue if c.band is band]
        if not group:
            continue
        style = "ok" if band is ImpactBand.NONE else (
            "warn" if band is ImpactBand.CLIENT else "bad")
        out.append((style, BAND_TITLE[band]))
        for c in group:
            i = session.queue.index(c)
            cursor = ">" if i == session.index else " "
            title = c.title if len(c.title) < width - 46 else c.title[:width - 49] + "…"
            out.append(("sel" if i == session.index else "",
                        f" {cursor} [{_STATE_MARK[c.state]}] {c.control_id:<38} {title}"))
        out.append(("", ""))

    out.append(("dim", f"accepted {s['accepted']} · skipped {s['skipped']} · "
                       f"undecided {s['pending']}"))
    if s["pending"] == 0:
        out.append(("head", "Every change is decided — press r to review and export."))
    return out


def _review_lines(session: Session, width: int, export_key: str = "e",
                  apply_key: str | None = None) -> list[tuple[str, str]]:
    s = session.summary()
    out: list[tuple[str, str]] = [("title", "Review"), ("", "")]
    out.append(("head", f"{s['accepted']} change(s) will be written to remediation.cfg"))
    for band, n in s["bands"].items():
        out.append(("dim", f"   {n} · {BAND_TITLE[ImpactBand(band)]}"))
    out.append(("", ""))
    if s["score_now"] is not None:
        out.append(("", f"Posture {s['score_now']:.1f} → {s['score_projected']:.1f}"))
        out.append(("", ""))
    for w in session.export_warnings():
        out += [("warn", ln) for ln in _wrap(f"! {w}", width - 2)]
    if not session.export_warnings():
        out.append(("ok", "no warnings"))
    out.append(("", ""))
    out.append(("head", f"Press {export_key} to write the files."))
    if apply_key:
        host = session.plan.context.host or "the controller"
        out.append(("head", f"Press {apply_key} to write them and apply them to "
                            f"{host} — you will be asked to confirm."))
        out.append(("dim", "Applying sends one block at a time and never runs "
                           "'write memory', so a reboot is still the way back."))
    else:
        out.append(("dim", "Nothing is sent to the controller here — this writes "
                           "remediation.cfg and stops."))
        out.append(("dim", "Applying it is a separate, opt-in command, printed once "
                           "the files exist."))
    out.append(("dim", "o for the overview, esc to go back, q to quit without writing."
                if export_key == "e" else
                "v for the overview, q to quit without writing."))
    return out


# --------------------------------------------------------------------------
# export, shared by both front ends
# --------------------------------------------------------------------------

def _do_export(session: Session, out_dir: Path, operator: str | None,
               suppressions_path: str | Path | None,
               include_secrets: bool,
               with_next_steps: bool = True) -> tuple[ExportResult, list[str]]:
    opts = ExportOptions(include_secrets=include_secrets, operator=operator)
    result = write_artifacts(session.plan, out_dir, opts)
    messages = [
        f"remediation.cfg  {result.remediation_cfg}",
        f"rollback.cfg     {result.rollback_cfg}",
        f"remediation.json {result.remediation_json}",
    ]
    entries = entries_from_plan(session.plan)
    if entries and suppressions_path:
        path = write_suppressions(suppressions_path, entries)
        messages.append(f"suppressions     {path} ({len(entries)} entry/entries)")
    elif entries:
        messages.append(f"{len(entries)} skip(s) marked as accepted risk were NOT "
                        "recorded: no --suppressions path was given")
    if include_secrets:
        messages.append("remediation.cfg contains secrets in clear text. It is mode "
                        "0600; delete it once the change is applied.")
    if with_next_steps:
        messages += _next_steps(session, out_dir)
    return result, messages


def _next_steps(session: Session, out_dir: Path) -> list[str]:
    """What to do with the files, spelled out.

    The wizard ends by writing three files, which is a fine place to stop and a
    terrible place to be left: the natural reading of "I accepted 12 changes" is
    that 12 changes happened. Nothing was sent, and the way to send it is a
    different command with different flags — so it gets printed here rather than
    left in the README.
    """
    host = session.plan.context.host or "<controller>"
    apply_cmd = f"aos8-audit --remediate-apply {out_dir} --host {host} --username <admin>"
    return [
        "",
        "NOT APPLIED. Nothing has been sent to the controller.",
        "Read remediation.cfg, then either paste it yourself or apply it:",
        f"  {apply_cmd} --remediate-dry-run   # rehearse; contacts nothing",
        f"  {apply_cmd} --password-env AOS_PW  # apply, one block at a time",
    ]


# --------------------------------------------------------------------------
# line-based front end
# --------------------------------------------------------------------------

def _run_plain(session: Session, out_dir: str | Path, operator: str | None,
               suppressions_path: str | Path | None,
               apply_hook: Callable[[Path], int] | None = None,
               apply_on_export: bool = False) -> ExportResult | None:
    """Prompt-driven wizard, for pipes, CI logs and limited terminals."""
    out = sys.stdout

    def show(lines: list[tuple[str, str]]) -> None:
        out.write("\n".join(text for _, text in lines) + "\n")

    def ask(prompt: str) -> str:
        out.write(prompt)
        out.flush()
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        return line.rstrip("\n")

    try:
        while True:
            show(_change_lines(session, 78))
            if not session.summary()["pending"]:
                out.write("\nEvery change is decided. Press x to write the files.\n")
            out.write("\n[y]accept [s]kip [f]ield [e]dit line [r]eset "
                      "[n]ext [p]rev [v]iew all [x]export "
                      + ("[a]pply " if apply_hook else "") + "[q]uit\n")
            choice = ask("> ").strip().lower()
            if choice in ("q", "quit"):
                return None
            if choice in ("n", ""):
                session.next_pending()
            elif choice == "p":
                session.prev()
            elif choice == "y":
                print(session.accept())
                if session.current and session.current.state is ChangeState.ACCEPTED:
                    session.next_pending()
            elif choice == "s":
                _plain_skip(session, ask)
            elif choice == "f":
                _plain_field(session, ask)
            elif choice == "e":
                _plain_edit(session, ask)
            elif choice == "r":
                print(session.reset())
            elif choice == "v":
                show(_overview_lines(session, 78))
            elif choice in ("x", "a"):
                applying = (choice == "a" or apply_on_export) and apply_hook is not None
                if choice == "a" and apply_hook is None:
                    print("no controller to apply to — re-run with --host "
                          "and --username")
                    continue
                if choice == "a" and not session.plan.accepted:
                    print("nothing accepted yet, so there is nothing to apply")
                    continue
                show(_review_lines(session, 78, export_key="x"))
                prompt = ("write the files and apply them? [y/N] " if applying
                          else "export now? [y/N] ")
                if ask(prompt).strip().lower() != "y":
                    continue
                secrets = _plain_secret_prompt(session, ask)
                result, messages = _do_export(session, Path(out_dir), operator,
                                              suppressions_path, secrets,
                                              with_next_steps=not applying)
                out.write("\n" + "\n".join(messages) + "\n")
                if applying:
                    apply_hook(Path(out_dir))
                return result
            else:
                print(f"unknown key {choice!r}")
    except (EOFError, KeyboardInterrupt):
        out.write("\nnothing written.\n")
        return None


def _plain_field(session: Session, ask) -> None:
    if not session.fields:
        print("this change has nothing to fill in")
        return
    for i, f in enumerate(session.fields):
        print(f"  {i + 1}. {f.placeholder:<28} {f.display()}")
    raw = ask("field number (blank to cancel): ").strip()
    if not raw.isdigit():
        return
    session.select_field(int(raw) - 1)
    f = session.current_field
    if f is None:
        return
    print(f"   {f.hint}")
    for s in session.suggestions()[:10]:
        print(f"   · {s}")
    value = ask(f"{f.placeholder} = ")
    result = session.set_field(value)
    print(("   " + result.message) if result.message else "")
    if not result.ok:
        print("   not accepted; the previous value stands")


def _plain_edit(session: Session, ask) -> None:
    c = session.current
    if c is None:
        return
    print(session.unlock_edit())
    for i in range(len(c.commands)):
        print(f"  {i + 1}. {c.line(i, mask_secrets=True)}")
    raw = ask("line number (blank to cancel): ").strip()
    if not raw.isdigit():
        return
    idx = int(raw) - 1
    text = ask(f"line {raw} = ")
    print(session.edit_line(idx, text))


def _plain_skip(session: Session, ask) -> None:
    reason = ask("reason (optional): ").strip()
    accept_risk = ask("record as accepted risk in suppressions.yaml? [y/N] ")
    if accept_risk.strip().lower() != "y":
        print(session.skip(reason))
        return
    days = ask(f"expires in how many days? [{DEFAULT_SUPPRESSION_DAYS}] ").strip()
    n = int(days) if days.isdigit() else DEFAULT_SUPPRESSION_DAYS
    print(session.skip(reason, suppress=True, days=n))


def _plain_secret_prompt(session: Session, ask) -> bool:
    secrets = session.plan.secret_fields()
    if not secrets:
        return False
    print(f"\n{len(secrets)} secret value(s) are part of these changes:")
    for c, f in secrets:
        print(f"   {c.control_id}  {f.placeholder}")
    print("Writing them puts them in clear text in remediation.cfg (mode 0600).")
    print("Declining comments those lines out and marks them FILL IN.")
    return ask("write secrets into remediation.cfg? [y/N] ").strip().lower() == "y"


# --------------------------------------------------------------------------
# curses front end
# --------------------------------------------------------------------------

class _Curses:
    """Thin renderer. Every decision goes through the session."""

    def __init__(self, screen, session: Session, out_dir: Path,
                 operator: str | None, suppressions_path: str | Path | None,
                 apply_hook: Callable[[Path], int] | None = None,
                 apply_on_export: bool = False):
        self.scr = screen
        self.session = session
        self.out_dir = out_dir
        self.operator = operator
        self.suppressions_path = suppressions_path
        self.apply_hook = apply_hook
        self.apply_on_export = apply_on_export
        self.view = "change"
        self.scroll = 0
        self.result: ExportResult | None = None
        self.styles: dict[str, int] = {}
        self._init_styles()

    def _init_styles(self) -> None:
        curses.curs_set(0)
        try:
            curses.set_escdelay(_ESC_DELAY_MS)
        except (AttributeError, curses.error):  # pragma: no cover - platform
            pass
        try:
            curses.start_color()
            curses.use_default_colors()
            for i, (name, fg) in enumerate((
                ("ok", curses.COLOR_GREEN), ("warn", curses.COLOR_YELLOW),
                ("bad", curses.COLOR_RED), ("head", curses.COLOR_CYAN),
                ("cmd", curses.COLOR_WHITE),
            ), start=1):
                curses.init_pair(i, fg, -1)
                self.styles[name] = curses.color_pair(i)
        except curses.error:
            pass
        self.styles.setdefault("ok", curses.A_NORMAL)
        self.styles.setdefault("warn", curses.A_BOLD)
        self.styles.setdefault("bad", curses.A_BOLD)
        self.styles.setdefault("head", curses.A_BOLD)
        self.styles.setdefault("cmd", curses.A_NORMAL)
        self.styles["title"] = curses.A_BOLD | self.styles.get("head", 0)
        self.styles["dim"] = curses.A_DIM
        self.styles["sel"] = curses.A_REVERSE
        self.styles[""] = curses.A_NORMAL

    # -- rendering -----------------------------------------------------
    def _body(self, width: int) -> list[tuple[str, str]]:
        if self.view == "overview":
            return _overview_lines(self.session, width)
        if self.view == "review":
            return _review_lines(self.session, width,
                                 apply_key="^A" if self.apply_hook else None)
        if self.view == "help":
            return [("title", "Keys"), ("", "")] + [
                ("", f"  {k:<18} {d}") for k, d in _HELP]
        return _change_lines(self.session, width)

    def draw(self) -> None:
        self.scr.erase()
        height, width = self.scr.getmaxyx()
        body = self._body(width - 2)
        room = max(1, height - 3)
        self.scroll = max(0, min(self._follow_selection(body, room),
                                 max(0, len(body) - room)))
        for row, (style, text) in enumerate(body[self.scroll:self.scroll + room]):
            self._put(row, text[:width - 1], self.styles.get(style, 0))
        # The rule doubles as the message row. A message that needs the operator
        # to do something about it sits where the rule was, in a colour, and the
        # keys below it stay where they were.
        notice = self._notice()
        if notice:
            self._put(height - 2, notice[:width - 1], self.styles["warn"])
        else:
            self._put(height - 2, "─" * (width - 1), self.styles["dim"])
        # Bold once there is nothing left to decide: the last line of a full
        # screen is easy to stop reading, and that is where the next step lives.
        done = not self.session.summary()["pending"]
        self._put(height - 1, self._status(width - 1)[:width - 1],
                  self.styles["head"] if done else self.styles["dim"])
        self.scr.refresh()

    def _follow_selection(self, body: list[tuple[str, str]], room: int) -> int:
        """Keep the highlighted row on screen when the arrows move it off.

        The overview is longer than a terminal on most runs, so an arrow key that
        moved an invisible cursor would look like a key that does nothing.
        """
        if self.view != "overview":
            return self.scroll
        rows = [i for i, (style, _) in enumerate(body) if style == "sel"]
        if not rows:
            return self.scroll
        row = rows[0]
        if row < self.scroll:
            return row
        if row >= self.scroll + room:
            return row - room + 1
        return self.scroll

    def _status(self, width: int | None = None) -> str:
        """The keys. Always on screen, whatever else has happened.

        This line used to be shared with whatever the last keystroke had to say,
        so filling in a field replaced the only list of keys on the screen with
        a sentence about the field — and an operator who had just arrived at the
        wizard had no way of knowing there was anywhere to go next. Messages have
        their own row now (:meth:`_notice`); this one does not move.
        """
        s = self.session.summary()
        counts = (f"{s['accepted']} accepted · {s['skipped']} skipped · "
                  f"{s['pending']} undecided")
        apply_key = " · ^A apply" if self.apply_hook else ""
        if not s["pending"]:
            keys = (f"DONE — e write the files{apply_key} · r review · q quit")
        else:
            keys = (f"y accept · s skip · ←→ change · ↑↓ field · "
                    f"r review{apply_key} · ? keys · q quit")
        line = f"{counts}   |   {keys}"
        # Truncation eats the right-hand end, which is where '? keys' and 'q quit'
        # live — the two an operator needs precisely when they are stuck. On a
        # narrow terminal the keys win and the running count goes.
        return keys if width is not None and len(line) > width else line

    def _notice(self) -> str:
        """Whatever the last keystroke had to say, if it had anything."""
        return self.session.message

    def _put(self, row: int, text: str, attr: int = 0) -> None:
        try:
            self.scr.addstr(row, 0, text, attr)
        except curses.error:
            pass  # bottom-right cell; harmless and unavoidable in curses

    # -- input ---------------------------------------------------------
    def _prompt(self, label: str, *, mask: bool = False, initial: str = "") -> str | None:
        """One-line editor at the bottom. Returns None if cancelled."""
        height, width = self.scr.getmaxyx()
        buf = list(initial)
        curses.curs_set(1)
        try:
            while True:
                shown = ("•" * len(buf)) if mask else "".join(buf)
                self._put(height - 1, " " * (width - 1))
                self._put(height - 1, (label + shown)[:width - 1], curses.A_BOLD)
                self.scr.move(height - 1, min(len(label) + len(shown), width - 2))
                self.scr.refresh()
                ch = self.scr.getch()
                if ch in (27,):                      # ESC
                    return None
                if ch in (10, 13, curses.KEY_ENTER):
                    return "".join(buf)
                if ch in (curses.KEY_BACKSPACE, 127, 8):
                    if buf:
                        buf.pop()
                elif ch == 21:                        # ^U
                    buf.clear()
                elif 32 <= ch < 127:
                    buf.append(chr(ch))
        finally:
            curses.curs_set(0)

    def _confirm(self, question: str) -> bool | None:
        """Yes, no, or None for "escaped out of the question entirely".

        The third answer exists so that ESC can be silent. Answering *no* is a
        decision worth acknowledging on screen; backing out is the operator
        saying they did not mean to be here, and telling them so is noise.
        """
        answer = self._prompt(f"{question} [y/N] ")
        if answer is None:
            return None
        return answer.strip().lower().startswith("y")

    # -- loop ----------------------------------------------------------
    def loop(self) -> ExportResult | None:
        self.scr.keypad(True)
        while True:
            self.draw()
            ch = self.scr.getch()
            if self._handle(ch) is False:
                return self.result

    def _handle(self, ch: int) -> bool | None:
        s = self.session
        s.message = ""
        if ch in (ord("q"), ord("Q")):
            if self.result is None and s.plan.accepted and self._confirm(
                    "quit without writing anything?") is not True:
                return None
            return False
        if ch == 27:                                   # ESC
            # ESC means back, from anywhere, with nothing to say about it. Every
            # other page is one keystroke away from the change you were on, so
            # that is where it lands.
            self.view, self.scroll = "change", 0
        elif ch in (ord("?"), curses.KEY_F1):
            self.view = "help" if self.view != "help" else "change"
            self.scroll = 0
        elif ch == ord("o"):
            self.view = "overview"
            self.scroll = 0
        elif ch == ord("r"):
            self.view = "review"
            self.scroll = 0
        elif ch == curses.KEY_DOWN:
            self._move(1)
        elif ch == curses.KEY_UP:
            self._move(-1)
        elif ch in (curses.KEY_NPAGE, ord(" ")):
            self.scroll += 10
        elif ch == curses.KEY_PPAGE:
            self.scroll = max(0, self.scroll - 10)
        elif ch == ord("e"):
            # From the review page, or from anywhere once nothing is undecided —
            # the status bar offers it in that state, so it has to answer.
            if self.view == "review" or not s.summary()["pending"]:
                self._export()
                return False
            self.view, self.scroll = "review", 0
            s.message = "some changes are still undecided — press e again to export"
        elif ch in (ord("n"), curses.KEY_RIGHT):
            s.next()
            self.view, self.scroll = "change", 0
        elif ch in (ord("p"), curses.KEY_LEFT):
            s.prev()
            self.view, self.scroll = "change", 0
        elif ch == 9:                                  # tab
            s.next_field()
        elif ch == curses.KEY_BTAB:
            s.prev_field()
        elif ch in (10, 13, curses.KEY_ENTER):
            self._edit_field()
        elif ch == ord("y"):
            s.accept()
            if s.current and s.current.state is ChangeState.ACCEPTED:
                s.next_pending()
                self.view, self.scroll = "change", 0
            self._finished()
        elif ch == ord("s"):
            self._skip()
            self._finished()
        elif ch == ord("S"):
            # Not every skip has a story. Asking for one anyway is how you get
            # twelve changes skipped with the reason "n/a".
            s.skip("")
            s.next_pending()
            self._finished()
        elif ch == 1:                                  # ^A
            if self._apply():
                return False
        elif ch == 5:                                  # ^E
            self._hand_edit()
        elif ch == 18:                                 # ^R
            s.reset()
        elif ch == ord("a"):
            s.accept_all_hot()
            self._finished()
        return None

    def _move(self, step: int) -> None:
        """Up and down move *within* a page; left and right move between pages.

        On a change page the only list is the values the operator has to supply,
        so that is what the arrows step through — which also puts them next to
        the enter key that edits the one they land on. The overview is a list of
        changes, so there they move the change cursor. Review and help are prose
        and have nothing to select, so they scroll.
        """
        s = self.session
        forward = step > 0
        if self.view == "overview":
            s.next() if forward else s.prev()
        elif self.view == "change" and s.fields:
            s.next_field() if forward else s.prev_field()
        else:
            self.scroll = max(0, self.scroll + step)

    def _finished(self) -> None:
        """Deciding the last change is the end of the walk, so say so and show it.

        Without this the wizard looks identical on the last change as on the
        first, and the only thing left to press is one that was last mentioned
        on a help screen.
        """
        if self.session.summary()["pending"]:
            return
        self.view, self.scroll = "review", 0
        self.session.message = ("all changes decided — press e to write the files, "
                                "o to look again")

    def _edit_field(self) -> None:
        if self.view == "overview":
            self.view, self.scroll = "change", 0
            return
        f = self.session.current_field
        if f is None:
            self.session.message = "this change has nothing to fill in"
            return
        value = self._prompt(f"{f.placeholder} = ", mask=f.is_secret,
                             initial="" if f.is_secret else f.value)
        if value is None:
            return          # escaped out; the page comes back unchanged, which says it
        result = self.session.set_field(value)
        if not result.ok:
            self.session.message = f"not accepted — {result.message}"
        elif not result.warning:
            # A value that was simply taken says so by appearing in the change
            # above, which is where the operator is already looking. Echoing it
            # back reads like a state the wizard has gone into, and it is the
            # last thing on screen after the one key they most expect to be
            # transparent. A value taken *with a caveat* still speaks up.
            self.session.message = ""

    def _hand_edit(self) -> None:
        c = self.session.current
        if c is None or not c.commands:
            return
        self.session.unlock_edit()
        raw = self._prompt(f"edit which line? [1-{len(c.commands)}] ")
        if raw is None or not raw.strip():
            return          # escape, or enter on an empty line: both mean "no"
        if not raw.strip().isdigit():
            self.session.message = "that is not a line number"
            return
        i = int(raw.strip()) - 1
        if not 0 <= i < len(c.commands):
            self.session.message = "no such line"
            return
        text = self._prompt(f"line {i + 1} = ", initial=c.line(i))
        if text is None:
            return
        self.session.edit_line(i, text)

    def _skip(self) -> None:
        reason = self._prompt("skip — reason (optional): ")
        if reason is None:
            return
        if self._confirm("record as accepted risk in suppressions.yaml?") is not True:
            self.session.skip(reason)
            self.session.next_pending()
            return
        raw = self._prompt(f"expires in how many days? [{DEFAULT_SUPPRESSION_DAYS}] ")
        days = int(raw) if raw and raw.strip().isdigit() else DEFAULT_SUPPRESSION_DAYS
        self.session.skip(reason, suppress=True, days=days)
        if self.session.current and \
                self.session.current.state is ChangeState.SKIPPED:
            self.session.next_pending()

    def _export(self, *, then_apply: bool = False) -> None:
        include_secrets = False
        if self.session.plan.secret_fields():
            include_secrets = self._confirm(
                "write secrets in clear text into remediation.cfg?") is True
        apply_now = (then_apply or self.apply_on_export) and self.apply_hook is not None
        self.result, messages = _do_export(
            self.session, self.out_dir, self.operator,
            self.suppressions_path, include_secrets,
            # Printing "here is how to apply this" immediately above an apply
            # would be instructions for something already happening.
            with_next_steps=not apply_now)
        curses.endwin()
        print("\n".join(messages))
        if apply_now:
            self.apply_hook(self.out_dir)

    def _apply(self) -> bool:
        """^A — write the files, then push them. Returns True if the wizard ends.

        Exporting first is not a formality. What the applier verifies is the
        directory's own hash pin, so the artifact has to exist before there is
        anything to verify, and pressing this key can never send bytes that were
        not also written down.
        """
        if self.apply_hook is None:
            self.session.message = ("no controller to apply to — re-run with "
                                    "--host and --username")
            return False
        if not self.session.plan.accepted:
            self.session.message = "nothing accepted yet, so there is nothing to apply"
            return False
        answer = self._confirm(
            f"write the files and apply them to "
            f"{self.session.plan.context.host or 'the controller'}?")
        if answer is not True:
            # Escaping out is silent; saying "no" to the one key that reaches a
            # controller gets an answer, because it is worth being sure it heard.
            self.session.message = ("" if answer is None
                                    else "nothing written, nothing sent")
            return False
        self._export(then_apply=True)
        return True
