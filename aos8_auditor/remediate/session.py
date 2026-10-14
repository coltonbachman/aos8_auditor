"""The wizard's state machine, with no screen attached.

Every decision an operator can make is a method here, and every method returns a
short result string the UI can display. Keeping it separate from curses is what
makes the interesting behaviour — a skip that must carry a reason, a field that
cannot hold an out-of-range VLAN, an edit that has to be unlocked first — testable
without a terminal.

The session owns *decisions*. It does not render and it does not write files;
:mod:`emit` does that from the plan the session hands back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta

from .fields import Field
from .plan import Change, ChangeState, ImpactBand, RemediationPlan
from .validate import ValidationResult, completions, validate

DEFAULT_SUPPRESSION_DAYS = 180
MIN_SKIP_REASON = 8  # characters; "no" is not a justification


@dataclass
class Session:
    """One operator's pass through one node's changes."""

    plan: RemediationPlan
    today: date = field(default_factory=date.today)

    index: int = 0                 # position in the queue
    field_index: int = 0           # position within the current change's fields
    edit_unlocked: bool = False    # ^E, reset on every navigation
    message: str = ""

    # -- the queue ---------------------------------------------------------
    @property
    def queue(self) -> list[Change]:
        """Actionable changes, in the order they will be emitted."""
        return self.plan.ordered(self.plan.actionable)

    @property
    def current(self) -> Change | None:
        q = self.queue
        return q[self.index] if 0 <= self.index < len(q) else None

    @property
    def total(self) -> int:
        return len(self.queue)

    @property
    def position(self) -> str:
        return f"{min(self.index + 1, self.total)}/{self.total}"

    @property
    def decided(self) -> int:
        return sum(1 for c in self.queue if c.state is not ChangeState.PENDING)

    @property
    def complete(self) -> bool:
        return self.decided == self.total

    # -- navigation --------------------------------------------------------
    def goto(self, index: int) -> str:
        self.index = max(0, min(index, max(self.total - 1, 0)))
        self.field_index = 0
        self.edit_unlocked = False  # never carries across changes
        return self._say("")

    def next(self) -> str:
        if self.index >= self.total - 1:
            return self._say("at the last change")
        return self.goto(self.index + 1)

    def prev(self) -> str:
        if self.index <= 0:
            return self._say("at the first change")
        return self.goto(self.index - 1)

    def next_pending(self) -> str:
        """Jump to the next undecided change, wrapping once."""
        q = self.queue
        order = list(range(self.index + 1, len(q))) + list(range(0, self.index + 1))
        for i in order:
            if q[i].state is ChangeState.PENDING:
                return self.goto(i)
        return self._say("every change has been decided")

    # -- fields ------------------------------------------------------------
    @property
    def fields(self) -> list[Field]:
        c = self.current
        return c.fields if c else []

    @property
    def current_field(self) -> Field | None:
        f = self.fields
        return f[self.field_index] if 0 <= self.field_index < len(f) else None

    def select_field(self, index: int) -> str:
        if not self.fields:
            return self._say("this change has nothing to fill in")
        self.field_index = max(0, min(index, len(self.fields) - 1))
        return self._say("")

    def next_field(self) -> str:
        return self.select_field(self.field_index + 1) if self.fields else self._say("")

    def prev_field(self) -> str:
        return self.select_field(self.field_index - 1) if self.fields else self._say("")

    def preview(self, value: str) -> ValidationResult:
        """Validate a keystroke-in-progress without committing it."""
        f = self.current_field
        if f is None:
            return ValidationResult(True)
        return validate(f, value, self.plan.context)

    def set_field(self, value: str, *, index: int | None = None) -> ValidationResult:
        """Commit a value. A blocked value is not stored — the old one stands."""
        fields = self.fields
        i = self.field_index if index is None else index
        if not (0 <= i < len(fields)):
            self.message = "no such field"
            return ValidationResult(False, "no such field")
        f = fields[i]
        result = validate(f, value, self.plan.context)
        if result.ok:
            f.value = value.strip() if f.type.value != "text" else value
            self._invalidate(f)
        self.message = result.message
        return result

    def clear_field(self, index: int | None = None) -> str:
        fields = self.fields
        i = self.field_index if index is None else index
        if 0 <= i < len(fields):
            fields[i].value = ""
            self._invalidate(fields[i])
            return self._say(f"cleared {fields[i].placeholder}")
        return self._say("no such field")

    def suggestions(self) -> list[str]:
        f = self.current_field
        return completions(f, self.plan.context) if f else []

    def _invalidate(self, f: Field) -> None:
        """A change stops being accepted the moment its inputs change."""
        c = self.current
        if c and c.state is ChangeState.ACCEPTED and not c.ready(self.plan.context):
            c.state = ChangeState.PENDING

    # -- hand editing ------------------------------------------------------
    def unlock_edit(self) -> str:
        """^E. Editing a generated line is allowed, but never by accident."""
        c = self.current
        if c is None:
            return self._say("nothing to edit")
        self.edit_unlocked = True
        return self._say("edit unlocked — your text replaces the guide's, and is "
                         "marked [hand-edited] in the export")

    def edit_line(self, line_index: int, text: str) -> str:
        c = self.current
        if c is None:
            return self._say("nothing to edit")
        if not self.edit_unlocked:
            return self._say("press ^E first — generated lines are locked by default")
        if not (0 <= line_index < len(c.commands)):
            return self._say("no such line")
        if "\n" in text or "\r" in text:
            return self._say("a config line cannot span lines")
        stripped = text.strip()
        if not stripped:
            return self.reset_line(line_index)
        c.hand_edited[line_index] = stripped
        if c.state is ChangeState.ACCEPTED and not c.ready(self.plan.context):
            c.state = ChangeState.PENDING
        return self._say(f"line {line_index + 1} hand-edited")

    def reset_line(self, line_index: int) -> str:
        c = self.current
        if c and line_index in c.hand_edited:
            del c.hand_edited[line_index]
            return self._say(f"line {line_index + 1} restored to the guide's wording")
        return self._say("that line is unmodified")

    def reset(self) -> str:
        """^R. Back to what the guide says, with every answer discarded."""
        c = self.current
        if c is None:
            return self._say("nothing to reset")
        c.hand_edited.clear()
        for f in c.fields:
            f.value = ""
        c.state = ChangeState.PENDING
        c.skip_reason = None
        c.suppress_expires = None
        self.field_index = 0
        self.edit_unlocked = False
        return self._say(f"{c.control_id} reset")

    # -- decisions ---------------------------------------------------------
    def accept(self) -> str:
        c = self.current
        if c is None:
            return self._say("nothing to accept")
        blocked = c.blocking_reason(self.plan.context)
        if blocked:
            return self._say(f"cannot accept — {blocked}")
        c.state = ChangeState.ACCEPTED
        c.selected = True
        c.skip_reason = None
        c.suppress_expires = None
        return self._say(f"{c.control_id} accepted")

    def skip(self, reason: str = "", *, suppress: bool = False,
             expires: str | None = None, days: int = DEFAULT_SUPPRESSION_DAYS) -> str:
        """Decline a change.

        A plain skip needs no justification — the operator may simply be doing it
        next week. Recording it as accepted risk does: a suppression hides a real
        failure from the score, so it carries a reason and an expiry date, and the
        expiry is not optional. Risk that never expires is risk nobody revisits.
        """
        c = self.current
        if c is None:
            return self._say("nothing to skip")
        reason = reason.strip()
        if suppress:
            if len(reason) < MIN_SKIP_REASON:
                return self._say("a suppression needs a real justification — it is "
                                 "what someone reads in six months")
            c.suppress_expires = expires or self._default_expiry(days)
        else:
            c.suppress_expires = None
        c.state = ChangeState.SKIPPED
        c.selected = False
        c.skip_reason = reason or None
        tail = f", suppressed until {c.suppress_expires}" if c.suppress_expires else ""
        return self._say(f"{c.control_id} skipped{tail}")

    def _default_expiry(self, days: int) -> str:
        return (self.today + timedelta(days=max(1, days))).isoformat()

    def undo(self) -> str:
        c = self.current
        if c is None or c.state is ChangeState.PENDING:
            return self._say("nothing to undo on this change")
        c.state = ChangeState.PENDING
        c.skip_reason = None
        c.suppress_expires = None
        return self._say(f"{c.control_id} back to undecided")

    def accept_all_hot(self) -> str:
        """Accept every ready change that disrupts nothing.

        Offered because the zero-impact band is where an operator says "yes, all
        of that, obviously" — but only for changes that are actually ready, so it
        can never accept a block that still has an empty field.
        """
        done = []
        for c in self.queue:
            if c.band is ImpactBand.NONE and c.state is ChangeState.PENDING \
                    and c.ready(self.plan.context):
                c.state = ChangeState.ACCEPTED
                c.selected = True
                done.append(c.control_id)
        if not done:
            return self._say("no zero-impact change is ready to accept")
        return self._say(f"accepted {len(done)} zero-impact change(s)")

    # -- review ------------------------------------------------------------
    def summary(self) -> dict:
        q = self.queue
        return {
            "total": len(q),
            "accepted": len(self.plan.accepted),
            "skipped": len(self.plan.skipped),
            "pending": sum(1 for c in q if c.state is ChangeState.PENDING),
            "manual": len(self.plan.manual),
            "bands": {b.value: n for b, n in self.plan.band_counts().items()},
            "needs_window": self.plan.needs_window(),
            "hand_edited": [c.control_id for c in self.plan.hand_edited_changes()],
            "secrets": len(self.plan.secret_fields()),
            "score_now": self.plan.report.summary.posture_score,
            "score_projected": self.plan.projected_score(),
        }

    def export_warnings(self) -> list[str]:
        """What the review screen must say out loud before anything is written."""
        out: list[str] = []
        if not self.plan.accepted:
            out.append("nothing has been accepted — remediation.cfg will contain no "
                       "commands, only a record of what was skipped or is manual")
        pending = [c for c in self.queue if c.state is ChangeState.PENDING]
        if pending:
            out.append(f"{len(pending)} change(s) undecided — they will not be "
                       "written to remediation.cfg")
        if self.plan.needs_window():
            out.append("the export includes changes that reboot APs or the "
                       "controller; it needs a change window")
        for c in self.plan.accepted:
            for f, msg in c.questionable(self.plan.context):
                # Named per value rather than counted: "1 value does not match the
                # config" tells the operator to go and find it, and the whole
                # reason it is here is that it was already easy to miss once.
                out.append(f"{c.control_id} {f.placeholder}: {msg}")
        edited = self.plan.hand_edited_changes()
        if edited:
            out.append(f"{len(edited)} change(s) contain hand-edited lines that did "
                       "not come from the hardening guide: "
                       + ", ".join(c.control_id for c in edited))
        secrets = self.plan.secret_fields()
        if secrets:
            out.append(f"{len(secrets)} secret value(s) entered — you will be asked "
                       "whether to write them into remediation.cfg")
        return out

    def _say(self, message: str) -> str:
        self.message = message
        return message
