"""The change set: one :class:`Change` per actionable finding, plus the state the
wizard mutates as the operator walks through them.

Grouping is by **availability impact**, not severity. Severity says how much a gap
matters; availability says which change window a fix can go in, and that is the
question that actually decides what gets applied this week. The four bands come
straight from the ``impact`` block already attached to every finding.

This module is pure: it reads a finished :class:`Report` and holds decisions. It
does not render, does not write files, and never touches a controller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from ..engine.models import Finding, RemediationImpact, Report, Severity, Status
from ..engine.scoring import score
from .context import DeviceContext
from .fields import (Field, FieldType, fields_for, fields_in, remaining_placeholders,
                     render_line)
from .hints import (Segment, command_lines, is_partial, note_lines, parse_hint,
                    text_entry_delimiter, text_entry_regions)
from .recipes import Recipe, recipe_for
from .validate import validate


class ChangeState(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    SKIPPED = "skipped"


class ImpactBand(str, Enum):
    """Which change window a fix can go in."""

    NONE = "none"              # hot: no client, AP or controller disruption
    CLIENT = "client"          # wireless users drop and rejoin
    AP = "ap"                  # one or more APs reboot
    CONTROLLER = "controller"  # full outage


BAND_ORDER = [ImpactBand.NONE, ImpactBand.CLIENT, ImpactBand.AP, ImpactBand.CONTROLLER]

BAND_TITLE = {
    ImpactBand.NONE: "APPLY ANY TIME · no client, AP or controller disruption",
    ImpactBand.CLIENT: "CLIENTS REAUTHENTICATE · wireless users drop and rejoin",
    ImpactBand.AP: "AP REBOOT · APs rejoin, clients on them drop",
    ImpactBand.CONTROLLER: "CONTROLLER REBOOT · full outage",
}

BAND_BANNER = {
    ImpactBand.NONE: ("AVAILABILITY IMPACT: NONE",
                      "No client drop · no AP reboot · no controller reboot"),
    ImpactBand.CLIENT: ("AVAILABILITY IMPACT: CLIENTS REAUTHENTICATE",
                        "Wireless users drop and rejoin · no AP or controller reboot"),
    ImpactBand.AP: ("AVAILABILITY IMPACT: AP REBOOT",
                    "Each affected AP reboots · clients on it drop until re-association"),
    ImpactBand.CONTROLLER: ("AVAILABILITY IMPACT: CONTROLLER REBOOT — FULL OUTAGE",
                            "All clients drop · all APs rejoin · window required"),
}

_SEV_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
             Severity.LOW: 3, Severity.MANUAL: 4, Severity.INFORMATIONAL: 5}

_NOTE_NOISE = re.compile(r"[^a-z0-9]+")


def _note_key(note: str) -> str:
    """Compare notes on their words, not their punctuation."""
    return _NOTE_NOISE.sub(" ", note.lower()).strip()


def band_for(impact: RemediationImpact | None) -> ImpactBand:
    if impact is None:
        return ImpactBand.NONE
    if impact.reboot_required:
        return ImpactBand.CONTROLLER
    if impact.ap_impact:
        return ImpactBand.AP
    if impact.client_impact:
        return ImpactBand.CLIENT
    return ImpactBand.NONE


@dataclass
class Change:
    """One control's fix, and every decision the operator makes about it."""

    finding: Finding
    segments: list[Segment]
    commands: list[str]
    fields: list[Field]
    recipe: Recipe
    advisory: bool = False

    state: ChangeState = ChangeState.PENDING
    selected: bool = False
    skip_reason: str | None = None
    suppress_expires: str | None = None  # set when a skip is recorded as accepted risk
    # line index -> operator-authored replacement, from the gated ^E unlock.
    hand_edited: dict[int, str] = field(default_factory=dict)

    # -- identity ----------------------------------------------------------
    @property
    def control_id(self) -> str:
        return self.finding.control_id

    @property
    def title(self) -> str:
        return self.finding.title

    @property
    def severity(self) -> Severity:
        return self.finding.severity

    @property
    def category_label(self) -> str:
        return self.finding.category.replace("_", " ")

    @property
    def impact(self) -> RemediationImpact | None:
        return self.finding.impact

    @property
    def band(self) -> ImpactBand:
        return band_for(self.finding.impact)

    @property
    def actionable(self) -> bool:
        return bool(self.commands)

    @property
    def partial(self) -> bool:
        return is_partial(self.segments)

    @property
    def notes(self) -> list[str]:
        """Guidance from the hint plus the recipe, with repeats collapsed.

        A recipe note is hand-written against a hint that has since been reworded,
        so the two can converge. Two near-identical RISK warnings in a row read as
        boilerplate, which is exactly how a real warning gets skimmed past.
        """
        out: list[str] = []
        seen: set[str] = set()
        for note in note_lines(self.segments) + list(self.recipe.notes):
            key = _note_key(note)
            if key in seen:
                continue
            seen.add(key)
            out.append(note)
        return out

    @property
    def order(self) -> int:
        return self.recipe.order

    # -- rendering ---------------------------------------------------------
    def line(self, index: int, *, mask_secrets: bool = False) -> str:
        if index in self.hand_edited:
            return self.hand_edited[index]
        return render_line(self.commands[index], self.fields, mask_secrets=mask_secrets)

    def rendered(self, *, mask_secrets: bool = False) -> list[str]:
        return [self.line(i, mask_secrets=mask_secrets) for i in range(len(self.commands))]

    def is_hand_edited(self, index: int) -> bool:
        return index in self.hand_edited

    # -- readiness ---------------------------------------------------------
    def unfilled(self) -> list[Field]:
        """Fields still needed — a field only used on hand-edited lines is not."""
        live = {i for i in range(len(self.commands)) if i not in self.hand_edited}
        return [f for f in self.fields
                if not f.filled and any(i in live for i in f.line_indexes)]

    def invalid(self, ctx: DeviceContext | None = None) -> list[tuple[Field, str]]:
        out = []
        for f in self.fields:
            if not f.filled:
                continue
            r = validate(f, f.value, ctx)
            if not r.ok:
                out.append((f, r.message))
        return out + self._text_entry_problems()

    def _text_entry_problems(self) -> list[tuple[Field, str]]:
        """The one error that only exists *between* two fields.

        A banner is raw text bounded by a one-character delimiter, so a delimiter
        that also occurs in the text ends the banner early — and because the CLI
        is back at a config prompt from that point on, the remainder of the
        operator's message is executed rather than displayed. Per-field checks
        cannot see this: both values are individually fine.
        """
        out: list[tuple[Field, str]] = []
        lines = self.rendered()
        # Region bounds from the template, contents from what would be sent: the
        # question is whether a filled-in value breaks a structure that is correct
        # before substitution.
        for start, end in text_entry_regions(self.commands):
            delim = text_entry_delimiter(lines[start])
            if delim is None or len(delim) != 1:
                continue  # still a placeholder; the unfilled-field check has it
            for i in range(start + 1, end if end is not None else len(lines)):
                if delim not in lines[i]:
                    continue
                culprit = next(
                    (f for f in fields_in(self.commands[i], self.fields)
                     if f.filled and delim in f.value),
                    next((f for f in self.fields
                          if f.type is FieldType.DELIMITER and f.filled), None))
                problem = (culprit, f"line {i + 1} contains the delimiter {delim!r} — "
                                    "the banner ends at the first one and the rest of "
                                    "the text would be run as commands")
                if culprit is not None and problem not in out:
                    out.append(problem)
        return out

    def questionable(self, ctx: DeviceContext | None = None) -> list[tuple[Field, str]]:
        """Filled values that validate but do not match the audited config.

        Never blocks — the operator may well be about to create the thing. But a
        warning shown once while typing and then scrolled past is a warning that
        did not do its job, and the value it was about is still in the artifact,
        so the review screen asks once more before anything is written.
        """
        out = []
        for f in self.fields:
            if not f.filled:
                continue
            r = validate(f, f.value, ctx)
            if r.ok and r.warning:
                out.append((f, r.message))
        return out

    def ready(self, ctx: DeviceContext | None = None) -> bool:
        """True when this change can be accepted."""
        return self.actionable and not self.unfilled() and not self.invalid(ctx)

    def blocking_reason(self, ctx: DeviceContext | None = None) -> str | None:
        if not self.actionable:
            return "no command form — this control is applied by hand"
        missing = self.unfilled()
        if missing:
            names = ", ".join(f.placeholder for f in missing)
            return f"{len(missing)} field(s) still empty: {names}"
        bad = self.invalid(ctx)
        if bad:
            f, msg = bad[0]
            return f"{f.placeholder}: {msg}"
        return None

    def secrets(self) -> list[Field]:
        return [f for f in self.fields if f.is_secret and f.filled]

    def open_placeholders(self) -> list[str]:
        """Placeholders still present in the rendered lines (incl. hand-edited)."""
        out: list[str] = []
        for line in self.rendered():
            out += [p for p in remaining_placeholders(line) if p not in out]
        return out

    # -- rollback ----------------------------------------------------------
    def rollback(self, ctx: DeviceContext | None = None) -> tuple[list[str], str | None]:
        """(commands, note). An empty command list means revert by hand.

        A partial rollback is worse than none — it can leave a half-reverted
        config — so a block is either fully invertible or it is emitted purely as
        guidance with the observed value recorded.
        """
        if self.recipe.rollback:
            return ([render_line(c, self.fields) for c in self.recipe.rollback],
                    self.recipe.rollback_note)
        if self.recipe.rollback_note:
            return [], self.recipe.rollback_note
        auto = self._auto_rollback(ctx)
        if auto:
            return auto, None
        return [], ("No inverse command exists for this block; restore it from the "
                    "pre-change running config.")

    def _auto_rollback(self, ctx: DeviceContext | None) -> list[str]:
        """The two inversions that are safe to derive rather than write out.

        1. A block that *creates* an object the audited config does not already
           contain inverts to deleting that object.
        2. ``no X`` inverts to ``X`` exactly.

        Anything else — a setting given a new value, an ordered ACL — is left to
        the reviewed table, because guessing at it is how a rollback makes an
        outage worse.
        """
        if self.hand_edited:
            return []  # the guide's wording no longer describes what was sent
        lines = self.rendered()
        if not lines:
            return []
        head = lines[0]
        if ctx is not None and len(lines) > 1 and not remaining_placeholders(head):
            existing = ctx.all_object_names
            tail = head.split()[-1] if head.split() else ""
            if tail and tail not in existing and _creates_object(head):
                return [f"no {head}"]
        if len(lines) == 1 and lines[0].lower().startswith("no "):
            return [lines[0][3:].strip()]
        return []


_OBJECT_CREATORS = (
    "aaa authentication-server", "aaa server-group", "aaa profile",
    "aaa authentication dot1x", "user-role", "ip access-list session",
    "wlan ssid-profile", "wlan virtual-ap", "netdestination", "ap system-profile",
)


def _creates_object(line: str) -> bool:
    return line.lower().startswith(_OBJECT_CREATORS)


@dataclass
class RemediationPlan:
    """Every change on the table for one node, plus the run it came from."""

    report: Report
    context: DeviceContext
    changes: list[Change] = field(default_factory=list)
    node_path: str = "/"

    # -- selection ---------------------------------------------------------
    @property
    def actionable(self) -> list[Change]:
        return [c for c in self.changes if c.actionable]

    @property
    def selected(self) -> list[Change]:
        return [c for c in self.actionable if c.selected]

    @property
    def accepted(self) -> list[Change]:
        return [c for c in self.changes
                if c.state is ChangeState.ACCEPTED and c.actionable]

    @property
    def skipped(self) -> list[Change]:
        return [c for c in self.changes if c.state is ChangeState.SKIPPED]

    @property
    def manual(self) -> list[Change]:
        """No command form — reported so the ticket shows the whole gap.

        Excludes anything the operator explicitly skipped; that is already
        reported under skipped, and listing it twice reads as two open items.
        """
        return [c for c in self.changes
                if not c.actionable and c.state is not ChangeState.SKIPPED]

    def by_band(self, changes: list[Change] | None = None) -> dict[ImpactBand, list[Change]]:
        out: dict[ImpactBand, list[Change]] = {b: [] for b in BAND_ORDER}
        for c in (self.actionable if changes is None else changes):
            out[c.band].append(c)
        return {b: v for b, v in out.items() if v}

    def ordered(self, changes: list[Change] | None = None) -> list[Change]:
        """Emission order: dependency hint first, then severity, then id."""
        src = self.accepted if changes is None else changes
        return sorted(src, key=lambda c: (c.order, _SEV_RANK.get(c.severity, 9), c.control_id))

    # -- summary -----------------------------------------------------------
    def band_counts(self) -> dict[ImpactBand, int]:
        return {b: len(v) for b, v in self.by_band(self.accepted).items()}

    def needs_window(self) -> bool:
        return any(c.band in (ImpactBand.AP, ImpactBand.CONTROLLER) for c in self.accepted)

    def hand_edited_changes(self) -> list[Change]:
        return [c for c in self.accepted if c.hand_edited]

    def secret_fields(self) -> list[tuple[Change, Field]]:
        return [(c, f) for c in self.accepted for f in c.secrets()]

    def projected_score(self) -> float | None:
        """Posture score if every accepted change lands and nothing regresses.

        Computed by re-scoring the real findings with the accepted ones flipped to
        pass — the same scorer the audit uses, so the number is comparable to the
        one in the report rather than an estimate.
        """
        accepted = {c.control_id for c in self.accepted if not c.advisory}
        if not accepted:
            return self.report.summary.posture_score
        findings = [
            f.model_copy(update={"status": Status.PASS})
            if f.control_id in accepted and f.status in (Status.FAIL, Status.WARN) else f
            for f in self.report.results
        ]
        profile = self.report.run_metadata.profile or "high_security"
        return score(findings, active_profile=profile).posture_score


def _is_candidate(f: Finding) -> bool:
    return f.status in (Status.FAIL, Status.WARN) and not f.suppressed


def build_change(f: Finding, *, advisory: bool = False) -> Change:
    recipe = recipe_for(f.control_id)
    segments = parse_hint(f.remediation_hint)
    commands = list(recipe.lines) if recipe.lines else command_lines(segments)
    return Change(finding=f, segments=segments, commands=commands,
                  fields=fields_for(commands), recipe=recipe, advisory=advisory)


def build_plan(report: Report, context: DeviceContext | None = None, *,
               include_advisories: bool = True) -> RemediationPlan:
    """Every failing/warning finding that has a fix, as a reviewable change set.

    Findings whose remediation is prose rather than commands are kept as
    ``manual`` changes: they cannot be exported as config, but they are listed so
    a reader of the change ticket sees the whole gap, not just the automatable
    part of it.
    """
    ctx = context or DeviceContext(host=report.run_metadata.target.get("host"))
    changes = [build_change(f) for f in report.results if _is_candidate(f)]
    if include_advisories:
        changes += [build_change(f, advisory=True)
                    for f in report.advisory_results if _is_candidate(f)]
    plan = RemediationPlan(report=report, context=ctx, changes=changes,
                           node_path=report.run_metadata.target.get("node_path") or "/")
    plan.changes = plan.ordered(changes)
    for c in plan.actionable:
        c.selected = c.band is ImpactBand.NONE  # hot changes pre-selected
    return plan
