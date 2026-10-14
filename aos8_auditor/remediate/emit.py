"""The three artifacts: ``remediation.cfg``, ``rollback.cfg``, ``remediation.json``.

Phase 1 ends here. Nothing in this module opens a session or sends a command; it
writes files that a human reads, edits if they disagree, and pastes themselves.

Two properties the format is built around:

* **Every block is self-contained.** It opens with ``cd``/``configure terminal``
  and closes with ``end``, so the whole file pastes cleanly and so does any single
  block a reviewer decides to take on its own. No block depends on the mode a
  previous block left the session in — which also means a paste that drops
  characters mid-file cannot silently apply half of the next change.
* **Nothing here persists.** ``write memory`` is never written, only mentioned.
  Verifying the change and saving it are the operator's, deliberately.

The destructive-verb check runs one last time over the finished text rather than
over the parsed segments, because a recipe override and an operator's own edit
both bypass the parser.
"""

from __future__ import annotations

import hashlib
import json
import os
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

from .. import __version__
from ..engine.models import GuideDocument, Reference
from ..model.evidence import utcnow_iso
from .fields import remaining_placeholders
from .hints import (is_destructive, prompts_for_confirmation, text_entry_delimiter,
                    text_entry_regions)
from .plan import BAND_BANNER, BAND_ORDER, BAND_TITLE, Change, ImpactBand, RemediationPlan

SCHEMA_VERSION = "1.0"
RULE = "!" + "=" * 77
THIN = "!" + "-" * 77

_GUIDE_LABEL = {
    GuideDocument.FEDERAL_2020: "Aruba OS Hardening Guide (Federal Technology Guide, 2020)",
    GuideDocument.CONTROLLER_2023: "ArubaOS 8 Controller Hardening Guide (rev 10, 2023)",
}

_FILL_IN = "! FILL IN"


class UnsafeExportError(RuntimeError):
    """A line reached the writer that must never appear in an artifact."""


@dataclass
class ExportOptions:
    """The choices made at export time, all of them the operator's."""

    # Asked once, at export. 'no' comments the secret-bearing lines out and marks
    # them FILL IN — deliberately NOT a clean-pasting placeholder, because a
    # placeholder that pastes without complaint is a placeholder that ships.
    include_secrets: bool = False
    include_skipped: bool = True
    include_manual: bool = True
    operator: str | None = None
    generated_at: str = field(default_factory=utcnow_iso)


@dataclass
class ExportResult:
    directory: Path
    remediation_cfg: Path
    rollback_cfg: Path
    remediation_json: Path
    cfg_sha256: str
    rollback_sha256: str
    contains_secrets: bool


# --------------------------------------------------------------------------
# comment helpers
# --------------------------------------------------------------------------

def _c(text: str = "", indent: str = "", hang: str | None = None) -> list[str]:
    """One logical comment, wrapped to fit a terminal, as '!'-prefixed lines.

    ``hang`` indents the continuation lines, so a wrapped guide citation or bullet
    still reads as one item rather than as two statements.
    """
    if not text:
        return ["!"]
    hang = indent if hang is None else hang
    out = []
    for para in str(text).splitlines() or [""]:
        para = para.rstrip()
        if not para:
            out.append("!")
            continue
        wrapped = textwrap.wrap(para, width=74, initial_indent=indent,
                                subsequent_indent=hang) or [indent + para]
        out += ["! " + line for line in wrapped]
    return out


def _kv(label: str, value: object, width: int = 13) -> list[str]:
    return _c(f"{label.ljust(width)}: {value}", hang=" " * (width + 2))


def _ref_text(refs: list[Reference]) -> str:
    parts = []
    for r in refs:
        loc = " ".join(b for b in (r.guide_section, r.ref) if b)
        if r.page:
            loc = f"{loc} p.{r.page}".strip()
        label = _GUIDE_LABEL.get(r.document, str(r.document))
        parts.append(f"{label} {loc}".strip())
    return "; ".join(parts)


def _rollback_impact(c: Change) -> list[str]:
    """The rating describes applying the change. Reversing it is usually — but
    not always — symmetric, so it is labelled rather than restated as fact."""
    head, _ = BAND_BANNER[c.band]
    out = _kv("Rated impact", f"{head.split(': ', 1)[-1]} (of the original change)")
    if c.band is not ImpactBand.NONE:
        out += _c("Reversing a disruptive change is usually as disruptive as "
                  "making it. Read the note below before assuming otherwise.",
                  indent="  ")
    return out


def _impact_text(c: Change) -> list[str]:
    head, detail = BAND_BANNER[c.band]
    out = _c(head) + _c(detail, indent="  ")
    if c.impact and c.impact.detail:
        out += _c(c.impact.detail, indent="  ")
    return out


# --------------------------------------------------------------------------
# command lines
# --------------------------------------------------------------------------

@dataclass
class _Line:
    text: str
    commented: bool = False
    marker: str | None = None


def _lines_for(c: Change, opts: ExportOptions, *, force_comment: bool = False) -> list[_Line]:
    """Render one change's commands, commenting out what must not paste clean."""
    secret_indexes: set[int] = set()
    if not opts.include_secrets:
        for f in c.fields:
            if f.is_secret:
                secret_indexes |= set(f.line_indexes)

    out: list[_Line] = []
    for i in range(len(c.commands)):
        text = c.line(i, mask_secrets=False)
        commented = force_comment
        marker = "[hand-edited]" if c.is_hand_edited(i) else None
        if i in secret_indexes and not c.is_hand_edited(i):
            # Re-render with the placeholder rather than the value.
            text = c.commands[i]
            commented = True
            marker = f"{_FILL_IN} — secret withheld from this file"
        elif remaining_placeholders(text):
            commented = True
            marker = f"{_FILL_IN} — {', '.join(remaining_placeholders(text))}"
        out.append(_Line(text, commented, marker))
    return out


def _render_block(lines: list[_Line], node_path: str, *, commented: bool = False) -> list[str]:
    """A self-contained config block: cd / configure terminal / ... / end."""
    pre = "! " if commented else ""
    out: list[str] = []
    if node_path and node_path != "/":
        out.append(f"{pre}cd {node_path}")
    out.append(f"{pre}configure terminal")
    for line in lines:
        if line.marker:
            out += _c(line.marker, indent="  ")
        out.append(("! " if (line.commented or commented) else "") + line.text)
    out.append(f"{pre}end")
    return out


# --------------------------------------------------------------------------
# remediation.cfg
# --------------------------------------------------------------------------

def _cfg_header(plan: RemediationPlan, opts: ExportOptions, accepted: list[Change]) -> list[str]:
    md = plan.report.run_metadata
    target = md.target or {}
    host = target.get("host") or plan.context.host or "unknown"
    name = plan.context.hostname or target.get("hostname")
    where = f"{host} ({name})" if name else str(host)
    if plan.node_path and plan.node_path != "/":
        where += f"  node {plan.node_path}"

    out = [RULE]
    out += _c("ArubaOS 8 remediation — GENERATED, NOT APPLIED")
    out += [RULE]
    out += _kv("Generated by", f"aos8-audit {__version__}")
    out += _kv("Generated at", opts.generated_at)
    if opts.operator or md.operator:
        out += _kv("Operator", opts.operator or md.operator)
    out += _kv("Source run", md.run_id)
    out += _kv("Target", where)
    if md.profile:
        out += _kv("Profile", md.profile)
    out += _c()

    counts = plan.band_counts()
    out += _c(f"{len(accepted)} change(s), ordered so that objects exist before "
              "anything references them, and so the changes that can lock you out "
              "are written last:")
    for band in BAND_ORDER:
        if counts.get(band):
            out += _c(f"{counts[band]:>3} · {BAND_TITLE[band]}", indent="  ")
    out += _c()

    before = plan.report.summary.posture_score
    after = plan.projected_score()
    if before is not None and after is not None:
        out += _c(f"Posture score if every change below lands: {before:.1f} -> {after:.1f}")
        out += _c("Projected by re-scoring this run with these controls passing. It "
                  "assumes the changes apply cleanly and nothing else regresses.",
                  indent="  ")
        out += _c()

    out += _c("READ BEFORE PASTING")
    for bullet in (
        "Nothing here has been sent to a controller. This file is a proposal, and "
        "it is worth exactly as much as your review of it.",
        "Each block is self-contained — it opens 'configure terminal' and closes "
        "'end' — so the whole file, or any single block, pastes cleanly.",
        "Nothing is persisted. Verify the result, then run 'write memory' "
        "yourself. That step is deliberately not automated.",
        "rollback.cfg reverses these changes. Read it before you start.",
        "Lines marked [hand-edited] were typed by the operator and did not come "
        "from the hardening guide.",
        f"Lines marked '{_FILL_IN}' are commented out and incomplete. Fill them in "
        "or delete them; they will not apply as written.",
    ):
        out += _c(f"* {bullet}", indent="  ", hang="    ")
    if plan.needs_window():
        out += _c()
        out += _c("ATTENTION: this file contains changes that reboot APs or the "
                  "controller. They are NOT all at the end — a disruptive change "
                  "can be a prerequisite for a later one, and the lockout-risk "
                  "changes are held to last regardless. Each disruptive block is "
                  "preceded by a full-width STOP banner. Paste block by block, not "
                  "in one go, unless you hold a change window.")
    out += [RULE, "!"]
    return out


def _change_block(c: Change, n: int, total: int, plan: RemediationPlan,
                  opts: ExportOptions, *, skipped: bool = False) -> list[str]:
    out = _stop_banner(c) if not skipped else []
    out += [THIN]
    out += _c(f"[{n}/{total}] {c.control_id} — {c.title}", hang="  " * 4)
    out += _kv("Severity", f"{c.severity.value} · {c.category_label}")
    out += _impact_text(c)
    refs = _ref_text(c.finding.references)
    if refs:
        out += _kv("Guide", refs)
    if c.finding.observed:
        out += _kv("Observed", c.finding.observed)
    if skipped:
        out += _c()
        out += _c(f"SKIPPED by the operator: {c.skip_reason or 'no reason recorded'}")
        if c.suppress_expires:
            out += _c(f"Recorded as accepted risk in suppressions.yaml, expiring "
                      f"{c.suppress_expires}.", indent="  ")
        out += _c("The block below is commented out. It is here so the change "
                  "ticket shows what was declined, not just what was done.",
                  indent="  ")
    for note in c.notes:
        out += _c()
        out += _c(f"NOTE: {note}", hang="      ")
    if c.partial and not skipped:
        out += _c()
        out += _c("NOTE: this control's guidance is partly prose that could not be "
                  "turned into commands. The comments above are the rest of it; "
                  "read them before applying.", hang="      ")
    out += [THIN]
    out += _render_block(_lines_for(c, opts), plan.node_path, commented=skipped)
    out.append("!")
    return out


def render_cfg(plan: RemediationPlan, opts: ExportOptions | None = None) -> str:
    """The full ``remediation.cfg`` text."""
    opts = opts or ExportOptions()
    accepted = plan.ordered()
    out = _cfg_header(plan, opts, accepted)

    for i, c in enumerate(accepted, 1):
        out += _change_block(c, i, len(accepted), plan, opts)

    if opts.include_skipped and plan.skipped:
        out += _section("SKIPPED — declined by the operator, recorded for the change ticket")
        for i, c in enumerate(plan.ordered(plan.skipped), 1):
            if c.actionable:
                out += _change_block(c, i, len(plan.skipped), plan, opts, skipped=True)
            else:
                out += _manual_block(c)

    if opts.include_manual and plan.manual:
        out += _section("MANUAL — no command form; these are applied by hand")
        for c in plan.ordered(plan.manual):
            out += _manual_block(c)

    out += [RULE]
    out += _c("END OF PROPOSED CHANGES")
    out += _c("Nothing above has been applied and nothing above persists itself. "
              "After verifying the controller behaves as expected, save with:")
    out += _c("write memory", indent="    ")
    out += [RULE, ""]
    return _finalize("\n".join(out))


def _stop_banner(c: Change) -> list[str]:
    """A full-width warning immediately above one disruptive block.

    Deliberately per-block rather than once per band. The file is ordered by
    dependency and lockout risk, not by impact, so a controller reboot can sit
    between two changes that disrupt nothing — meaning a banner that claimed
    "everything below needs a window" would be false, and a false banner is worse
    than none. This one only ever describes the block directly beneath it.
    """
    if c.band not in (ImpactBand.AP, ImpactBand.CONTROLLER):
        return []
    head, detail = BAND_BANNER[c.band]
    return ([RULE]
            + _c(f"STOP — {head}")
            + _c(detail)
            + _c("This applies to the single block below. Do not paste it without a "
                 "change window. The blocks before and after it are complete on "
                 "their own and can be applied without this one.")
            + [RULE, "!"])


def _section(title: str) -> list[str]:
    return [RULE] + _c(title, hang="  ") + [RULE, "!"]


def _manual_block(c: Change) -> list[str]:
    out = [THIN]
    out += _c(f"{c.control_id} — {c.title}", hang="  ")
    out += _kv("Severity", f"{c.severity.value} · {c.category_label}")
    refs = _ref_text(c.finding.references)
    if refs:
        out += _kv("Guide", refs)
    if c.finding.observed:
        out += _kv("Observed", c.finding.observed)
    if c.finding.remediation_hint:
        out += _c()
        out += _c("Remediation (from the guide, no command form):")
        out += _c(c.finding.remediation_hint, indent="  ")
    # Only the recipe's notes here: the parsed notes are fragments of the hint
    # that was just printed in full, so repeating them says nothing new.
    for note in c.recipe.notes:
        out += _c()
        out += _c(f"NOTE: {note}", hang="      ")
    out += [THIN, "!"]
    return out


# --------------------------------------------------------------------------
# rollback.cfg
# --------------------------------------------------------------------------

def render_rollback(plan: RemediationPlan, opts: ExportOptions | None = None) -> str:
    """The full ``rollback.cfg`` text — the apply order, reversed.

    A block is either fully invertible or it is guidance only. A partial rollback
    is worse than none: it leaves a config that matches neither the before state
    nor the after state, which is the worst thing to be holding at 3am.
    """
    opts = opts or ExportOptions()
    accepted = list(reversed(plan.ordered()))
    md = plan.report.run_metadata

    out = [RULE]
    out += _c("ArubaOS 8 rollback — GENERATED, NOT APPLIED")
    out += [RULE]
    out += _kv("Generated by", f"aos8-audit {__version__}")
    out += _kv("Generated at", opts.generated_at)
    out += _kv("Source run", md.run_id)
    out += _kv("Reverses", "remediation.cfg from this same export")
    out += _c()
    out += _c("Blocks are in reverse apply order, so a dependency is not removed "
              "while something still references it.")
    out += _c("Where a change has no inverse — an ordered ACL, a setting given a "
              "new value — the block records the value this audit observed and "
              "leaves the restore to you. Guessing at an inverse is how a "
              "rollback turns one outage into two.")
    out += [RULE, "!"]

    for i, c in enumerate(accepted, 1):
        cmds, note = c.rollback(plan.context)
        out += [THIN]
        out += _c(f"[{i}/{len(accepted)}] reverse {c.control_id} — {c.title}",
                  hang="  " * 4)
        out += _rollback_impact(c)
        if c.finding.observed:
            out += _kv("Was", c.finding.observed)
        if note:
            out += _c()
            out += _c(note, hang="  ")
        for extra in c.notes:
            out += _c()
            out += _c(f"NOTE: {extra}", hang="      ")
        out += [THIN]
        if cmds:
            out += _render_block([_Line(t) for t in cmds], plan.node_path)
        else:
            out += _c("No commands: restore this control by hand from the "
                      "pre-change running config.")
        out.append("!")

    out += [RULE]
    out += _c("END OF ROLLBACK")
    out += _c("This reversal does not persist itself either. If remediation.cfg was "
              "saved, the controller still boots into the remediated config until "
              "you verify this reversal and save it with:")
    out += _c("write memory", indent="    ")
    out += [RULE, ""]
    return _finalize("\n".join(out))


# --------------------------------------------------------------------------
# remediation.json
# --------------------------------------------------------------------------

def _change_record(c: Change, plan: RemediationPlan, opts: ExportOptions) -> dict:
    cmds, rb_note = c.rollback(plan.context)
    return {
        "control_id": c.control_id,
        "title": c.title,
        "category": c.finding.category,
        "severity": c.severity.value,
        "source": c.finding.source.value,
        "advisory": c.advisory,
        "state": c.state.value,
        "order": c.order,
        "impact_band": c.band.value,
        "impact": c.impact.model_dump(mode="json") if c.impact else None,
        "references": [r.model_dump(mode="json") for r in c.finding.references],
        "observed": c.finding.observed,
        "expected": c.finding.expected,
        "actionable": c.actionable,
        "partial": c.partial,
        # Secrets are masked here unconditionally: this file is the one that gets
        # attached to a ticket, and a masked value cannot be un-masked later.
        "commands": c.rendered(mask_secrets=True),
        "hand_edited_lines": sorted(c.hand_edited),
        "rollback": cmds,
        "rollback_note": rb_note,
        "notes": c.notes,
        "fields": [
            {
                "placeholder": f.placeholder,
                "type": f.type.value,
                "secret": f.is_secret,
                "filled": f.filled,
                "value": None if f.is_secret else (f.value or None),
                "used_in_lines": f.line_indexes,
            }
            for f in c.fields
        ],
        "skip_reason": c.skip_reason,
        "suppression_expires": c.suppress_expires,
    }


def render_record(plan: RemediationPlan, opts: ExportOptions, *,
                  cfg_sha256: str, rollback_sha256: str) -> str:
    """The machine-readable ``remediation.json``.

    Carries the sha256 of the two .cfg files. Phase 2's permission model, if it
    is ever built, is "apply exactly this reviewed artifact and nothing else" —
    which needs the hash of the thing that was reviewed, taken at the moment it
    was written.
    """
    md = plan.report.run_metadata
    accepted = plan.ordered()
    doc = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "generated_at": opts.generated_at,
        "operator": opts.operator or md.operator,
        "applied": False,
        "phase": 1,
        "source_run": {
            "run_id": md.run_id,
            "started_at": md.started_at,
            "profile": md.profile,
            "target": md.target,
            "controls_content_version": md.controls_content_version,
        },
        "node_path": plan.node_path,
        "posture_score": {
            "observed": plan.report.summary.posture_score,
            "projected": plan.projected_score(),
        },
        "counts": {
            "accepted": len(accepted),
            "skipped": len(plan.skipped),
            "manual": len(plan.manual),
            **{b.value: n for b, n in plan.band_counts().items()},
        },
        "needs_change_window": plan.needs_window(),
        "secrets_written_to_cfg": bool(opts.include_secrets and plan.secret_fields()),
        "artifacts": {
            "remediation.cfg": {"sha256": cfg_sha256},
            "rollback.cfg": {"sha256": rollback_sha256},
        },
        "changes": [_change_record(c, plan, opts) for c in accepted],
        "skipped": [_change_record(c, plan, opts) for c in plan.ordered(plan.skipped)],
        "manual": [_change_record(c, plan, opts) for c in plan.ordered(plan.manual)],
    }
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"


# --------------------------------------------------------------------------
# writing
# --------------------------------------------------------------------------

def _finalize(text: str) -> str:
    """Last gate before the text becomes a file."""
    lines = text.splitlines()
    # Banner text is exempt from the command checks — 'Reboot requests go to the
    # service desk' is a sentence, not a reload — so an unterminated region would
    # exempt the whole rest of the file. Refuse that first.
    banner_text: set[int] = set()
    for start, end in text_entry_regions(lines):
        if end is None:
            raise UnsafeExportError(
                f"line {start + 1} opens banner text ({lines[start].strip()!r}) that "
                f"is never closed: {text_entry_delimiter(lines[start])!r} has to "
                "appear alone on a line to end it. Everything below it would be "
                "swallowed into the banner instead of being run.")
        banner_text |= set(range(start + 1, end + 1))

    for n, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("!") or (n - 1) in banner_text:
            continue
        if is_destructive(stripped):
            raise UnsafeExportError(
                f"line {n} would be exported as a destructive command: {stripped!r}. "
                "The wizard never writes one; this indicates a bad recipe override "
                "or an unchecked hand edit."
            )
        if prompts_for_confirmation(stripped):
            raise UnsafeExportError(
                f"line {n} would be exported as a command that stops and asks for "
                f"confirmation: {stripped!r}. The line after it would be read as the "
                "answer rather than run. This indicates a bad recipe override or an "
                "unchecked hand edit."
            )
    return text


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write(path: Path, text: str) -> None:
    """Write 0600. These files describe exactly where a controller is weak."""
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)


def write_artifacts(plan: RemediationPlan, out_dir: str | Path,
                    opts: ExportOptions | None = None) -> ExportResult:
    """Write the three artifacts into ``out_dir`` and return where they landed."""
    opts = opts or ExportOptions()
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)

    cfg_text = render_cfg(plan, opts)
    rollback_text = render_rollback(plan, opts)
    cfg_sha, rb_sha = _sha256(cfg_text), _sha256(rollback_text)
    record_text = render_record(plan, opts, cfg_sha256=cfg_sha, rollback_sha256=rb_sha)

    cfg = directory / "remediation.cfg"
    rollback = directory / "rollback.cfg"
    record = directory / "remediation.json"
    _write(cfg, cfg_text)
    _write(rollback, rollback_text)
    _write(record, record_text)

    return ExportResult(
        directory=directory,
        remediation_cfg=cfg,
        rollback_cfg=rollback,
        remediation_json=record,
        cfg_sha256=cfg_sha,
        rollback_sha256=rb_sha,
        contains_secrets=bool(opts.include_secrets and plan.secret_fields()),
    )
