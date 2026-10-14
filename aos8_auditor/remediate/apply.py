"""Applying a verified artifact, one block at a time, checking after each one.

The shape of this is deliberate and worth stating before the code:

* **Block by block, never the whole file at once.** Each block is self-contained,
  so a run that stops after block four leaves four complete changes and no
  fragments. Sending the file in one go would make "it failed somewhere" the only
  available description of the outcome.
* **Stop at the first failure.** Pushing more configuration on top of a command
  the controller just rejected is how a plan that was reviewed as a sequence ends
  up applied as something else.
* **A heartbeat after every block, not just the risky-looking ones.** The
  ``lockout_risk`` flag decides how loudly the operator is warned beforehand. It
  must not decide whether the safety net exists, because then the net is only as
  good as the curation of a YAML file — and the whole point is that the change
  which cuts you off is the one nobody expected to.
* **Nothing is ever saved.** ``write memory`` is not sent here and there is no
  flag to make it happen. That is not squeamishness: an unsaved lockout is one
  power cycle away from being over, and taking that away in exchange for saving
  the operator a command would be a bad trade.

Refusals, verification and the transcript all live behind
:class:`~..transport.apply_session.ApplySession`, which cannot be built from an
artifact that does not verify. This module decides *when*; it has no ability to
decide *what*.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..engine.impact import impact_for
from ..engine.models import Status
from ..model.evidence import ExitKind, utcnow_iso
from ..transport.apply_session import ApplyRefused, ApplySession, BlockResult
from .approve import RESULT_NAME, Artifact, CfgBlock
from .preflight import PreflightReport, preflight, recheck

RESULT_SCHEMA_VERSION = "1.0"
TRANSCRIPT_NAME = "apply_transcript.txt"

# Controllers carrying the Mobility-Master configuration hierarchy — including
# standalones, which have a /mm/mynode of their own — do not apply what you type
# in config mode. It lands in a pending buffer and takes effect only when it is
# committed, which on these platforms is 'write memory'. This tool does not send
# that and will not, so on such a controller a clean run leaves the change staged
# and inert. Reporting that as "applied" and saying nothing else would be true of
# the commands and false about the controller.
PENDING_COMMAND = "show configuration pending"
# Where a run that sent nothing writes itself. Deliberately not RESULT_NAME:
# that filename is an interlock, read back by verify() to refuse a second apply,
# and a rehearsal or a refusal has nothing to interlock against. Dropping one
# there would make "we thought about applying this" indistinguishable from "some
# of this is on the controller now".
ATTEMPT_NAME = "apply_attempt.json"


# Outcomes. Plain strings, not an Enum, because verify() in approve.py reads
# these back out of a JSON file written by an earlier run — possibly by an
# earlier version of the tool — and comparing strings is what that has to do.
APPLIED = "applied"          # everything intended landed and was confirmed
STAGED = "staged"            # ...and none of it is in effect until it is committed
STOPPED = "stopped"          # ran, then stopped early; some blocks may have landed
NOTHING_TO_DO = "nothing_to_do"
REFUSED = "refused"          # never sent anything
DRY_RUN = "dry_run"


@dataclass
class AppliedBlock:
    control_id: str
    result: BlockResult
    confirmed: Status | None = None      # the control's status after the change
    rolled_back: bool = False
    rollback_result: BlockResult | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.result.ok


@dataclass
class ApplyOptions:
    operator: str | None = None
    verify_each: bool = True
    rollback_on_error: bool = True
    # Called before a block that can cut off admin access. Returning False stops
    # the run. None means nothing is asked, which is only ever right when the
    # caller has already asked — the CLI does.
    confirm: Callable[[CfgBlock, str], bool] | None = None
    progress: Callable[[str], None] | None = None


@dataclass
class ApplyResult:
    outcome: str = REFUSED
    dry_run: bool = False
    started_at: str = ""
    finished_at: str | None = None
    preflight: PreflightReport | None = None
    blocks: list[AppliedBlock] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (control_id, why)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    lockout_suspected: bool = False
    stages_config: bool = False       # this controller has a pending buffer
    staged_not_applied: bool = False  # ...and this run's changes are sitting in it

    @property
    def applied_ids(self) -> list[str]:
        return [b.control_id for b in self.blocks if b.ok]

    @property
    def failed(self) -> AppliedBlock | None:
        return next((b for b in self.blocks if not b.ok), None)


def apply_artifact(session: ApplySession, artifact: Artifact, *,
                   options: ApplyOptions | None = None,
                   controls=None) -> ApplyResult:
    """Apply the blocks of ``artifact`` that this controller still needs."""
    opts = options or ApplyOptions()
    say = opts.progress or (lambda _msg: None)
    result = ApplyResult(started_at=utcnow_iso(), dry_run=session.dry_run)
    result.warnings.extend(session.verify_report.warnings)

    say("checking this is the controller the plan was made for")
    pre = preflight(session, artifact, controls=controls)
    result.preflight = pre
    result.warnings.extend(pre.warnings)
    if not pre.ok:
        result.errors.extend(pre.errors)
        result.outcome = REFUSED
        result.finished_at = utcnow_iso()
        return result

    todo = _blocks_to_apply(artifact, pre, result)
    if not todo:
        result.outcome = NOTHING_TO_DO
        result.finished_at = utcnow_iso()
        return result

    # Asked before the first block, so the answer is about the controller rather
    # than about what this run just did to it.
    pending_before = _pending_config(session)
    result.stages_config = pending_before is not None
    if pending_before:
        result.warnings.append(
            "this controller had uncommitted configuration pending before this run "
            "started. It is not ours, and a 'write memory' would commit it too — "
            "read 'show configuration pending' before you save anything.")

    for i, block in enumerate(todo, 1):
        label = f"[{i}/{len(todo)}] {block.control_id}"
        if not _confirmed(block, opts, result, say):
            result.skipped.append((block.control_id, "declined by the operator"))
            break

        say(f"{label}: applying")
        try:
            sent = session.send_block(block)
        except ApplyRefused as e:
            result.errors.append(str(e))
            break

        applied = AppliedBlock(control_id=block.control_id, result=sent)
        result.blocks.append(applied)

        if not sent.ok:
            _handle_failure(session, artifact, applied, opts, result, say)
            break

        if not _still_answering(session, applied, result, say):
            break

        if opts.verify_each and not session.dry_run:
            _confirm_change(session, artifact, applied, controls, say,
                            stages_config=result.stages_config)

    if result.stages_config and result.blocks:
        result.staged_not_applied = _is_staged(
            _pending_config(session), pending_before, result.blocks)
    if result.staged_not_applied and result.errors:
        # The clean wording below says "the commands above were accepted", which
        # on this path is flatly untrue — one of them is why the run stopped. An
        # operator who reads it and commits would put a half-applied block into
        # effect, which is the one outcome the staging buffer was protecting them
        # from.
        result.warnings.append(
            "this controller stages configuration, so nothing this run sent is in "
            "effect — but the run did not finish. What is in the pending "
            "configuration is as much of the plan as it got through, possibly "
            f"including part of the block that failed. Read '{PENDING_COMMAND}' "
            "before you commit anything: a 'write memory' now would put exactly "
            "that into effect. A reload discards it.")
    elif result.staged_not_applied:
        result.warnings.append(
            "this controller stages configuration. The commands above were "
            "accepted and none of them is in effect: they are sitting in the "
            "pending configuration until someone commits them with 'write "
            "memory', which this tool does not send. 'show configuration pending' "
            "lists them, and a reload discards them.")

    result.finished_at = utcnow_iso()
    result.outcome = _outcome(result, todo)
    return result


def _pending_config(session: ApplySession) -> str | None:
    """What this controller has staged and not committed.

    ``None`` means the platform has no pending buffer at all — it applies what
    you type — which is a different thing from a pending buffer that is empty,
    and the difference decides what the operator has to be told at the end.
    """
    if session.dry_run:
        return None
    try:
        pending = session.probe(PENDING_COMMAND)
    except Exception:
        return None
    if pending.exit_kind in (ExitKind.UNSUPPORTED, ExitKind.DENIED, ExitKind.ERROR,
                             ExitKind.TIMEOUT):
        return None
    return pending.redacted_output.strip()


# Every block opens and closes with these. They say nothing about whether the
# configuration in between landed, and 'end' would match half of any buffer.
_FRAMING = {"configure terminal", "end", "exit"}


def _sent_config_lines(applied: AppliedBlock) -> list[str]:
    """The lines of a block that actually configure something."""
    lines = [ln.command.strip() for ln in applied.result.lines if ln.sent]
    return [ln for ln in lines
            if ln and ln not in _FRAMING and not ln.startswith("cd ")]


def _lines_in_pending(pending: str | None, blocks: list[AppliedBlock]) -> bool:
    """Does the pending buffer contain a line one of these blocks sent?"""
    if not pending:
        return False
    staged_lines = {line.strip() for line in pending.splitlines()}
    return any(line in staged_lines
               for b in blocks for line in _sent_config_lines(b))


def _is_staged(after: str | None, before: str | None,
               blocks: list[AppliedBlock]) -> bool:
    """Is this run's configuration sitting in the pending buffer, not in effect?

    Asked of the controller's own pending configuration rather than inferred
    from the platform: "this box has a pending buffer" and "what we just sent is
    in it" are different claims, and only the second one is worth telling the
    operator that their change has not happened yet.

    Two signals, either of which is enough. A line we sent appears verbatim in
    the buffer — direct, and what a staging controller does. Or the buffer
    changed across the run, which catches a controller that stores the change in
    some normalised form we would not recognise line for line.
    """
    if not after:
        return False
    return _lines_in_pending(after, blocks) or after != (before or "")


# --------------------------------------------------------------------------
# choosing what to send
# --------------------------------------------------------------------------

def _blocks_to_apply(artifact: Artifact, pre: PreflightReport,
                     result: ApplyResult) -> list[CfgBlock]:
    """Artifact order, minus what the controller says it no longer needs.

    The order is emit's: dependency first, lockout risk last. It is deliberately
    NOT regrouped by impact here — banding would hoist the console-block change
    above the client-facing ones, which removes the fallback path before the
    risky part rather than after it.
    """
    keep = set(pre.apply_ids)
    todo = []
    for block in artifact.blocks:
        if block.control_id in keep:
            todo.append(block)
            continue
        verdict = pre.verdict_for(block.control_id)
        result.skipped.append((
            block.control_id,
            verdict.reason if verdict and verdict.reason else "not needed"))
    return todo


def _confirmed(block: CfgBlock, opts: ApplyOptions, result: ApplyResult,
               say) -> bool:
    if opts.confirm is None:
        return True
    impact = impact_for(block.control_id)
    if not impact.lockout_risk:
        return True
    say(f"{block.control_id}: this change can cut off your own access")
    if opts.confirm(block, impact.detail or ""):
        return True
    result.warnings.append(
        f"{block.control_id} was declined at the confirmation prompt; the run "
        "stopped there, leaving the earlier changes applied and unsaved.")
    return False


# --------------------------------------------------------------------------
# after each block
# --------------------------------------------------------------------------

def _still_answering(session: ApplySession, applied: AppliedBlock,
                     result: ApplyResult, say) -> bool:
    """The heartbeat. Runs after every block, whatever the block was."""
    if session.alive():
        return True

    say(f"{applied.control_id}: the controller stopped answering — reconnecting")
    if session.reconnect():
        note = ("the session dropped after this change and was re-established; "
                "the change itself looks intact")
        applied.notes.append(note)
        result.warnings.append(f"{applied.control_id}: {note}")
        return True

    result.lockout_suspected = True
    result.errors.append(
        f"{applied.control_id}: the controller stopped answering after this "
        "change and did not come back. Nothing in this run was saved, so a power "
        "cycle restores the last saved configuration — that is the way out. Do "
        "not run 'write memory' until you have confirmed you can still log in.")
    return False


def _confirm_change(session: ApplySession, artifact: Artifact,
                    applied: AppliedBlock, controls, say, *,
                    stages_config: bool = False) -> None:
    """Did the change actually do what the control asked for?

    A block whose commands were all accepted has not necessarily fixed anything —
    accepted is what the CLI says to a command that parsed. This re-reads the
    controller and asks the control itself.
    """
    status = recheck(session, artifact, [applied.control_id],
                     controls=controls).get(applied.control_id)
    applied.confirmed = status
    if status is Status.PASS:
        say(f"{applied.control_id}: confirmed")
    elif status is None:
        applied.notes.append(
            "could not re-read the controller to confirm this change")
    elif stages_config and _lines_in_pending(_pending_config(session), [applied]):
        # Asked of the controller rather than assumed, and only on the path where
        # the answer changes what the operator does: a staged change reads exactly
        # like a change that did not work, and sending someone to go and debug a
        # command that was fine would waste their afternoon.
        applied.notes.append(
            f"the commands were accepted and the control still reports "
            f"{status.value}, which is what a staged change looks like: it is in "
            "the pending configuration and not yet in effect.")
    else:
        applied.notes.append(
            f"the commands were accepted but the control still reports "
            f"{status.value}. The change may be incomplete, or it may depend on "
            "something outside this plan.")


def _handle_failure(session: ApplySession, artifact: Artifact,
                    applied: AppliedBlock, opts: ApplyOptions,
                    result: ApplyResult, say) -> None:
    failed_line = applied.result.lines[applied.result.failed_at or 0]
    detail = (f": {failed_line.error_signature}"
              if failed_line.error_signature else "")
    if failed_line.exit_kind is ExitKind.INTERACTIVE:
        # The most useful thing to say here is that the controller is fine. This
        # is a bad command, not a bad device, and the operator should be reading
        # the command rather than power-cycling anything.
        result.errors.append(
            f"{applied.control_id}: {failed_line.command!r} did not run — it "
            f"opened a prompt and waited for an answer ({detail.lstrip(': ')}). "
            "On ArubaOS this is what a configuration keyword does when it falls "
            "through to the exec command of the same name, usually because an "
            "argument is not valid for it. The prompt was cancelled and nothing "
            "further was sent; the controller is not stuck.")
    elif failed_line.exit_kind is ExitKind.TIMEOUT:
        # Not "rejected". A timeout means the reply never arrived, so the command
        # may well have been carried out — and saying the controller refused it
        # sends the operator to go and read a command that was probably fine.
        result.errors.append(
            f"{applied.control_id}: no reply to {failed_line.command!r} before the "
            f"read timeout ({failed_line.exit_kind.value}{detail}). It may or may "
            "not have taken effect; nothing further was sent.")
    else:
        result.errors.append(
            f"{applied.control_id}: the controller rejected "
            f"{failed_line.command!r} ({failed_line.exit_kind.value}{detail}). "
            "Nothing further was sent.")

    # The heartbeat runs here too, before anything is decided. A block can fail
    # *because* the line before it cut us off, and that has to be reported as a
    # lockout rather than as a syntax problem with the next command.
    reachable = session.alive()
    if not reachable:
        result.lockout_suspected = True
        result.errors.append(
            f"{applied.control_id}: the controller is not answering after this "
            "failure. Nothing in this run was saved, so a power cycle restores "
            "the last saved configuration. Do not run 'write memory' until you "
            "have confirmed you can still log in.")

    if not applied.result.partial:
        # The first line failed, so nothing landed and there is nothing to undo.
        return
    if not opts.rollback_on_error:
        result.warnings.append(
            f"{applied.control_id} was left half-applied because automatic "
            "rollback was turned off. rollback.cfg has the reversal.")
        return
    if not reachable:
        result.warnings.append(
            f"{applied.control_id} was left half-applied and the controller is "
            "not answering, so it could not be reversed.")
        return

    reverse = artifact.rollback_for(applied.control_id)
    if reverse is None:
        result.warnings.append(
            f"{applied.control_id} was left half-applied and this artifact has no "
            "reversal for it. Undo it by hand before continuing.")
        return

    say(f"{applied.control_id}: reversing the part that landed")
    try:
        applied.rollback_result = session.send_block(reverse)
    except ApplyRefused as e:
        result.warnings.append(f"could not reverse {applied.control_id}: {e}")
        return
    applied.rolled_back = applied.rollback_result.ok
    if not applied.rolled_back:
        if result.stages_config:
            # Nothing is running on this box that was not running before, so the
            # alarming version of this sentence would send someone to firefight a
            # controller that is fine. The mess is real, but it is in the buffer.
            result.warnings.append(
                f"the reversal of {applied.control_id} did not complete either. "
                "Neither the change nor its reversal is in effect — this "
                "controller stages configuration, and both are sitting in the "
                f"pending configuration. Read '{PENDING_COMMAND}' and clear it "
                "rather than committing it; a reload discards the lot.")
        else:
            result.warnings.append(
                f"the reversal of {applied.control_id} did not complete either. "
                "That controller is now in a state neither the plan nor the "
                "rollback describes — read rollback.cfg and finish it by hand.")


def _outcome(result: ApplyResult, todo: list[CfgBlock]) -> str:
    if result.errors:
        # A rehearsal that hit a refusal is not a clean rehearsal, but it is also
        # not a run that stopped part-way: nothing was ever sent.
        return REFUSED if result.dry_run else STOPPED
    if result.dry_run:
        return DRY_RUN
    if len(result.blocks) < len(todo):
        return STOPPED  # someone declined a confirmation part-way through
    if result.staged_not_applied:
        # Every block was sent and every one was accepted, and the controller is
        # holding all of it uncommitted. "applied" is the one word the operator
        # most needs not to read here, and it is also what verify() reads back to
        # refuse a second run — which would be the wrong refusal, because this
        # change has not happened yet.
        return STAGED
    return APPLIED


# --------------------------------------------------------------------------
# what gets written down
# --------------------------------------------------------------------------

def result_document(artifact: Artifact, result: ApplyResult, *,
                    operator: str | None = None) -> dict:
    pre = result.preflight
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "outcome": result.outcome,
        "dry_run": result.dry_run,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "operator": operator,
        "saved_to_flash": False,  # never; 'write memory' stays the operator's
        "node_path": artifact.node_path,
        "artifact": {
            "remediation_cfg_sha256": (
                (artifact.record.get("artifacts") or {})
                .get("remediation.cfg", {}).get("sha256")),
            "source_run": artifact.record.get("source_run"),
        },
        "controller": (pre.identity.model_dump(mode="json")
                       if pre and pre.identity else None),
        "preflight": {
            "skipped": bool(pre and pre.skipped),
            "errors": list(pre.errors) if pre else [],
            "warnings": list(pre.warnings) if pre else [],
            "drift": [
                {"control_id": d.control_id, "verdict": d.verdict.value,
                 "status": d.status.value if d.status else None,
                 "reason": d.reason}
                for d in (pre.drift if pre else [])
            ],
        },
        "blocks": [
            {
                "control_id": b.control_id,
                "ok": b.ok,
                "confirmed": b.confirmed.value if b.confirmed else None,
                "rolled_back": b.rolled_back,
                "notes": b.notes,
                "commands": [
                    {"command": ln.command, "exit_kind": ln.exit_kind.value,
                     "sent": ln.sent, "output": ln.output}
                    for ln in b.result.lines
                ],
            }
            for b in result.blocks
        ],
        "skipped": [{"control_id": cid, "reason": why}
                    for cid, why in result.skipped],
        "counts": {
            "applied": len(result.applied_ids),
            "confirmed": sum(1 for b in result.blocks if b.confirmed is Status.PASS),
            "skipped": len(result.skipped),
        },
        "lockout_suspected": result.lockout_suspected,
        "stages_config": result.stages_config,
        "staged_not_applied": result.staged_not_applied,
        "errors": result.errors,
        "warnings": result.warnings,
        "next_steps": next_steps(result),
    }


def next_steps(result: ApplyResult) -> list[str]:
    if result.dry_run:
        return ["Nothing was sent. Drop --remediate-dry-run to apply this."]
    if result.lockout_suspected:
        return [
            "Confirm you can still log in — from the console if necessary.",
            "Nothing was saved. A power cycle restores the last saved "
            "configuration.",
            "Do NOT run 'write memory' until you have working access.",
        ]
    steps = []
    if result.staged_not_applied and result.errors:
        # Leading with "commit it when you are ready" would be advice to commit a
        # change that did not finish. The first thing to do here is read the
        # buffer; the second is decide, and neither is 'write memory' on trust.
        steps.append(
            "NOT IN EFFECT, AND NOT FINISHED. This controller stages "
            f"configuration; read the buffer back with '{PENDING_COMMAND}'.")
        steps.append(
            "Do NOT 'write memory' until you have. Committing now puts the "
            "part that was sent into effect — the errors above say where it "
            "stopped.")
        steps.append(
            "A reload discards the whole buffer, which is the clean way back to "
            "where this run started.")
    elif result.staged_not_applied:
        # 'write memory' means something different here — not "keep this across a
        # reboot" but "make this happen at all" — so the ordinary wording, which
        # tells the operator to verify the controller first, would have them
        # verifying a change that has not taken place.
        steps.append(
            "NOT IN EFFECT YET. This controller stages configuration; read it "
            f"back with '{PENDING_COMMAND}'.")
        steps.append(
            "Commit it when you are ready: 'write memory'. On this platform that "
            "is what makes the change take effect, not merely what saves it.")
        steps.append(
            "Verify the controller behaves as expected afterwards — clients "
            "associating, APs up, your own access working from a second session.")
        steps.append(
            "Until you commit, a reload discards all of it. That is the way out "
            "if you change your mind.")
    elif result.applied_ids:
        steps.append(
            "Verify the controller behaves as expected — clients associating, "
            "APs up, your own access working from a second session.")
        steps.append(
            "Then persist the changes yourself: 'write memory'. Nothing here "
            "saved anything, which is what makes the step above reversible.")
    if result.outcome == STOPPED:
        if result.staged_not_applied:
            # The ordinary version promises the re-run will skip what landed.
            # Nothing landed here, so it would send the whole plan again on top
            # of a buffer that already holds half of it.
            steps.append(
                "The run stopped early, and on this controller nothing landed, "
                "so a re-run starts from the top rather than continuing. Deal "
                "with the pending buffer first.")
        else:
            steps.append(
                "The run stopped early. Re-run it to continue: changes that "
                "already landed are detected and skipped.")
    return steps


def transcript(artifact: Artifact, result: ApplyResult) -> str:
    """A plain-text record for the change ticket. Redacted, like everything else."""
    out = [
        "=" * 78,
        "ArubaOS 8 remediation — apply transcript",
        "=" * 78,
        f"node        : {artifact.node_path}",
        f"started     : {result.started_at}",
        f"finished    : {result.finished_at}",
        f"outcome     : {result.outcome}",
        "saved       : no — 'write memory' was not sent and is not automated",
        "",
    ]
    if result.staged_not_applied and result.errors:
        out += ["THIS CONTROLLER STAGES CONFIGURATION AND THIS RUN DID NOT "
                "FINISH. None of",
                "the below is in effect; the pending configuration holds the part "
                "that was",
                "sent. Read it before committing anything.", ""]
    elif result.staged_not_applied:
        out += ["THIS CONTROLLER STAGES CONFIGURATION. Everything below was "
                "accepted and",
                "none of it is in effect until someone runs 'write memory'.", ""]
    if result.dry_run:
        out += ["THIS WAS A DRY RUN. Nothing below was sent to a controller.", ""]

    for b in result.blocks:
        out.append("-" * 78)
        confirmed = b.confirmed.value if b.confirmed else "not checked"
        out.append(f"{b.control_id}  [{'ok' if b.ok else 'FAILED'}; "
                   f"control now: {confirmed}]")
        out.append("-" * 78)
        for ln in b.result.lines:
            mark = " " if ln.ok else "!"
            out.append(f"{mark} {ln.command}")
            for reply in (ln.output or "").splitlines():
                out.append(f"      {reply}")
        for note in b.notes:
            out.append(f"  NOTE: {note}")
        if b.rolled_back:
            out.append("  REVERSED: the part that landed was rolled back.")
        out.append("")

    for cid, why in result.skipped:
        out.append(f"skipped {cid}: {why}")
    if result.skipped:
        out.append("")
    for w in result.warnings:
        out.append(f"WARNING: {w}")
    for e in result.errors:
        out.append(f"ERROR: {e}")
    out.append("")
    for step in next_steps(result):
        out.append(f"NEXT: {step}")
    return "\n".join(out) + "\n"


def write_result(artifact: Artifact, result: ApplyResult, *,
                 operator: str | None = None) -> list[Path]:
    """Write the result and transcript beside the artifact, 0600.

    A run that reached the controller writes ``apply_result.json``, which is the
    interlock against a second apply: verify() reads it back and refuses an
    artifact that already went out in full. A run that sent nothing — a rehearsal,
    a refused preflight, a declined first block — writes the same document under
    :data:`ATTEMPT_NAME` instead, so the record exists without claiming that
    anything reached the controller.
    """
    doc = result_document(artifact, result, operator=operator)
    reached_the_controller = bool(result.blocks) and not result.dry_run
    paths = []
    for name, text in (
        (RESULT_NAME if reached_the_controller else ATTEMPT_NAME,
         json.dumps(doc, indent=2) + "\n"),
        (TRANSCRIPT_NAME, transcript(artifact, result)),
    ):
        path = artifact.directory / name
        path.write_text(text, encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        paths.append(path)
    return paths
