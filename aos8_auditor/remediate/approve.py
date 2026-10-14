"""Deciding whether the file about to be applied is the file that was reviewed.

Phase 2's permission model is not a list of allowed verbs. It is: *these exact
bytes, and a human read them*. Everything in this module exists to make that
sentence mechanically checkable before a single character reaches a controller.

The pin is the sha256 that :mod:`emit` recorded at the moment it wrote the file.
If ``remediation.cfg`` still hashes to it, what gets sent is byte-for-byte what
was reviewed. If it does not, the file has been edited since export — which is a
thing Phase 1 explicitly invites ("edit it if you disagree with it") — and the
edit has to be re-reviewed and recorded before it can be applied. That is what
``approval.json`` is: a second, explicit, dated act naming the new bytes.

What gets sent is parsed out of the ``.cfg``, never rebuilt from the JSON record.
The two would diverge the moment an operator edited one of them, and the ``.cfg``
is the artifact a human actually read. (The record also masks secrets, so
rebuilding from it would send the word ``********`` to a controller.)

Nothing here opens a session.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..model.evidence import utcnow_iso
from .hints import (is_destructive, prompts_for_confirmation, text_entry_delimiter,
                    text_entry_regions, text_entry_spans)

APPROVAL_SCHEMA_VERSION = "1.0"
SUPPORTED_RECORD_SCHEMAS = frozenset({"1.0"})

CFG_NAME = "remediation.cfg"
ROLLBACK_NAME = "rollback.cfg"
RECORD_NAME = "remediation.json"
APPROVAL_NAME = "approval.json"
RESULT_NAME = "apply_result.json"

# '! [3/7] AOS8-MGMT-SSH-PUBKEY-001 — SSH public-key authentication enabled', and
# the rollback's '! [3/7] reverse AOS8-...'. Skipped and manual blocks use the
# same header shape but carry no live lines, which is what tells them apart here.
_BLOCK_HEADER = re.compile(
    r"^!\s*\[(?P<index>\d+)/(?P<total>\d+)\]\s+(?P<reverse>reverse\s+)?"
    r"(?P<control_id>[A-Z][A-Z0-9-]*[0-9])\s+—")

# emit marks every line it deliberately left incomplete. The token is what matters;
# the surrounding prose explains which kind of incomplete it is.
_FILL_IN = "FILL IN"


class ArtifactError(RuntimeError):
    """The artifact directory cannot be read as a remediation export."""


@dataclass
class CfgBlock:
    """One self-contained block of a .cfg, as it will actually be sent."""

    control_id: str
    index: int
    total: int
    lines: list[str] = field(default_factory=list)
    reverse: bool = False
    # A line inside this block was written commented-out and marked FILL IN — a
    # withheld secret, or a placeholder nobody answered. The block is NOT safe to
    # send: the commented line is skipped and the rest applies, which is how you
    # get 'vrrp 7' enabled with no authentication line under it.
    incomplete: bool = False
    incomplete_reasons: list[str] = field(default_factory=list)

    @property
    def node_path(self) -> str:
        """The node this block navigates to, or '/' if it never leaves home."""
        for i, line in enumerate(self.lines):
            if line.startswith("cd ") and i not in self.text_indexes:
                return line[3:].strip()
        return "/"

    @property
    def text_indexes(self) -> set[int]:
        """Lines that are raw text the controller stores, not commands it runs.

        ``banner motd ^`` switches the CLI into text entry until a lone ``^``
        closes it. Everything between is data — it is not parsed as config, so
        none of the command-level checks apply to it and none of them mean
        anything if they are run on it anyway.
        """
        return text_entry_spans(self.lines)


def parse_blocks(text: str) -> list[CfgBlock]:
    """Pull the live command blocks out of a rendered .cfg.

    Live lines are attributed to the most recent block header. Skipped and manual
    blocks are rendered fully commented, so they contribute no lines and are
    dropped — but they are still parsed as headers, because a header that was
    silently ignored could let a following live line be attributed to the wrong
    control.

    Inside a ``banner motd`` region the usual tidying stops: the lines are the
    banner, so stripping their indentation, dropping the blank ones and treating
    a leading ``!`` as a comment would all quietly rewrite what the controller
    displays. They are taken exactly as written until the delimiter closes the
    region — and if it never does, they run to the end of the file, which is what
    the controller would do with them and what :func:`verify` refuses to send.
    """
    blocks: list[CfgBlock] = []
    current: CfgBlock | None = None
    awaiting: str | None = None  # the delimiter that closes an open text region
    for raw in text.splitlines():
        if awaiting is not None and current is not None:
            current.lines.append(raw)
            if raw.strip() == awaiting:
                awaiting = None
            continue
        line = raw.strip()
        if not line:
            continue
        header = _BLOCK_HEADER.match(line)
        if header:
            current = CfgBlock(
                control_id=header.group("control_id"),
                index=int(header.group("index")),
                total=int(header.group("total")),
                reverse=bool(header.group("reverse")),
            )
            blocks.append(current)
            continue
        if line.startswith("!"):
            if current is not None and _FILL_IN in line:
                current.incomplete = True
                current.incomplete_reasons.append(line.lstrip("! ").strip())
            continue
        if current is not None:
            current.lines.append(line)
            awaiting = text_entry_delimiter(line)
    return [b for b in blocks if b.lines]


@dataclass
class Artifact:
    """A loaded remediation export. Loaded, not yet trusted — see :func:`verify`."""

    directory: Path
    record: dict
    cfg_text: str
    rollback_text: str
    blocks: list[CfgBlock]
    rollback_blocks: list[CfgBlock]
    approval: dict | None = None
    prior_result: dict | None = None

    @property
    def node_path(self) -> str:
        return self.record.get("node_path") or "/"

    @property
    def target(self) -> dict:
        return (self.record.get("source_run") or {}).get("target") or {}

    def rollback_for(self, control_id: str) -> CfgBlock | None:
        for b in self.rollback_blocks:
            if b.control_id == control_id:
                return b
        return None

    def change_record(self, control_id: str) -> dict:
        for c in self.record.get("changes") or []:
            if c.get("control_id") == control_id:
                return c
        return {}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_json(path: Path, *, what: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise ArtifactError(f"{what} not found: {path}") from e
    except (OSError, ValueError) as e:
        raise ArtifactError(f"{what} is not readable JSON ({path}): {e}") from e
    if not isinstance(data, dict):
        raise ArtifactError(f"{what} is not a JSON object: {path}")
    return data


def load_artifact(directory: str | Path) -> Artifact:
    """Read an export directory. Raises :class:`ArtifactError`, never half-loads."""
    d = Path(directory)
    if not d.is_dir():
        raise ArtifactError(f"not a directory: {d}")

    record = _read_json(d / RECORD_NAME, what="the remediation record")
    try:
        cfg_text = (d / CFG_NAME).read_text(encoding="utf-8")
    except OSError as e:
        raise ArtifactError(f"cannot read {d / CFG_NAME}: {e}") from e
    try:
        rollback_text = (d / ROLLBACK_NAME).read_text(encoding="utf-8")
    except OSError:
        # A rollback is not required to exist for the artifact to be loadable, but
        # applying without one is refused in verify(): a change you cannot reverse
        # is not one to apply unattended.
        rollback_text = ""

    approval = None
    if (d / APPROVAL_NAME).exists():
        approval = _read_json(d / APPROVAL_NAME, what="the approval")
    prior = None
    if (d / RESULT_NAME).exists():
        prior = _read_json(d / RESULT_NAME, what="the previous apply result")

    return Artifact(
        directory=d,
        record=record,
        cfg_text=cfg_text,
        rollback_text=rollback_text,
        blocks=parse_blocks(cfg_text),
        rollback_blocks=parse_blocks(rollback_text),
        approval=approval,
        prior_result=prior,
    )


@dataclass
class VerifyReport:
    """Why the artifact may or may not be applied."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # 'record' — untouched since export. 'approval' — edited, then re-approved.
    pinned_by: str | None = None

    @property
    def ok(self) -> bool:
        return not self.errors


def verify(artifact: Artifact) -> VerifyReport:
    """Check the artifact against its own pin. Reports everything, raises nothing.

    A caller that gets ``ok`` here still has not talked to a controller. This
    answers "is this file the reviewed one and is it internally coherent", not
    "is it right for the device in front of me" — that is :mod:`preflight`.
    """
    r = VerifyReport()
    _verify_schema(artifact, r)
    _verify_pin(artifact, r)
    _verify_blocks_match_record(artifact, r)
    _verify_text_entry(artifact, r)
    _verify_block_shape(artifact, r)
    _verify_nothing_destructive(artifact, r)
    _verify_nothing_incomplete(artifact, r)
    _verify_rollback(artifact, r)
    _verify_not_already_applied(artifact, r)
    return r


def _verify_schema(a: Artifact, r: VerifyReport) -> None:
    version = str(a.record.get("schema_version"))
    if version not in SUPPORTED_RECORD_SCHEMAS:
        r.errors.append(
            f"remediation.json schema_version {version!r} is not supported by this "
            f"build (supported: {', '.join(sorted(SUPPORTED_RECORD_SCHEMAS))}). "
            "Regenerate the export with this version of the tool.")


def _verify_pin(a: Artifact, r: VerifyReport) -> None:
    """The whole security model, in one comparison."""
    recorded = ((a.record.get("artifacts") or {}).get(CFG_NAME) or {}).get("sha256")
    actual = sha256_text(a.cfg_text)
    if not recorded:
        r.errors.append(
            "remediation.json records no sha256 for remediation.cfg, so there is "
            "nothing to check the file against. Regenerate the export.")
        return
    if actual == recorded:
        r.pinned_by = "record"
        return

    approval = a.approval or {}
    if approval.get("remediation_cfg_sha256") == actual:
        # Edited after export, then explicitly re-reviewed. That is a supported
        # path — it is how a withheld secret gets filled in — but it is recorded
        # as its own act, by name and date, rather than silently tolerated.
        if approval.get("supersedes_sha256") != recorded:
            r.errors.append(
                "approval.json approves this remediation.cfg but was written "
                "against a different export. Re-run --remediate-approve.")
            return
        r.pinned_by = "approval"
        r.warnings.append(
            f"remediation.cfg was edited after export and re-approved by "
            f"{approval.get('operator') or 'an unnamed operator'} at "
            f"{approval.get('approved_at')}. What will be sent is the edited file.")
        return

    r.errors.append(
        f"remediation.cfg does not match the export it came from.\n"
        f"    recorded: {recorded}\n"
        f"    actual:   {actual}\n"
        "  The file has changed since it was generated and reviewed. Re-review it "
        "with --remediate-approve, or regenerate it from a fresh audit. It will "
        "not be applied on the strength of a hash that no longer describes it.")


def _verify_blocks_match_record(a: Artifact, r: VerifyReport) -> None:
    """Belt and braces on the hash: the file must also *say* what the record says.

    A pin catches any edit at all, so in practice this only fires when the pin was
    satisfied by an approval. It is the check that an operator filling in a secret
    did not also delete, duplicate or reorder a block while they were in there.
    """
    in_cfg = [b.control_id for b in a.blocks]
    in_record = [c.get("control_id") for c in a.record.get("changes") or []]
    if in_cfg == in_record:
        return
    missing = [c for c in in_record if c not in in_cfg]
    extra = [c for c in in_cfg if c not in in_record]
    detail = []
    if missing:
        detail.append(f"in the record but not in the file: {', '.join(missing)}")
    if extra:
        detail.append(f"in the file but not in the record: {', '.join(extra)}")
    if not detail:
        detail.append(f"same changes in a different order: file has {in_cfg}, "
                      f"record has {in_record}")
    r.errors.append("remediation.cfg and remediation.json disagree about what this "
                    "change set contains — " + "; ".join(detail))


def _verify_text_entry(a: Artifact, r: VerifyReport) -> None:
    """A ``banner motd`` region has to close, and close inside its own block.

    While the region is open the CLI is storing text, not running commands. If the
    closing delimiter is missing the region never ends, so every line after it —
    the ``end`` that closes the block, and each command of every block that
    follows — is swallowed into the banner instead of being executed. Nothing
    downstream can recover from that, so it is refused here.
    """
    for block in a.blocks + a.rollback_blocks:
        where = f"{block.control_id}{' (rollback)' if block.reverse else ''}"
        for start, end in text_entry_regions(block.lines):
            if end is not None:
                continue
            delim = text_entry_delimiter(block.lines[start])
            r.errors.append(
                f"{where}: {block.lines[start]!r} opens banner text that is never "
                f"closed. The delimiter {delim!r} has to appear alone on a line of "
                "its own to end it; without that, every line after it — including "
                "the 'end' that closes this block — becomes part of the banner "
                "instead of being run.")


def _verify_block_shape(a: Artifact, r: VerifyReport) -> None:
    """Every block must still be the self-contained frame the emitter wrote.

    ``cd <node>`` / ``configure terminal`` / commands / ``end`` is not decoration —
    it is the property that makes block-by-block apply possible, and each way of
    breaking it fails differently:

    * no closing ``end``, and the session is left in configuration mode, where the
      next block's ``cd`` is not a navigation command;
    * a second ``cd`` part-way through, and the tail of a block reviewed for one
      node lands on a sibling — the multi-node hazard, arriving by hand-edit
      instead of by values file;
    * nothing between the frame lines, and the block reports as applied while
      having changed nothing.

    Only reachable via an approved edit; the emitter cannot produce any of these.
    """
    head = ([f"cd {a.node_path}"] if a.node_path and a.node_path != "/" else [])
    head.append("configure terminal")
    for block in a.blocks + a.rollback_blocks:
        where = f"{block.control_id}{' (rollback)' if block.reverse else ''}"
        if block.lines[:len(head)] != head or block.lines[-1] != "end":
            r.errors.append(
                f"{where}: the block is no longer self-contained. Expected it to "
                f"open with {' / '.join(head)} and close with 'end'; it runs "
                f"{block.lines[0]!r} .. {block.lines[-1]!r}. Applying it would "
                "leave the session somewhere the next block does not expect.")
            continue
        # Banner text is data. 'end' inside a motd is a word, not a mode change.
        text = block.text_indexes
        body = block.lines[len(head):-1]
        stray = [ln for i, ln in enumerate(body, start=len(head))
                 if i not in text
                 and (ln.startswith("cd ") or ln in ("configure terminal", "end"))]
        if stray:
            r.errors.append(
                f"{where}: changes context part-way through the block "
                f"({', '.join(repr(s) for s in stray)}). Everything after that line "
                "would run somewhere other than where it was reviewed to run.")
        if not body:
            r.errors.append(
                f"{where}: the block has a frame but no commands left in it. It "
                "would be sent, report as applied, and change nothing. Delete the "
                "block instead of emptying it.")


def _verify_nothing_destructive(a: Artifact, r: VerifyReport) -> None:
    """The build-time gate, run again on the bytes about to be sent.

    emit._finalize already refused these when the file was written. Running it
    again here is not redundant: between then and now the file has been sitting on
    a filesystem where anything could have edited it, and an approval is a human
    saying "send these bytes" — which is not a human who checked every line for a
    reload.
    """
    for block in a.blocks + a.rollback_blocks:
        text = block.text_indexes
        for i, line in enumerate(block.lines):
            if i in text:
                continue  # banner prose; 'reboot' in a message is a word
            if is_destructive(line):
                r.errors.append(
                    f"{block.control_id}: refusing to send a destructive command: "
                    f"{line!r}. The generator never writes one of these.")
            if prompts_for_confirmation(line):
                r.errors.append(
                    f"{block.control_id}: refusing to send {line!r} — it stops and "
                    "asks for confirmation, and the next line of the block would be "
                    "read as the answer instead of being run. Apply this one by "
                    "hand. The generator never writes one of these.")


def _verify_nothing_incomplete(a: Artifact, r: VerifyReport) -> None:
    """A block with a commented-out line is a half-change, not a smaller change.

    The withheld-secret case is the dangerous one: 'vrrp 7' and 'no shutdown'
    apply cleanly while the 'authentication <secret>' line between them is skipped,
    leaving the feature enabled and unauthenticated — worse than before the fix.
    """
    for block in a.blocks:
        if not block.incomplete:
            continue
        why = "; ".join(block.incomplete_reasons) or "a line is marked FILL IN"
        r.errors.append(
            f"{block.control_id} is incomplete and would apply as a partial change "
            f"({why}). Fill the line in and re-run --remediate-approve, or remove "
            "the block. Applying the rest of it without that line is not a safer "
            "subset of the change.")


def _verify_rollback(a: Artifact, r: VerifyReport) -> None:
    recorded = ((a.record.get("artifacts") or {}).get(ROLLBACK_NAME) or {}).get("sha256")
    if not a.rollback_text:
        r.warnings.append(
            "no rollback.cfg beside this export: a failed block cannot be reversed "
            "automatically and will be left applied for you to undo by hand.")
        return
    if recorded and sha256_text(a.rollback_text) != recorded:
        # Not fatal — the rollback is never sent unless something goes wrong, and
        # refusing to apply because the *undo* file was edited would be perverse.
        # But the operator should know the safety net is not the generated one.
        r.warnings.append(
            "rollback.cfg has been edited since export. If a block fails, the "
            "reversal that runs is the edited one.")


def _verify_not_already_applied(a: Artifact, r: VerifyReport) -> None:
    prior = a.prior_result
    if not prior:
        return
    when = prior.get("finished_at") or prior.get("started_at") or "an earlier run"
    if prior.get("outcome") == "applied":
        r.errors.append(
            f"this artifact was already applied in full at {when}. Re-applying it "
            "would push a change set that was planned against a configuration the "
            "controller no longer has. Re-audit and generate a fresh export.")
        return
    r.warnings.append(
        f"a previous apply of this artifact stopped early at {when} "
        f"(outcome: {prior.get('outcome')}). Blocks that already landed will be "
        "detected as already-satisfied and skipped.")


# --------------------------------------------------------------------------
# re-approval
# --------------------------------------------------------------------------

def approval_document(artifact: Artifact, *, operator: str | None,
                      note: str | None = None) -> dict:
    """The record of a human re-reviewing an edited remediation.cfg.

    Deliberately a new file rather than an update to remediation.json: the record
    is the thing the pin is taken against, and a file that rewrites its own pin to
    match whatever it currently holds is not a pin.
    """
    recorded = ((artifact.record.get("artifacts") or {}).get(CFG_NAME) or {}).get("sha256")
    return {
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "approved_at": utcnow_iso(),
        "operator": operator,
        "note": note,
        "remediation_cfg_sha256": sha256_text(artifact.cfg_text),
        "supersedes_sha256": recorded,
        "source_run": artifact.record.get("source_run"),
        "node_path": artifact.node_path,
        # What was actually approved, in the form it will be sent. An approval that
        # only recorded a hash would be unreviewable after the fact.
        "blocks": [
            {"control_id": b.control_id, "commands": list(b.lines)}
            for b in artifact.blocks
        ],
    }


def write_approval(artifact: Artifact, document: dict) -> Path:
    """Drop the approval beside the artifact, 0600 like everything else here.

    Takes an already-built document rather than building one, so a caller can
    check that the approval it is about to write actually makes the artifact
    verify before any of it reaches the disk.
    """
    path = artifact.directory / APPROVAL_NAME
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path
