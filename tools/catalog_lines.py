"""Every command line the catalog can send, and the snapshot of what was checked.

Shared by the validator (which asks a controller about these lines) and by
tests/test_command_lines_pinned.py (which fails when the two drift apart). They
have to agree on what "the lines" means or the pin guards a different set than
the one that was validated, which is worse than no pin at all.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from aos8_auditor.engine.loader import load_controls
from aos8_auditor.remediate.hints import command_lines, parse_hint
from aos8_auditor.remediate.recipes import recipe_for

REPO_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = REPO_ROOT / "tests" / "data" / "validated_command_lines.txt"

SNAPSHOT_HEADER = """\
# Every command line this tool can send to a controller, and what a real one
# said about each. Regenerate with:
#
#     python3 tools/validate_catalog.py --host ... --report r.json
#     python3 tools/validate_catalog.py --snapshot --from-report r.json
#
# This file is not documentation. tests/test_command_lines_pinned.py compares it
# against what the catalog emits today and fails on any difference, so a new or
# edited remediation line cannot reach an operator until someone has run it past
# a controller's own grammar and updated this snapshot.
#
# Why it exists: 'ssh disable-ciphers hmac-sha1-96' was wrong in a way that did
# not produce an error. hmac-sha1-96 is a MAC, 'disable-ciphers' takes only
# aes-cbc/aes-ctr, and the bad argument dropped the parser into the exec-mode SSH
# client, which asked for a password and then read the next line of the block as
# one. Five more lines were wrong in quieter ways; four of them were rollbacks
# written by prefixing 'no ' to a command whose negation takes no argument, so
# they would only have failed at the moment they were needed.
#
# checked against: {train}
# method:          CLI '?' completion, walked token by token. Nothing executed.
#                  A whole-line '?' does NOT report a bad argument -- the parser
#                  answers the part it liked and ignores the rest.
#
# format: <status>\\t<control-id>\\t<apply|rollback>\\t<command line>\\t[<reason>]
#
#   {ok:<8}the controller's grammar accepted this line.
#   {gap:<8}nobody has checked it. The reason is the controller's own words.
#           Every one of these is a line an operator can be handed that no
#           device has ever confirmed -- the count is on the line above, and it
#           is meant to be read, not to become furniture.
#   {absent:<8}the keyword is not in this platform's grammar at all, so this
#           controller cannot answer. Listed in PLATFORM_ABSENT in
#           tools/catalog_lines.py with what it would take to settle.
"""

DEFAULT_TRAIN = "ArubaOS 8.13.3.0, MC-VA-US"

OK, GAP, ABSENT = "ok", "gap", "absent"

# Lines this repository cannot attest on the hardware it has, and what would
# settle each. These are claims about the *platform*, not about the line: the
# parser answers "not a command" rather than "wrong argument", because the
# keyword is not in its dictionary.
#
# They are marked rather than dropped. Dropping them would let the pin pass on a
# catalog that can still send them; recording them as checked would say a
# controller accepted them, and none has.
PLATFORM_ABSENT: dict[tuple[str, str, str], str] = {
    ("AOS8-GLOBAL-FIPS-001", "apply", "fips enable"):
        "'fips' is absent from the config-mode keyword list of a non-FIPS image. "
        "Needs a controller running a FIPS image to settle.",
    ("AOS8-GLOBAL-FIPS-001", "rollback", "no fips enable"):
        "same image difference as the apply line: 'no fips' is not offered either.",
    ("AOS8-GLOBAL-LCD-001", "apply", "lcd-menu"):
        "an MC-VA has no LCD panel, so 'lcd-menu' is not in its grammar. Needs a "
        "hardware controller with a front panel to settle.",
    ("AOS8-GLOBAL-LCD-001", "rollback", "lcd-menu"):
        "same hardware difference as the apply line.",
}


def catalog_lines() -> list[tuple[str, str, int, str]]:
    """``(control_id, 'apply'|'rollback', index_in_block, line)`` for the catalog.

    The index matters to the validator and not to the pin: a line is only valid
    in the context the lines before it opened, so checking one in isolation is
    how 'prohibit-arp-spoofing' gets reported as invalid when it is simply inside
    'firewall'.
    """
    out: list[tuple[str, str, int, str]] = []
    for control in sorted(load_controls(), key=lambda c: c.id):
        recipe = recipe_for(control.id)
        # The planner's resolution order (see remediate/plan.py): an explicit
        # ``lines`` in the recipe replaces the parsed hint rather than adding to
        # it. Reading the hint here instead would validate text that never
        # reaches a controller, while reporting the control as covered.
        apply_lines = (list(recipe.lines) if recipe and recipe.lines
                       else command_lines(parse_hint(control.remediation_hint)))
        for i, line in enumerate(apply_lines):
            out.append((control.id, "apply", i, line))
        rollback = list(getattr(recipe, "rollback", None) or []) if recipe else []
        for i, line in enumerate(rollback):
            out.append((control.id, "rollback", i, line))
    return out


def emitted_rows() -> list[str]:
    """The same lines, flattened to ``id\\tkind\\tline`` identity rows.

    Both directions, because four of the six defects this exists for were in
    rollbacks — the half of the artifact that only runs when something has
    already gone wrong, and therefore the half where a broken line waits longest
    to be found.

    The status is deliberately not part of the identity: the pin's question is
    "can the tool send a line nobody checked", and a line whose verdict changed
    is the same line.
    """
    return [f"{cid}\t{kind}\t{line}" for cid, kind, _, line in catalog_lines()]


def snapshot_records(path: Path | None = None) -> list[tuple[str, str, str, str, str]]:
    """``(status, control_id, kind, line, reason)`` per recorded row."""
    out = []
    for ln in (path or SNAPSHOT).read_text().splitlines():
        if not ln.strip() or ln.startswith("#"):
            continue
        parts = ln.split("\t")
        if len(parts) < 4:
            raise ValueError(f"malformed snapshot row: {ln!r}")
        status, cid, kind, line = parts[:4]
        out.append((status, cid, kind, line, parts[4] if len(parts) > 4 else ""))
    return out


def snapshot_rows(path: Path | None = None) -> list[str]:
    """The recorded rows as identities, for comparison with ``emitted_rows``."""
    return [f"{cid}\t{kind}\t{line}"
            for _, cid, kind, line, _ in snapshot_records(path)]


def write_snapshot(verdicts: dict[str, tuple[str, str]],
                   train: str = DEFAULT_TRAIN, path: Path | None = None) -> int:
    """Write the snapshot from ``identity -> (status, reason)``.

    Every emitted line must have a verdict. There is no default, because the
    only safe default would be OK and that is the one thing this file must never
    say without evidence.
    """
    target = path or SNAPSHOT
    target.parent.mkdir(parents=True, exist_ok=True)

    rows, tally = [], Counter()
    for identity in emitted_rows():
        if identity not in verdicts:
            raise KeyError(f"no verdict recorded for {identity!r}")
        status, reason = verdicts[identity]
        tally[status] += 1
        # The reason is free text from a controller. A tab in it would move the
        # rest of the sentence into a column that does not exist.
        reason = " ".join(reason.split())
        rows.append(f"{status}\t{identity}" + (f"\t{reason}" if reason else ""))

    summary = "  ".join(f"{status}={tally[status]}"
                        for status in (OK, GAP, ABSENT) if tally[status])
    target.write_text(
        SNAPSHOT_HEADER.format(train=train, ok=OK, gap=GAP, absent=ABSENT)
        + f"#\n# {len(rows)} lines: {summary}\n"
        + "\n".join(rows) + "\n")
    return len(rows)
