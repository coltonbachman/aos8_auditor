"""Every line the tool can send, pinned to the set that was checked on a device.

This is a different kind of test from the rest of the suite. It does not assert
that anything is *correct* — it cannot, because correctness here is a property of
ArubaOS and not of this repository. It asserts that the set of command lines the
catalog emits is the set someone has run past a controller's own grammar, and
fails on any difference so that adding a control forces that step to happen.

The gap it covers is real and was expensive. 'ssh disable-ciphers hmac-sha1-96'
looked fine in review, passed every other test in this suite, and on a controller
dropped the parser into the exec-mode SSH client, which asked for a password and
read the next line of the block as one. Nothing in a unit test can know that;
only the device knows. So the device's answer is written down, and this test
keeps the two from drifting apart.

Regenerating the snapshot is deliberately a separate, explicit step
(``tools/validate_catalog.py --snapshot``), because the point is that a human
went and checked. See tools/README.md.

The snapshot carries a verdict per line, not a blanket claim. It used to say all
of them had been validated; a sweep that reported its own coverage honestly put
that figure at 174 of 201, and a file asserting the other 27 was not a smaller
problem for being an old one.
"""

import pytest

from tools.catalog_lines import (
    ABSENT,
    GAP,
    OK,
    PLATFORM_ABSENT,
    SNAPSHOT,
    emitted_rows,
    snapshot_records,
    snapshot_rows,
)


def test_the_catalog_emits_exactly_what_was_validated():
    """The whole point. Read the failure message, not this docstring."""
    current, pinned = emitted_rows(), snapshot_rows()
    added = [r for r in current if r not in pinned]
    removed = [r for r in pinned if r not in current]
    assert not (added or removed), (
        "the set of commands this tool can send no longer matches the set that "
        "was checked against a controller.\n\n"
        + ("new or changed lines (NOT yet validated):\n  "
           + "\n  ".join(added) + "\n\n" if added else "")
        + ("lines that were validated and are now gone:\n  "
           + "\n  ".join(removed) + "\n\n" if removed else "")
        + "If you added or edited a remediation, run the new lines past a real\n"
        "controller before shipping them:\n\n"
        "    AOS_PW=... python3 tools/validate_catalog.py --host <controller> \\\n"
        "        --username <user> --password-env AOS_PW\n\n"
        "then re-snapshot with --snapshot. A line that parses in review can still\n"
        "open a password prompt on the device; that is the failure this catches.")


def test_the_snapshot_says_what_it_was_validated_against():
    """A snapshot with no train on it is a snapshot nobody can re-check. The
    controller's grammar moves between releases, so the release is part of the
    evidence, not a comment."""
    header = SNAPSHOT.read_text()
    assert "checked against:" in header
    assert "ArubaOS" in header


def test_every_status_is_one_the_format_defines():
    """An unrecognised status reads as 'fine' to a skimming eye."""
    bad = {status for status, *_ in snapshot_records()} - {OK, GAP, ABSENT}
    assert not bad, f"unknown status in the snapshot: {sorted(bad)}"


def test_nothing_unchecked_is_recorded_without_saying_why():
    """A bare 'gap' is indistinguishable from a line someone forgot about. The
    reason is the controller's own answer, carried through from the sweep, so a
    reader can tell 'no RADIUS server exists to enter' from 'the read failed'."""
    silent = [f"{cid}\t{kind}\t{line}"
              for status, cid, kind, line, reason in snapshot_records()
              if status != OK and not reason.strip()]
    assert not silent, ("recorded as unchecked with no reason:\n  "
                        + "\n  ".join(silent))


def test_platform_gaps_are_declared_in_code_not_just_in_the_file():
    """'absent' is a claim about hardware, and it has to be reviewable as code:
    a controller that grows the feature must make some test fail, or the
    exemption outlives the reason for it.

    Both directions. An entry in the table with no row in the snapshot means the
    catalog stopped emitting that line and the exemption is now permanent
    fiction; the sweep can never contradict a line it does not check.
    """
    recorded = {(cid, kind, line)
                for status, cid, kind, line, _ in snapshot_records()
                if status == ABSENT}
    assert recorded == set(PLATFORM_ABSENT), (
        f"only in the snapshot: {sorted(recorded - set(PLATFORM_ABSENT))}\n"
        f"only in PLATFORM_ABSENT: {sorted(set(PLATFORM_ABSENT) - recorded)}")


def test_the_unchecked_count_is_stated_where_a_reader_will_see_it():
    """A coverage number kept only in a tool's stdout is a number nobody reads
    twice. The point of writing it into the artifact is that a line nobody has
    ever run stays visible after the run that discovered it scrolls away."""
    assert "lines:" in SNAPSHOT.read_text()
    checked = sum(1 for status, *_ in snapshot_records() if status == OK)
    assert checked, "no line in the snapshot is recorded as checked at all"


@pytest.mark.parametrize("status", [OK, GAP, ABSENT])
def test_each_status_is_explained_in_the_snapshot_header(status):
    """The file is read by people who did not write it."""
    assert f"#   {status}" in SNAPSHOT.read_text()


def test_the_banner_text_region_is_pinned_as_text_not_as_commands():
    """The banner is the one control whose block is not a list of commands: two
    of its three lines are the message being stored. They belong in the snapshot
    — they are bytes this tool sends — but a reader has to be able to tell that
    they were never meant to parse."""
    banner = [r for r in snapshot_rows() if "AOS8-GLOBAL-BANNER-001" in r]
    assert "AOS8-GLOBAL-BANNER-001\tapply\tbanner motd <delim>" in banner
    assert "AOS8-GLOBAL-BANNER-001\tapply\t<approved text>" in banner
