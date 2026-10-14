"""Skips that become suppressions — and the ones that must not.

A suppression hides a real failure from the posture score, so this module has one
job beyond writing YAML: refuse to write anything the next audit would reject or
that nobody will ever revisit.
"""

import stat
from datetime import date
from pathlib import Path

import pytest
import yaml

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.suppressions import apply_suppressions, load_suppressions
from aos8_auditor.remediate import build_plan, context_from_config
from aos8_auditor.remediate.plan import ChangeState
from aos8_auditor.remediate.session import Session
from aos8_auditor.remediate.suppress import (
    entries_from_plan,
    merge,
    read_existing,
    to_suppression_objects,
    write_suppressions,
)
from support import make_collection

CONFIG = Path(__file__).parent.parent / "fixtures" / "sample_running_config.txt"
CONTROLS = load_controls()
HOST = "wlc-test"  # the identity in support.make_collection


def _plan():
    rc = CONFIG.read_text()
    report = audit(make_collection(rc), CONTROLS, tool_version="test")
    return build_plan(report, context_from_config(rc, host="10.0.0.1"))


def _skipped(plan, index=0, **kwargs):
    s = Session(plan=plan, today=date(2026, 1, 1))
    s.goto(index)
    s.skip(**kwargs)
    return s.current


# -- which skips become entries ------------------------------------------

def test_a_plain_skip_writes_no_suppression():
    """'Not this week' is not 'we accept this risk'. The control must keep
    failing until someone fixes it."""
    plan = _plan()
    _skipped(plan, reason="doing it next maintenance window")
    assert entries_from_plan(plan) == []


def test_a_suppressed_skip_carries_reason_expiry_and_host():
    plan = _plan()
    c = _skipped(plan, reason="compensating control on the upstream switch",
                 suppress=True, days=90)
    entries = entries_from_plan(plan)
    assert len(entries) == 1
    assert entries[0] == {
        "control_id": c.control_id,
        "justification": "compensating control on the upstream switch",
        "expires": "2026-04-01",
        "host": HOST,
    }


def test_entries_are_scoped_to_the_host_the_auditor_will_match_on():
    """An unscoped suppression silences the control on every controller in the
    fleet, which is almost never what the operator meant.

    The scope is the controller's own identity, not the address the operator
    connected to: the auditor matches suppressions against ``identity.host``, so
    an entry keyed by the connection IP would silently never match.
    """
    plan = _plan()
    assert plan.context.host == "10.0.0.1"  # what the operator typed
    _skipped(plan, reason="risk accepted for this lab unit only", suppress=True)
    assert entries_from_plan(plan)[0]["host"] == HOST


def test_an_explicit_host_overrides_the_audited_one():
    plan = _plan()
    _skipped(plan, reason="risk accepted for this lab unit only", suppress=True)
    assert entries_from_plan(plan, host="wlc-dr")[0]["host"] == "wlc-dr"


# -- writing --------------------------------------------------------------

def test_the_file_it_writes_is_one_the_auditor_can_read(tmp_path):
    plan = _plan()
    c = _skipped(plan, reason="accepted until the hardware refresh", suppress=True)
    path = write_suppressions(tmp_path / "suppressions.yaml", entries_from_plan(plan))
    loaded = load_suppressions(path)
    assert [s.control_id for s in loaded] == [c.control_id]
    assert loaded[0].host == HOST


def test_it_actually_suppresses_the_finding_it_was_written_for(tmp_path):
    """The round trip that matters: skip it, write it, re-audit, see it excluded."""
    plan = _plan()
    c = _skipped(plan, reason="accepted until the hardware refresh", suppress=True)
    path = write_suppressions(tmp_path / "suppressions.yaml", entries_from_plan(plan))
    findings = [f.model_copy() for f in plan.report.results]
    apply_suppressions(findings, load_suppressions(path), host=HOST,
                       today=date(2026, 1, 2))
    assert next(f for f in findings if f.control_id == c.control_id).suppressed


def test_an_entry_with_no_expiry_is_refused_at_write_time(tmp_path):
    """Discovering this on the next run is worse: the operator believes the risk
    was recorded, and it silently was not."""
    with pytest.raises(ValueError, match="no expiry"):
        write_suppressions(tmp_path / "s.yaml",
                           [{"control_id": "X", "justification": "because"}])


def test_a_malformed_expiry_is_refused_at_write_time(tmp_path):
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        write_suppressions(tmp_path / "s.yaml", [
            {"control_id": "X", "justification": "because", "expires": "next year"}])


def test_a_missing_justification_is_refused_at_write_time(tmp_path):
    with pytest.raises(ValueError, match="justification"):
        write_suppressions(tmp_path / "s.yaml",
                           [{"control_id": "X", "expires": "2026-06-01"}])


def test_the_file_is_written_owner_only(tmp_path):
    path = write_suppressions(tmp_path / "s.yaml", [
        {"control_id": "X", "justification": "because", "expires": "2026-06-01"}])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_the_banner_explains_what_a_suppression_costs(tmp_path):
    path = write_suppressions(tmp_path / "s.yaml", [
        {"control_id": "X", "justification": "because", "expires": "2026-06-01"}])
    text = path.read_text()
    assert "excluded from the posture" in text and "expiry" in text


# -- merging --------------------------------------------------------------

def test_rerunning_the_wizard_replaces_rather_than_duplicates(tmp_path):
    """Two entries for the same control shadow each other, and the one that wins
    is whichever the loader happens to hit first."""
    path = tmp_path / "s.yaml"
    write_suppressions(path, [{"control_id": "X", "justification": "first pass",
                               "expires": "2026-06-01", "host": "10.0.0.1"}])
    write_suppressions(path, [{"control_id": "X", "justification": "second pass",
                               "expires": "2026-09-01", "host": "10.0.0.1"}])
    items = read_existing(path)
    assert len(items) == 1 and items[0]["justification"] == "second pass"


def test_a_different_host_is_a_different_entry(tmp_path):
    path = tmp_path / "s.yaml"
    write_suppressions(path, [{"control_id": "X", "justification": "lab unit",
                               "expires": "2026-06-01", "host": "10.0.0.1"}])
    write_suppressions(path, [{"control_id": "X", "justification": "dr unit",
                               "expires": "2026-06-01", "host": "10.0.0.2"}])
    assert len(read_existing(path)) == 2


def test_hand_written_entries_survive_a_wizard_run(tmp_path):
    """The file is the operator's, not the tool's."""
    path = tmp_path / "s.yaml"
    path.write_text(yaml.safe_dump({"suppressions": [
        {"control_id": "HAND-WRITTEN", "justification": "signed off by security",
         "expires": "2027-01-01"}]}))
    write_suppressions(path, [{"control_id": "X", "justification": "from the wizard",
                               "expires": "2026-06-01"}])
    assert {i["control_id"] for i in read_existing(path)} == {"HAND-WRITTEN", "X"}


def test_merge_can_be_turned_off(tmp_path):
    path = tmp_path / "s.yaml"
    write_suppressions(path, [{"control_id": "OLD", "justification": "old",
                               "expires": "2026-06-01"}])
    write_suppressions(path, [{"control_id": "NEW", "justification": "new",
                               "expires": "2026-06-01"}], merge_existing=False)
    assert [i["control_id"] for i in read_existing(path)] == ["NEW"]


def test_reading_a_file_that_is_not_there_is_not_an_error(tmp_path):
    assert read_existing(tmp_path / "nope.yaml") == []


def test_merge_keeps_a_stable_order():
    """Otherwise every wizard run produces a diff even when nothing changed."""
    a = [{"control_id": "B", "host": None}, {"control_id": "A", "host": None}]
    assert [e["control_id"] for e in merge(a, [])] == ["A", "B"]


def test_preview_objects_match_what_would_be_written():
    plan = _plan()
    _skipped(plan, reason="accepted until the hardware refresh", suppress=True)
    entries = entries_from_plan(plan)
    objects = to_suppression_objects(entries)
    assert [o.control_id for o in objects] == [e["control_id"] for e in entries]


def test_an_undone_skip_leaves_nothing_behind():
    plan = _plan()
    s = Session(plan=plan, today=date(2026, 1, 1))
    s.skip("accepted for now, documented elsewhere", suppress=True)
    s.undo()
    assert s.current.state is ChangeState.PENDING
    assert entries_from_plan(plan) == []
