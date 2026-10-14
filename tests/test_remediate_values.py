"""The non-interactive path: answers by file instead of by keyboard.

Two properties carry this module. A values file lands in a repository, so a secret
must never be expressible in it — only the name of an environment variable to read.
And a values file outlives the run it was made from, so it has to distinguish
"this control now passes" (fine) from "this answer is wrong" (not fine).
"""

from datetime import date
from pathlib import Path

import yaml

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.impact import impact_for
from aos8_auditor.engine.models import Finding, Severity, Status
from aos8_auditor.remediate import build_plan, context_from_config
from aos8_auditor.remediate.fields import FieldType
from aos8_auditor.remediate.plan import ChangeState, RemediationPlan, build_change
from aos8_auditor.remediate.validate import validate
from aos8_auditor.remediate.values import (
    apply_values,
    load_values,
    template_for,
)
from support import make_collection

CONFIG = Path(__file__).parent.parent / "fixtures" / "sample_running_config.txt"
CONTROLS = load_controls()
VRRP = "AOS8-NET-VRRP-AUTH-001"   # <id> number + <strong-non-default-secret>
ARP = "AOS8-FW-ARPSPOOF-001"      # no fields at all
SECRET = "correct-horse-battery-staple"
OWN_IP = "10.10.100.254"  # the controller's own address in the fixture


def _plan(*control_ids):
    rc = CONFIG.read_text()
    report = audit(make_collection(rc), CONTROLS, tool_version="test")
    ctx = context_from_config(rc, host="10.0.0.1")
    if not control_ids:
        return build_plan(report, ctx)
    by_id = {c.id: c for c in CONTROLS}
    changes = [build_change(Finding(
        control_id=cid, title=by_id[cid].title, category=by_id[cid].category,
        status=Status.FAIL, severity=Severity.HIGH,
        remediation_hint=by_id[cid].remediation_hint, impact=impact_for(cid)))
        for cid in control_ids]
    return RemediationPlan(report=report, context=ctx, changes=changes)


def _entry(**kw):
    return {"changes": [kw]}


# -- the template ---------------------------------------------------------

def test_the_template_never_has_a_place_to_put_a_secret():
    """A file with a password field is a file with a password in it."""
    plan = _plan(VRRP)
    text = template_for(plan)
    doc = yaml.safe_load(text)
    entry = doc["changes"][0]
    assert "strong-non-default-secret" not in (entry.get("values") or {})
    assert entry["secret_env"] == {"strong-non-default-secret": "CHANGE_ME"}


def test_the_template_lists_every_answerable_placeholder():
    plan = _plan("AOS8-GLOBAL-NTP-001")
    entry = yaml.safe_load(template_for(plan))["changes"][0]
    plain = {f.placeholder.strip("<>") for f in plan.changes[0].fields if not f.is_secret}
    assert set(entry["values"]) == plain


def test_the_template_defaults_to_accepting_nothing():
    """Generating a file and piping it straight back must be a no-op, not a
    silent yes to every change on the controller."""
    plan = _plan()
    doc = yaml.safe_load(template_for(plan))
    assert doc["changes"] and all(e["accept"] is False for e in doc["changes"])
    report = apply_values(plan, doc)
    assert report.ok and not report.accepted and not report.skipped


def test_the_template_round_trips_through_the_loader(tmp_path):
    plan = _plan()
    path = tmp_path / "values.yaml"
    path.write_text(template_for(plan))
    assert load_values(path)["changes"]


def test_a_bare_list_is_accepted_as_the_changes(tmp_path):
    path = tmp_path / "values.yaml"
    path.write_text(yaml.safe_dump([{"control_id": ARP, "accept": True}]))
    assert load_values(path)["changes"][0]["control_id"] == ARP


# -- filling --------------------------------------------------------------

def test_a_filled_entry_accepts_the_change():
    plan = _plan(VRRP)
    report = apply_values(plan, _entry(control_id=VRRP, accept=True,
                                       values={"id": 7},
                                       secret_env={"strong-non-default-secret": "PW"}),
                          env={"PW": SECRET})
    assert report.ok and report.accepted == [VRRP]
    assert plan.changes[0].state is ChangeState.ACCEPTED
    assert plan.changes[0].rendered() == ["vrrp 7", f"authentication {SECRET}"]


def test_a_numeric_answer_does_not_have_to_be_quoted():
    """YAML turns 7 into an int; refusing it would be a papercut on every run."""
    plan = _plan(VRRP)
    apply_values(plan, _entry(control_id=VRRP, accept=True, values={"id": 7}))
    assert plan.changes[0].fields[0].value == "7"


def test_the_secret_comes_from_the_environment_and_nowhere_else():
    plan = _plan(VRRP)
    report = apply_values(plan, _entry(control_id=VRRP, accept=True,
                                       values={"id": 7,
                                               "strong-non-default-secret": SECRET}),
                          env={})
    assert not report.ok
    assert any("secret_env" in e for e in report.errors)
    assert SECRET not in "".join(plan.changes[0].rendered())


def test_an_unset_environment_variable_is_an_error_not_an_empty_password():
    plan = _plan(VRRP)
    report = apply_values(plan, _entry(control_id=VRRP, accept=True,
                                       values={"id": 7},
                                       secret_env={"strong-non-default-secret": "PW"}),
                          env={})
    assert not report.ok
    assert any("PW is not set" in e for e in report.errors)
    assert plan.changes[0].state is ChangeState.PENDING


def test_an_invalid_value_fails_exactly_as_it_would_on_screen():
    plan = _plan("AOS8-GLOBAL-NTP-001")
    report = apply_values(plan, _entry(control_id="AOS8-GLOBAL-NTP-001", accept=True,
                                       values={"ip": "10.20.30"}))
    expected = validate(next(f for f in plan.changes[0].fields
                             if f.type is FieldType.IP), "10.20.30", plan.context)
    assert not report.ok
    assert any(expected.message in e for e in report.errors)


def test_a_warning_does_not_block():
    """Nothing here probes the network, so a warning is a hint, not a verdict."""
    plan = _plan("AOS8-GLOBAL-NTP-001")
    fields = {f.type: f.placeholder.strip("<>") for f in plan.changes[0].fields}
    report = apply_values(plan, _entry(
        control_id="AOS8-GLOBAL-NTP-001", accept=True,
        values={fields[FieldType.IP]: OWN_IP, fields[FieldType.NUMBER]: 7},
        secret_env={fields[FieldType.SECRET]: "PW"}), env={"PW": SECRET})
    assert report.ok and report.accepted == ["AOS8-GLOBAL-NTP-001"]
    assert any("own address" in w for w in report.warnings)


def test_a_half_answered_entry_is_an_error_and_is_not_accepted():
    plan = _plan("AOS8-GLOBAL-NTP-001")
    report = apply_values(plan, _entry(control_id="AOS8-GLOBAL-NTP-001", accept=True))
    assert not report.ok
    assert plan.changes[0].state is ChangeState.PENDING


def test_leaving_accept_out_is_undecided_not_an_error():
    plan = _plan(ARP)
    report = apply_values(plan, _entry(control_id=ARP))
    assert report.ok and not report.accepted
    assert plan.changes[0].state is ChangeState.PENDING


# -- skipping -------------------------------------------------------------

def test_a_skip_with_an_expiry_records_accepted_risk():
    plan = _plan(ARP)
    report = apply_values(plan, _entry(control_id=ARP, skip={
        "reason": "upstream switch already blocks this",
        "expires": "2026-06-01"}))
    assert report.ok and report.skipped == [ARP]
    assert plan.changes[0].suppress_expires == "2026-06-01"


def test_a_skip_without_an_expiry_is_just_a_skip():
    plan = _plan(ARP)
    apply_values(plan, _entry(control_id=ARP, skip={"reason": "next window"}))
    assert plan.changes[0].state is ChangeState.SKIPPED
    assert plan.changes[0].suppress_expires is None


def test_accepted_risk_still_needs_a_reason():
    plan = _plan(ARP)
    report = apply_values(plan, _entry(control_id=ARP, skip={"expires": "2026-06-01"}))
    assert not report.ok and any("needs a reason" in e for e in report.errors)
    assert plan.changes[0].state is ChangeState.PENDING


def test_a_malformed_expiry_is_an_error():
    plan = _plan(ARP)
    report = apply_values(plan, _entry(control_id=ARP, skip={
        "reason": "documented elsewhere", "expires": "next june"}))
    assert not report.ok and any("YYYY-MM-DD" in e for e in report.errors)


def test_a_skip_wins_over_accept():
    """An entry that says both is a mistake; declining is the safe reading."""
    plan = _plan(ARP)
    apply_values(plan, _entry(control_id=ARP, accept=True, skip={"reason": "no"}))
    assert plan.changes[0].state is ChangeState.SKIPPED


def test_a_shorthand_string_skip_is_read_as_the_reason():
    plan = _plan(ARP)
    apply_values(plan, _entry(control_id=ARP, skip="handled by the upstream switch"))
    assert plan.changes[0].skip_reason == "handled by the upstream switch"


# -- belonging to a node --------------------------------------------------

def test_the_template_records_the_node_it_was_gathered_for():
    plan = _plan(ARP)
    assert yaml.safe_load(template_for(plan))["node_path"] == plan.node_path


def test_answers_for_another_node_are_not_applied_here():
    """Managed nodes on one Mobility Master run different configs, so answers
    gathered against one node describe a change set that does not exist on
    another. A mismatch is a skip, not an error: the caller loops over every node
    and exactly one of them is meant to match."""
    plan = _plan(ARP)
    report = apply_values(plan, {"node_path": "/md/Campus/somewhere-else",
                                 "changes": [{"control_id": ARP, "accept": True}]})
    assert report.ok and report.node_mismatch == "/md/Campus/somewhere-else"
    assert not report.accepted
    assert plan.changes[0].state is ChangeState.PENDING


def test_a_matching_node_applies_normally():
    plan = _plan(ARP)
    report = apply_values(plan, {"node_path": plan.node_path,
                                 "changes": [{"control_id": ARP, "accept": True}]})
    assert report.node_mismatch is None and report.accepted == [ARP]


def test_a_file_without_a_node_key_applies_anywhere():
    """Hand-written and pre-existing files have no node key; refusing them would
    break every values file that predates the scoping."""
    plan = _plan(ARP)
    report = apply_values(plan, _entry(control_id=ARP, accept=True))
    assert report.node_mismatch is None and report.accepted == [ARP]


# -- surviving a stale file ----------------------------------------------

def test_a_control_that_now_passes_is_a_note_not_a_failure():
    """A values file outlives the run it was made from, and a control that has
    since been fixed is a good outcome, not a broken file."""
    plan = _plan(ARP)
    report = apply_values(plan, _entry(control_id="AOS8-GONE-001", accept=True))
    assert report.ok
    assert report.unknown_controls == ["AOS8-GONE-001"]


def test_garbage_is_reported_rather_than_raised():
    """A pipeline needs the whole list of problems, not the first one."""
    plan = _plan(ARP)
    report = apply_values(plan, {"changes": ["not a mapping", 42, None]})
    assert not report.ok and len(report.errors) == 3


def test_an_empty_file_does_nothing():
    plan = _plan(ARP)
    report = apply_values(plan, {})
    assert report.ok and not report.accepted and not report.skipped


def test_apply_uses_the_supplied_environment_not_the_real_one(monkeypatch):
    """Otherwise a test — or a pipeline — silently picks up a stray export."""
    monkeypatch.setenv("PW", "leaked-from-the-real-environment")
    plan = _plan(VRRP)
    apply_values(plan, _entry(control_id=VRRP, accept=True, values={"id": 7},
                              secret_env={"strong-non-default-secret": "PW"}),
                 env={"PW": SECRET})
    assert "leaked-from-the-real-environment" not in "".join(plan.changes[0].rendered())


def test_today_is_injectable_so_the_suite_does_not_drift():
    plan = _plan(ARP)
    report = apply_values(plan, _entry(control_id=ARP, skip={
        "reason": "documented elsewhere", "expires": "2026-06-01"}),
        today=date(2026, 1, 1))
    assert report.ok
