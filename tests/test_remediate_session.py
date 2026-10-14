"""The wizard's decisions, without a terminal.

Everything interesting about the wizard is a rule about what the operator is
*not* allowed to do by accident: accept a block with an empty field, rewrite a
line from the hardening guide without meaning to, or record accepted risk with no
justification and no end date. Those rules live here, so they are testable.
"""

from datetime import date
from pathlib import Path

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.impact import impact_for
from aos8_auditor.engine.models import Finding, Severity, Status
from aos8_auditor.remediate import build_plan, context_from_config
from aos8_auditor.remediate.fields import FieldType
from aos8_auditor.remediate.plan import ChangeState, ImpactBand, RemediationPlan, build_change
from aos8_auditor.remediate.session import MIN_SKIP_REASON, Session
from support import make_collection

CONFIG = Path(__file__).parent.parent / "fixtures" / "sample_running_config.txt"
CONTROLS = load_controls()
TODAY = date(2026, 1, 1)


def _session(*control_ids):
    """A session over the fixture's real changes, or over the controls named."""
    rc = CONFIG.read_text()
    report = audit(make_collection(rc), CONTROLS, tool_version="test")
    ctx = context_from_config(rc, host="10.0.0.1")
    if control_ids:
        by_id = {c.id: c for c in CONTROLS}
        changes = [build_change(Finding(
            control_id=cid, title=by_id[cid].title, category=by_id[cid].category,
            status=Status.FAIL, severity=Severity.HIGH,
            remediation_hint=by_id[cid].remediation_hint, impact=impact_for(cid)))
            for cid in control_ids]
        plan = RemediationPlan(report=report, context=ctx, changes=changes)
    else:
        plan = build_plan(report, ctx)
    return Session(plan=plan, today=TODAY)


_PLAUSIBLE = {
    FieldType.SECRET: "correct-horse-battery-staple",
    FieldType.IP: "10.20.30.40",
    FieldType.NETMASK: "255.255.255.0",
    FieldType.VLAN_ID: "220",
    FieldType.INTERFACE: "0/0/1",
    FieldType.NUMBER: "7",
    FieldType.NAME: "corp-servers",
    FieldType.DELIMITER: "^",
    FieldType.TEXT: "Authorized use only",
}


def _answer(s, **overrides):
    """Fill every field with something its own validator accepts."""
    for i, f in enumerate(s.fields):
        key = f.placeholder.strip("<>")
        result = s.set_field(overrides.get(key, _PLAUSIBLE[f.type]), index=i)
        assert result.ok, f"test helper produced a bad {f.type.value}: {result.message}"
    return s


# -- accepting ------------------------------------------------------------

def test_a_change_with_an_empty_field_cannot_be_accepted():
    s = _session("AOS8-GLOBAL-NTP-001")
    assert "cannot accept" in s.accept()
    assert s.current.state is ChangeState.PENDING


def test_the_refusal_names_the_fields_that_are_missing():
    """'Cannot accept' with no reason makes the operator hunt for the problem."""
    s = _session("AOS8-GLOBAL-NTP-001")
    message = s.accept()
    for f in s.fields:
        assert f.placeholder in message


def test_a_fully_answered_change_accepts():
    s = _answer(_session("AOS8-GLOBAL-NTP-001"))
    assert "accepted" in s.accept()
    assert s.current.state is ChangeState.ACCEPTED


def test_an_invalid_value_is_not_stored():
    """The old value stands, so a typo cannot silently blank a good answer."""
    s = _session("AOS8-GLOBAL-NTP-001")
    ip = next(i for i, f in enumerate(s.fields) if f.type is FieldType.IP)
    s.set_field("10.20.30.40", index=ip)
    assert not s.set_field("10.20.30", index=ip).ok
    assert s.fields[ip].value == "10.20.30.40"


def test_the_queue_never_offers_a_change_with_no_command_form():
    """Prose-only controls belong in the export, but there is nothing for the
    operator to decide about them, so they are not questions."""
    s = _session()
    assert s.plan.manual
    manual = {c.control_id for c in s.plan.manual}
    assert not manual & {c.control_id for c in s.queue}


def test_changing_an_answer_takes_back_the_acceptance():
    """An accepted block describes a specific set of values. Editing one of them
    means nobody has approved what is now in the file."""
    s = _answer(_session("AOS8-GLOBAL-NTP-001"))
    s.accept()
    s.clear_field(0)
    assert s.current.state is ChangeState.PENDING


def test_accept_all_hot_skips_anything_not_ready():
    s = _session()
    s.accept_all_hot()
    for c in s.queue:
        if c.band is ImpactBand.NONE and c.unfilled():
            assert c.state is ChangeState.PENDING
    assert all(c.band is ImpactBand.NONE for c in s.plan.accepted)


# -- skipping and suppression --------------------------------------------

def test_a_plain_skip_needs_no_justification():
    """Most skips mean 'not this week'; the control keeps failing, as it should."""
    s = _session("AOS8-FW-ARPSPOOF-001")
    s.skip()
    assert s.current.state is ChangeState.SKIPPED
    assert s.current.suppress_expires is None


def test_a_suppression_needs_a_real_justification():
    s = _session("AOS8-FW-ARPSPOOF-001")
    assert "justification" in s.skip("no", suppress=True)
    assert s.current.state is ChangeState.PENDING
    assert s.current.suppress_expires is None


def test_a_suppression_gets_an_expiry_whether_or_not_one_was_given():
    """Risk that never expires is risk nobody revisits."""
    s = _session("AOS8-FW-ARPSPOOF-001")
    s.skip("upstream switch already blocks this", suppress=True, days=30)
    assert s.current.suppress_expires == "2026-01-31"


def test_an_explicit_expiry_wins():
    s = _session("AOS8-FW-ARPSPOOF-001")
    s.skip("carrying this until the switch refresh", suppress=True,
           expires="2026-06-30")
    assert s.current.suppress_expires == "2026-06-30"


def test_min_skip_reason_is_longer_than_a_shrug():
    assert MIN_SKIP_REASON > len("no")


def test_undo_clears_the_suppression_too():
    """Otherwise an undone skip still writes accepted risk to suppressions.yaml."""
    s = _session("AOS8-FW-ARPSPOOF-001")
    s.skip("documented compensating control", suppress=True)
    s.undo()
    assert s.current.state is ChangeState.PENDING
    assert s.current.suppress_expires is None and s.current.skip_reason is None


# -- hand editing ---------------------------------------------------------

def test_a_generated_line_is_locked_until_it_is_unlocked():
    s = _session("AOS8-FW-ARPSPOOF-001")
    assert "^E" in s.edit_line(0, "firewall attack-rate")
    assert not s.current.hand_edited


def test_an_unlocked_line_takes_the_operators_text():
    s = _session("AOS8-FW-ARPSPOOF-001")
    s.unlock_edit()
    s.edit_line(1, "prohibit-ip-spoofing")
    assert s.current.hand_edited[1] == "prohibit-ip-spoofing"


def test_the_unlock_does_not_survive_moving_to_another_change():
    """Otherwise one ^E early on leaves every later block editable by a stray key."""
    s = _session("AOS8-FW-ARPSPOOF-001", "AOS8-GLOBAL-NTP-001")
    s.unlock_edit()
    s.next()
    assert not s.edit_unlocked
    assert "^E" in s.edit_line(0, "ntp server 10.0.0.1")


def test_a_hand_edit_cannot_smuggle_in_a_second_command():
    """One line in, one line out — a newline would hide a command the reviewer
    never sees on the line they are reading."""
    s = _session("AOS8-FW-ARPSPOOF-001")
    s.unlock_edit()
    assert "cannot span lines" in s.edit_line(1, "prohibit-ip-spoofing\nreload")
    assert not s.current.hand_edited


def test_clearing_a_hand_edit_restores_the_guides_wording():
    s = _session("AOS8-FW-ARPSPOOF-001")
    s.unlock_edit()
    s.edit_line(1, "prohibit-ip-spoofing")
    s.edit_line(1, "   ")
    assert not s.current.hand_edited
    assert s.current.line(1) == s.current.commands[1]


def test_reset_discards_every_answer_and_edit():
    s = _answer(_session("AOS8-NET-VRRP-AUTH-001"))
    s.unlock_edit()
    s.edit_line(0, "vrrp 9")
    s.accept()
    s.reset()
    c = s.current
    assert c.state is ChangeState.PENDING and not c.hand_edited
    assert all(not f.filled for f in c.fields)
    assert not s.edit_unlocked


# -- navigation -----------------------------------------------------------

def test_next_pending_wraps_and_stops_when_everything_is_decided():
    s = _session()
    for c in s.queue:
        c.state = ChangeState.SKIPPED
    assert "every change has been decided" in s.next_pending()


def test_position_never_runs_past_the_end():
    s = _session("AOS8-FW-ARPSPOOF-001")
    s.next()
    assert s.position == "1/1"


# -- review ---------------------------------------------------------------

def test_export_warnings_says_when_nothing_was_accepted():
    s = _session()
    assert any("nothing has been accepted" in w for w in s.export_warnings())


def test_export_warnings_counts_the_undecided():
    s = _answer(_session("AOS8-NET-VRRP-AUTH-001", "AOS8-FW-ARPSPOOF-001"))
    s.accept()
    assert any("1 change(s) undecided" in w for w in s.export_warnings())


def test_export_warnings_names_hand_edited_changes():
    s = _answer(_session("AOS8-FW-ARPSPOOF-001"))
    s.unlock_edit()
    s.edit_line(1, "prohibit-ip-spoofing")
    s.accept()
    assert any("AOS8-FW-ARPSPOOF-001" in w and "hand-edited" in w
               for w in s.export_warnings())


def test_export_warnings_flags_entered_secrets():
    s = _answer(_session("AOS8-NET-VRRP-AUTH-001"))
    s.accept()
    assert any("secret value(s)" in w for w in s.export_warnings())


def test_export_warnings_name_a_value_the_config_does_not_recognise():
    """The failure this catches, from a real run: a session ACL name that the
    controller had never heard of was typed, warned about once, scrolled past,
    exported, and rejected mid-apply — after the block before it had landed."""
    s = _session("AOS8-ADMIN-POLICY-002")
    s.plan.context.objects["session_acls"] = {"validate-mgmt"}
    _answer(s, port="1/1/1", **{"admin-policy": "testing-admin-policy"})
    s.accept()
    warnings = s.export_warnings()

    assert any("<admin-policy>" in w and "session ACL" in w for w in warnings)
    assert any("<port>" in w and "not an interface seen" in w for w in warnings)
    assert all(w.startswith("AOS8-ADMIN-POLICY-002")
               for w in warnings if "<" in w)


def test_export_warnings_leave_alone_values_the_config_does_recognise():
    s = _session("AOS8-ADMIN-POLICY-002")
    s.plan.context.objects["session_acls"] = {"validate-mgmt"}
    _answer(s, port="0/0/0", **{"admin-policy": "validate-mgmt"})
    s.accept()

    assert not any("AOS8-ADMIN-POLICY-002" in w for w in s.export_warnings())


def test_summary_agrees_with_the_plan():
    s = _session()
    s.accept_all_hot()
    summary = s.summary()
    assert summary["accepted"] == len(s.plan.accepted)
    assert summary["total"] == len(s.queue)
    assert summary["score_projected"] >= summary["score_now"]


# -- values that are only wrong together ----------------------------------

def test_a_banner_whose_text_contains_the_delimiter_cannot_be_accepted():
    """Both values pass their own validator. Together they truncate the banner
    at the first delimiter — and the CLI is back at a config prompt from that
    point, so the rest of the operator's message is executed, not displayed."""
    s = _session("AOS8-GLOBAL-BANNER-001")
    _answer(s, **{"approved text": "Authorized use only ^ no exceptions"})
    message = s.accept()

    assert "cannot accept" in message
    assert "<approved text>" in message and "delimiter" in message
    assert s.current.state is ChangeState.PENDING


def test_a_banner_that_uses_a_delimiter_its_text_avoids_is_fine():
    s = _answer(_session("AOS8-GLOBAL-BANNER-001"))
    assert "accepted" in s.accept()
    assert s.current.rendered() == [
        "banner motd ^", "Authorized use only", "^"]
