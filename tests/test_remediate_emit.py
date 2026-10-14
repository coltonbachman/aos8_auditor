"""The three artifacts.

These are the only files a human ever pastes, so the properties worth asserting
are the ones a tired operator at 2am depends on: every block stands alone, nothing
incomplete pastes clean, no secret leaks into the file that gets attached to a
ticket, and nothing destructive can reach the disk no matter which layer produced
it.
"""

import json
import stat
from pathlib import Path

import pytest

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.impact import impact_for
from aos8_auditor.engine.models import Finding, Severity, Status
from aos8_auditor.remediate import build_plan, context_from_config
from aos8_auditor.remediate.emit import (
    RULE,
    THIN,
    ExportOptions,
    UnsafeExportError,
    _sha256,
    render_cfg,
    render_record,
    render_rollback,
    write_artifacts,
)
from aos8_auditor.remediate.plan import ChangeState, ImpactBand, RemediationPlan, build_change
from support import make_collection

CONFIG = Path(__file__).parent.parent / "fixtures" / "sample_running_config.txt"
CONTROLS = load_controls()
SECRET = "correct-horse-battery-staple"


def _report():
    rc = CONFIG.read_text()
    return audit(make_collection(rc), CONTROLS, tool_version="test"), rc


def _plan():
    report, rc = _report()
    return build_plan(report, context_from_config(rc, host="10.0.0.1"))


def _synthetic(*control_ids) -> RemediationPlan:
    """A plan holding exactly the controls named, whatever the fixture did."""
    report, rc = _report()
    by_id = {c.id: c for c in CONTROLS}
    changes = []
    for cid in control_ids:
        ctl = by_id[cid]
        changes.append(build_change(Finding(
            control_id=cid, title=ctl.title, category=ctl.category,
            status=Status.FAIL, severity=Severity.HIGH,
            remediation_hint=ctl.remediation_hint,
            impact=impact_for(cid), observed="observed value from the audit")))
    return RemediationPlan(report=report, context=context_from_config(rc),
                           changes=changes)


def _fill(change, **values):
    """Answer every field; secrets get SECRET unless overridden by placeholder."""
    for f in change.fields:
        key = f.placeholder.strip("<>")
        f.value = values.get(key, SECRET if f.is_secret else "7")
    return change


def _accept(change):
    change.state = ChangeState.ACCEPTED
    change.selected = True
    return change


def _live(text):
    """Only the lines that would actually be sent by a paste."""
    return [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("!")]


# -- structure ------------------------------------------------------------

def test_every_block_opens_and_closes_its_own_config_mode():
    """A block that relied on the mode a previous block left behind would apply
    into the wrong context if a reviewer pasted it on its own."""
    plan = _plan()
    for c in plan.actionable:
        _accept(_fill(c))
    live = _live(render_cfg(plan))
    depth = 0
    for line in live:
        if line == "configure terminal":
            assert depth == 0, "a block opened config mode inside another one"
            depth += 1
        elif line == "end":
            assert depth == 1, "an 'end' with no matching 'configure terminal'"
            depth -= 1
    assert depth == 0
    assert live.count("configure terminal") == len(plan.accepted)


def test_write_memory_is_never_a_live_command():
    """Persisting is the operator's step, deliberately. It is mentioned in a
    comment and nowhere else."""
    plan = _plan()
    for c in plan.actionable:
        _accept(_fill(c))
    for text in (render_cfg(plan), render_rollback(plan)):
        assert "write memory" in text
        assert "write memory" not in _live(text)


def test_rule_lines_are_a_fixed_width():
    assert len(RULE) == len(THIN) == 78


def test_every_disruptive_block_carries_its_own_stop_banner():
    """The file is ordered by dependency and lockout risk, not by impact, so a
    controller reboot can sit between two harmless changes. A banner claiming
    'everything below needs a window' would therefore be false — the warning has
    to attach to the block it describes."""
    plan = _plan()
    for c in plan.actionable:
        _accept(_fill(c))
    disruptive = [c for c in plan.ordered()
                  if c.band in (ImpactBand.AP, ImpactBand.CONTROLLER)]
    assert disruptive, "fixture no longer exercises a windowed change"
    lines = render_cfg(plan).splitlines()
    for c in disruptive:
        at = next(i for i, ln in enumerate(lines) if c.control_id in ln)
        above = "\n".join(lines[max(0, at - 12):at])
        assert "STOP —" in above, f"{c.control_id} has no stop banner"


def test_the_lockout_chain_is_still_last_even_past_a_reboot():
    """Ordering by impact would hoist the console-block change above a block of
    client-impacting ones, taking away the fallback path before the risky part."""
    plan = _plan()
    for c in plan.actionable:
        _accept(_fill(c))
    ids = [c.control_id for c in plan.ordered()]
    if "AOS8-MGMT-CONSOLE-BLOCK-001" in ids:
        assert ids[-1] == "AOS8-MGMT-CONSOLE-BLOCK-001"


def test_rollback_reverses_the_apply_order():
    plan = _plan()
    for c in plan.actionable:
        _accept(_fill(c))
    text = render_rollback(plan)
    positions = [text.index(c.control_id) for c in plan.ordered()]
    assert positions == sorted(positions, reverse=True)


def test_rollback_labels_the_rating_as_the_original_changes():
    """The rating describes applying the change, not reversing it. Printing it
    unlabelled in rollback.cfg would state something nobody measured."""
    plan = _synthetic("AOS8-GLOBAL-FIPS-001")
    _accept(_fill(plan.changes[0]))
    assert "(of the original change)" in render_rollback(plan)


# -- secrets --------------------------------------------------------------

def test_secrets_are_withheld_by_default_and_do_not_paste_clean():
    plan = _synthetic("AOS8-NET-VRRP-AUTH-001")
    _accept(_fill(plan.changes[0]))
    text = render_cfg(plan)
    assert SECRET not in text
    assert "! FILL IN" in text
    assert not any("authentication" in ln for ln in _live(text))


def test_secrets_are_written_only_when_the_operator_says_so():
    plan = _synthetic("AOS8-NET-VRRP-AUTH-001")
    _accept(_fill(plan.changes[0]))
    text = render_cfg(plan, ExportOptions(include_secrets=True))
    assert f"authentication {SECRET}" in _live(text)


def test_json_masks_secrets_even_when_the_cfg_carries_them():
    """remediation.json is the file that gets attached to a ticket."""
    plan = _synthetic("AOS8-NET-VRRP-AUTH-001")
    _accept(_fill(plan.changes[0]))
    opts = ExportOptions(include_secrets=True)
    doc = json.loads(render_record(plan, opts, cfg_sha256="x", rollback_sha256="y"))
    blob = json.dumps(doc)
    assert SECRET not in blob
    secret_field = [f for f in doc["changes"][0]["fields"] if f["secret"]][0]
    assert secret_field["value"] is None and secret_field["filled"] is True


# -- incomplete lines -----------------------------------------------------

def test_unfilled_placeholders_are_commented_out():
    """An unanswered line must not apply. Commenting it out is what makes the
    whole-file paste safe even when the operator stopped halfway."""
    plan = _synthetic("AOS8-GLOBAL-NTP-001")
    c = plan.changes[0]
    _accept(c)  # deliberately answered nothing
    text = render_cfg(plan)
    assert "! FILL IN" in text
    assert not any("ntp server" in ln for ln in _live(text))


def test_hand_edited_lines_are_marked_as_not_from_the_guide():
    plan = _synthetic("AOS8-FW-ARPSPOOF-001")
    c = _accept(_fill(plan.changes[0]))
    c.hand_edited[1] = "prohibit-ip-spoofing"
    text = render_cfg(plan)
    assert "[hand-edited]" in text
    assert "prohibit-ip-spoofing" in _live(text)


def test_skipped_changes_are_recorded_but_commented_out():
    plan = _synthetic("AOS8-FW-ARPSPOOF-001")
    c = _fill(plan.changes[0])
    c.state = ChangeState.SKIPPED
    c.skip_reason = "upstream firewall already does this"
    text = render_cfg(plan)
    assert "SKIPPED by the operator" in text
    assert "upstream firewall already does this" in text
    assert _live(text) == []


# -- the safety gate ------------------------------------------------------

def test_a_destructive_hand_edit_cannot_reach_a_file():
    """The parser refuses destructive verbs, but ^E and a recipe override both
    bypass the parser, so the finished text is checked one last time."""
    plan = _synthetic("AOS8-FW-ARPSPOOF-001")
    c = _accept(_fill(plan.changes[0]))
    c.hand_edited[1] = "reload"
    with pytest.raises(UnsafeExportError, match="destructive"):
        render_cfg(plan)


def test_a_destructive_recipe_override_cannot_reach_a_file():
    plan = _synthetic("AOS8-FW-ARPSPOOF-001")
    c = _accept(plan.changes[0])
    c.commands = ["write erase all"]
    c.fields = []
    with pytest.raises(UnsafeExportError):
        render_cfg(plan)


def test_the_word_reload_is_fine_inside_a_comment():
    """The gate reads live lines only — a note that explains a reboot must not
    be mistaken for one."""
    plan = _synthetic("AOS8-GLOBAL-FIPS-001")
    _accept(_fill(plan.changes[0]))
    render_cfg(plan)  # FIPS guidance mentions the reload; must not raise


def test_a_command_that_asks_a_question_cannot_reach_a_file():
    """A confirmation prompt is worse than a stall: the line under it is read as
    the answer, so the block silently loses a command and gains a reboot."""
    plan = _synthetic("AOS8-FW-ARPSPOOF-001")
    c = _accept(plan.changes[0])
    c.commands = ["controller-ip vlan 200"]
    c.fields = []
    with pytest.raises(UnsafeExportError, match="confirmation"):
        render_cfg(plan)


def test_a_banner_that_never_closes_cannot_reach_a_file():
    """Everything below an unterminated delimiter is swallowed into the banner —
    including the 'end' that closes the block and every command after it."""
    plan = _synthetic("AOS8-GLOBAL-BANNER-001")
    c = _accept(plan.changes[0])
    c.commands = ["banner motd ^", "Authorized use only."]
    c.fields = []
    with pytest.raises(UnsafeExportError, match="never closed"):
        render_cfg(plan)


def test_a_reload_in_the_banner_text_is_a_sentence_not_a_command():
    """The exemption the unterminated-region check exists to make safe: banner
    text is stored, not run, so the gate must read it as prose."""
    plan = _synthetic("AOS8-GLOBAL-BANNER-001")
    _accept(_fill(plan.changes[0],
                  **{"delim": "^",
                     "approved text": "Reload requests go to the service desk."}))
    assert "Reload requests" in render_cfg(plan)  # must not raise


# -- writing --------------------------------------------------------------

def test_write_artifacts_hashes_what_it_wrote(tmp_path):
    plan = _plan()
    for c in plan.actionable:
        _accept(_fill(c))
    result = write_artifacts(plan, tmp_path)
    assert result.cfg_sha256 == _sha256(result.remediation_cfg.read_text())
    assert result.rollback_sha256 == _sha256(result.rollback_cfg.read_text())
    doc = json.loads(result.remediation_json.read_text())
    assert doc["artifacts"]["remediation.cfg"]["sha256"] == result.cfg_sha256
    assert doc["artifacts"]["rollback.cfg"]["sha256"] == result.rollback_sha256


def test_artifacts_are_written_owner_only(tmp_path):
    """These files describe exactly where a controller is weak."""
    result = write_artifacts(_plan(), tmp_path)
    for p in (result.remediation_cfg, result.rollback_cfg, result.remediation_json):
        assert stat.S_IMODE(p.stat().st_mode) == 0o600, p


def test_the_record_says_nothing_was_applied(tmp_path):
    """Phase 1 is export-only, and the artifact must say so on its face."""
    doc = json.loads(write_artifacts(_plan(), tmp_path).remediation_json.read_text())
    assert doc["applied"] is False and doc["phase"] == 1


def test_an_empty_plan_still_produces_readable_files(tmp_path):
    """Accepting nothing is a legitimate outcome; it must not produce a file that
    looks like a crash."""
    plan = _plan()
    result = write_artifacts(plan, tmp_path)
    assert "END OF PROPOSED CHANGES" in result.remediation_cfg.read_text()
    assert _live(result.remediation_cfg.read_text()) == []
