"""Classifier: applicability gates, logic, attestation, profile overlay."""

import pytest

from aos8_auditor.engine.classifier import classify
from aos8_auditor.engine.loader import load_controls
from aos8_auditor.engine.models import ClassificationBasis, Status
from aos8_auditor.engine.profiles import resolve_overlay
from aos8_auditor.model.evidence import ControllerIdentity, ExitKind, NodeRole
from aos8_auditor.parse.model_builder import build_controller_model

from support import make_collection

CONTROLS = {c.id: c for c in load_controls()}


def _model(rc="", outputs=None, identity=None):
    return build_controller_model(make_collection(rc, outputs, identity=identity))


def _classify(cid, model, facts, profile="high_security", attestations=None):
    return classify(CONTROLS[cid], model, facts, active_profile=profile,
                    attestations=attestations or {}, overlay=resolve_overlay(profile))


def test_profile_gate_excludes_fips_only_in_baseline():
    m = _model("fips enable\n")
    f = _classify("AOS8-PHYS-TEL-001", m, {}, profile="baseline")
    assert f.status == Status.NOT_APPLICABLE
    assert "profile" in f.reason


def test_platform_gate_lcd_not_applicable_on_vmc():
    ident = ControllerIdentity(host="vmc", model="vmc", platform_family="vmc", role=NodeRole.STANDALONE)
    m = _model("", identity=ident)
    f = _classify("AOS8-GLOBAL-LCD-001", m, {})
    assert f.status == Status.NOT_APPLICABLE
    assert "platform" in f.reason


def test_condition_unknown_is_manual():
    # ha_required not provided -> VRRP control condition unknown -> manual
    m = _model("vrrp 10\n")
    f = _classify("AOS8-NET-VRRP-001", m, m.facts)  # no ha_required in facts
    assert f.status == Status.MANUAL
    assert "condition" in f.reason


def test_condition_false_is_not_applicable():
    m = _model("")
    f = _classify("AOS8-NET-VRRP-001", m, {**m.facts, "ha_required": False})
    assert f.status == Status.NOT_APPLICABLE


def test_evidence_denied_is_manual_not_fail():
    # mgmt_localauth denied to the read-only role -> manual (capability gated)
    m = _model("", outputs={"show mgmt-user local-authentication-mode":
                            ("You do not have permission", ExitKind.DENIED)})
    f = _classify("AOS8-MGMT-LOCALAUTH-001", m, {**m.facts, "require_external_only_auth": True})
    assert f.status == Status.MANUAL
    assert f.classification_basis == ClassificationBasis.CAPABILITY_GATED


def test_fact_unknown_routes_to_manual():
    # No FIPS evidence at all -> fips_enabled unknown -> manual, never fail.
    m = _model("hostname x\n")
    f = _classify("AOS8-GLOBAL-FIPS-001", m, m.facts)
    assert f.status == Status.MANUAL


def test_pass_and_fail_logic():
    m1 = _model("fips enable\n")
    assert _classify("AOS8-GLOBAL-FIPS-001", m1, m1.facts).status == Status.PASS
    # SNMP v1/v2c present -> fail
    m2 = _model("snmp-server community public\n")
    assert _classify("AOS8-GLOBAL-SNMP-001", m2, m2.facts).status == Status.FAIL
    # no v1/v2c -> pass
    m3 = _model("snmp-server enable trap\n")
    assert _classify("AOS8-GLOBAL-SNMP-001", m3, m3.facts).status == Status.PASS


def test_profile_overlay_escalates_warn_to_fail():
    # SSH pubkey absent -> base 'warn'; high_security overlay escalates to fail.
    m = _model("hostname x\n")
    base = _classify("AOS8-MGMT-SSH-PUBKEY-001", m, {}, profile="baseline")
    assert base.status == Status.WARN
    hi = _classify("AOS8-MGMT-SSH-PUBKEY-001", m, {}, profile="high_security")
    assert hi.status == Status.FAIL


def test_malformed_control_isolated_to_error_not_crash():
    from aos8_auditor.engine.models import ControlDef
    bad = ControlDef.model_validate({
        "id": "BAD-001", "title": "bad regex", "category": "c", "severity": "high",
        "applicability": {"requires_evidence": ["running_config"]},
        "evidence": [{"key": "running_config", "command": "show running-config"}],
        "logic": {"type": "first_match", "clauses": [
            {"when": {"source": "running_config", "predicate": "regex", "arg": "(unbalanced"}, "then": "pass"},
            {"else": "fail"}]},
    })
    m = _model("hostname x\n")
    f = classify(bad, m, m.facts, active_profile="high_security", overlay=resolve_overlay("high_security"))
    assert f.status == Status.ERROR
    assert "logic error" in (f.reason or "")


def test_condition_mixed_type_equality_is_not_unknown():
    from aos8_auditor.engine.applicability import eval_condition
    # equality yields a real bool even across types (must not degrade to None)
    assert eval_condition("stp_required == false", {"stp_required": False}) is True
    assert eval_condition("ha_required == true", {"ha_required": True}) is True
    assert eval_condition("x >= 5", {"x": "notnum"}) is None  # only ordering degrades


def test_attestation_resolves_manual_control():
    m = _model("")
    att = {"AOS8-INIT-001": {"status": "pass", "justification": "rotated 2026-05-01"}}
    f = _classify("AOS8-INIT-001", m, {}, attestations=att)
    assert f.status == Status.PASS
    assert f.classification_basis == ClassificationBasis.ATTESTATION
    assert "rotated" in (f.notes or "")
