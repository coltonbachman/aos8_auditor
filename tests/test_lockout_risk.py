"""`lockout_risk`: the flag that decides how carefully a change is applied.

This exists because the disruption rating cannot answer the question. Every
lockout-risky control is rated `low` — hot, management-plane only, no client
dropped and nothing rebooted — which is precisely the rating that reads as "safe
to apply unattended". Cutting off your own admin access is a different axis, so it
gets a different field.

The risk this file guards against is the flag and the prose drifting apart: the
`detail` text is what a human reads in the report, the flag is what the apply path
acts on, and a control where those two disagree is one where the tool's behaviour
does not match its own explanation.
"""

import re

import pytest

from aos8_auditor.engine.impact import impact_for, rated_control_ids
from aos8_auditor.engine.models import DisruptionLevel

# Curated, not derived. Deriving it from the prose is what the test below checks
# *against* — if both sides came from the same regex the test would be circular.
LOCKOUT = {
    "AOS8-INIT-001",                            # mistyped new admin password
    "AOS8-MGMT-LOCALAUTH-001",                  # no local fallback if AAA is unreachable
    "AOS8-MGMT-SSH-DISABLE-INSECURE-MGMT-001",  # you may be on the protocol being disabled
    "AOS8-MGMT-SSH-PUBKEY-001",                 # wrong/missing key mapped
    "AOS8-MGMT-WEBUI-CERTAUTH-001",             # wrong trusted-CA / serial mapping
    "AOS8-MGMT-CONSOLE-BLOCK-001",              # removes the emergency access path
    "AOS8-ADMIN-POLICY-002",                    # ACL that omits your own mgmt host
    "ADV-MGMT-RESTRICT",                        # same, via the advisory workaround
    "AOS8-FW-CP-ACL-001",                       # the classic control-plane deny
    "AOS8-PORTS-CAPTIVE-PORTAL-001",            # ordered deny above a permit you need
    "AOS8-NET-GW-001",                          # wrong gateway kills the return path
}

# Reads as a lockout risk but is not one.
NOT_LOCKOUT = {
    # "lockout" here is the name of the password-policy feature being enabled
    # (failed-attempt lockout), not something that happens to you.
    "AOS8-MGMT-PWDPOL-001",
    # Creates the netdestinations and the ACL object. Inert until ADMIN-POLICY-002
    # actually applies it to a port, which is the entry that carries the flag.
    "AOS8-ADMIN-POLICY-001",
}


@pytest.mark.parametrize("control_id", sorted(LOCKOUT))
def test_the_lockout_risky_controls_are_flagged(control_id):
    # impact_for falls back to the shared default, so an id that lost its entry
    # would quietly answer lockout_risk=False rather than raising.
    assert control_id in rated_control_ids(), f"{control_id} has no impact entry"
    assert impact_for(control_id).lockout_risk is True


@pytest.mark.parametrize("control_id", sorted(NOT_LOCKOUT))
def test_the_lookalikes_are_not_flagged(control_id):
    assert control_id in rated_control_ids(), f"{control_id} has no impact entry"
    assert impact_for(control_id).lockout_risk is False


def test_nothing_else_carries_the_flag():
    """A control flagged without a line here is a silent behaviour change."""
    flagged = {cid for cid in rated_control_ids() if impact_for(cid).lockout_risk}
    assert flagged == LOCKOUT


def test_every_flagged_control_explains_the_risk_to_a_human():
    """The flag changes what the tool does; the detail is what the operator reads.
    If a control acts risky but reads safe, the operator has no way to agree."""
    for control_id in sorted(LOCKOUT):
        detail = (impact_for(control_id).detail or "").lower()
        assert re.search(r"risk|lock|lose|cut|emergency|fallback|reachab", detail), (
            f"{control_id} is applied with extra ceremony but its detail never "
            f"says why: {detail!r}")


def test_the_flag_is_not_a_restatement_of_the_disruption_rating():
    """If lockout risk tracked `level`, it would not need to exist. It is worth
    keeping the case that motivates it visible: these are all rated as the safest
    kind of change there is."""
    levels = {impact_for(c).level for c in LOCKOUT}
    assert DisruptionLevel.LOW in levels
    assert not {DisruptionLevel.HIGH} >= levels, (
        "if every lockout-risky control were also a reboot, the change window "
        "would already be forcing the care this flag exists to force")


def test_the_default_is_no_risk():
    """A control with no explicit entry must not be treated as risky-by-default —
    that would make the loud confirmation meaningless through sheer volume."""
    assert impact_for("AOS8-GLOBAL-LCD-001").lockout_risk is False
