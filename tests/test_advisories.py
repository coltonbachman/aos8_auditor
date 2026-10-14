"""Phase 4 — advisory (PSIRT) workaround module.

Covers: corpus parse, CVE→family clustering accuracy (the user's explicit
concern: never attribute a UDP/8211 workaround to a UDP/8444 CVE), severity
heuristic labeling, patch-only residual honesty, audit wiring into a separate
`advisory_results` list (never scored into the hardening posture), and the
"applying this prevents N CVEs" justification rendering.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from support import make_collection  # noqa: E402

from aos8_auditor.engine import audit, build_advisory_controls, load_controls  # noqa: E402
from aos8_auditor.engine.advisories import (  # noqa: E402
    heuristic_severity,
    load_corpus,
    load_families,
)
from aos8_auditor.engine.models import Status  # noqa: E402
from aos8_auditor.reporting.report import (  # noqa: E402
    advisory_justification,
    advisory_rollup,
    render_markdown,
)

ORG = {"stp_required": False, "ha_required": False, "wip_required": False, "ipv6_required": False}


# --- corpus + clustering ---------------------------------------------------

def test_corpus_parses_year_and_severity():
    corpus = load_corpus()
    assert len(corpus) > 100
    rec = next(r for r in corpus if r.cve == "CVE-2024-42501")
    assert rec.year == 2024
    assert rec.severity in {"critical", "high", "medium"}
    # every record carries a workaround and an advisory id
    assert all(r.advisory for r in corpus)


def test_clustering_is_port_specific_no_cross_attribution():
    """The headline requirement: a UDP/8211 workaround must NEVER be counted under
    the UDP/8444 family and vice-versa."""
    controls, prevents, _ = build_advisory_controls()
    corpus = {r.cve: r for r in load_corpus()}

    p8211 = prevents["ADV-PAPI-8211"]
    p8444 = prevents["ADV-PAPI-8444"]
    # Each claimed CVE's workaround text literally contains that family's port.
    assert all("8211" in corpus[c].workaround for c in p8211.cves)
    assert all("8444" in corpus[c].workaround for c in p8444.cves)
    # And the families do not bleed into one another.
    assert not (set(p8211.cves) & set(p8444.cves))


def test_every_claimed_cve_actually_matches_its_family():
    """No family may claim a CVE whose workaround does not contain one of its
    declared match substrings (guards against silent over-counting)."""
    families = {f.control.id: f for f in load_families()}
    _, prevents, _ = build_advisory_controls()
    corpus = {r.cve: r for r in load_corpus()}
    for fid, fam in families.items():
        if fid not in prevents:
            continue
        for cve in prevents[fid].cves:
            wl = corpus[cve].workaround.lower()
            assert any(pat in wl for pat in fam.match), f"{fid} wrongly claims {cve}"


def test_counts_are_consistent_and_not_inflated():
    controls, prevents, meta = build_advisory_controls()
    corpus = load_corpus()
    distinct = {r.cve for r in corpus}
    assert meta["total_cves"] == len(distinct)
    # config-mitigable + patch-only partition the universe exactly.
    assert meta["config_mitigable_cves"] + meta["patch_only_cves"] == len(distinct)
    # cve_count equals the number of distinct CVEs listed (no duplicates).
    for adv in prevents.values():
        assert adv.cve_count == len(set(adv.cves)) == len(adv.cves)


def test_patch_only_residual_is_honest():
    controls, prevents, meta = build_advisory_controls()
    ids = {c.id for c in controls}
    if meta["patch_only_cves"]:
        assert "ADV-PATCH-ONLY" in ids
        patch = prevents["ADV-PATCH-ONLY"]
        assert patch.config_workaround is False
        assert patch.cve_count == meta["patch_only_cves"]


def test_heuristic_severity_labels():
    assert heuristic_severity("Unauthenticated Remote Code Execution") == "critical"
    assert heuristic_severity("Authenticated Command Injection") == "high"
    assert heuristic_severity("Reflected Cross-Site Scripting (XSS)") == "medium"
    assert heuristic_severity("Unspecified weakness") == "medium"


# --- red-team regressions: severity heuristic ------------------------------

def test_heuristic_handles_command_execution_and_plurals():
    # "command execution" (not just "code execution") must be exec-class, and the
    # plural "Injections" must still match — these were under-scored as medium.
    assert heuristic_severity("Authenticated Remote Command Execution in the CLI") == "high"
    assert heuristic_severity("Multiple Unauthenticated Command Injections in PAPI") == "critical"
    assert heuristic_severity("Unauthenticated Stack-based Buffer Overflows") == "critical"


def test_heuristic_rce_token_does_not_match_interception():
    # bare "rce" must not match inside "inteRCEption" -> stays medium, not high.
    assert heuristic_severity("Bi-Directional Traffic Interception via L2/L3 Manipulation") == "medium"


# --- audit wiring ----------------------------------------------------------

def test_advisory_results_are_separate_and_unscored():
    adv_controls, prevents, meta = build_advisory_controls()
    col = make_collection("hostname x\nfips enable\n", {"show fips": "Mode Enabled\n"})
    # hardening + advisory together
    rep = audit(col, load_controls(), tool_version="t", org_profile=ORG,
                advisory_controls=adv_controls, advisory_prevents=prevents,
                advisory_catalog_version=meta["version"])
    assert rep.results and rep.advisory_results
    adv_ids = {f.control_id for f in rep.advisory_results}
    # advisory controls never leak into the scored hardening results
    assert not (adv_ids & {f.control_id for f in rep.results})
    # the hardening posture score ignores advisory findings entirely
    base = audit(col, load_controls(), tool_version="t", org_profile=ORG)
    assert rep.summary.posture_score == base.summary.posture_score
    assert rep.run_metadata.advisory_catalog_version == meta["version"]


def test_advisory_only_run_has_empty_hardening_results():
    adv_controls, prevents, _ = build_advisory_controls()
    col = make_collection("hostname x\n")
    rep = audit(col, [], tool_version="t", org_profile=ORG,
                advisory_controls=adv_controls, advisory_prevents=prevents)
    assert rep.results == []
    assert len(rep.advisory_results) == len(adv_controls)


def test_applied_workaround_passes_and_is_counted_mitigated():
    adv_controls, prevents, _ = build_advisory_controls()
    # CPSec enabled -> ADV-CPSEC / ADV-PAPI-8211 / ADV-PAPI-8444 should PASS.
    cfg = "hostname x\ncontrol-plane-security\n cpsec-enable\n"
    rep = audit(make_collection(cfg), [], tool_version="t", org_profile=ORG,
                advisory_controls=adv_controls, advisory_prevents=prevents)
    cpsec = next(f for f in rep.advisory_results if f.control_id == "ADV-CPSEC")
    assert cpsec.status == Status.PASS
    roll = advisory_rollup(rep.advisory_results)
    assert roll["mitigated"] > 0
    # mitigated + exposed never double-count a CVE
    assert roll["mitigated"] + roll["exposed"] + roll["needs_verify"] <= roll["total_cves"]


def test_unapplied_workaround_fails_and_carries_justification():
    adv_controls, prevents, _ = build_advisory_controls()
    rep = audit(make_collection("hostname x\n"), [], tool_version="t", org_profile=ORG,
                advisory_controls=adv_controls, advisory_prevents=prevents)
    mgmt = next(f for f in rep.advisory_results if f.control_id == "ADV-MGMT-RESTRICT")
    assert mgmt.status in (Status.FAIL, Status.WARN)
    assert mgmt.advisory and mgmt.advisory.cve_count > 0
    just = advisory_justification(mgmt.advisory)
    assert "prevents exploitation" in just and "CVE" in just
    # rendered report contains the advisory section + heuristic disclaimer
    md = render_markdown(rep)
    assert "Vulnerability exploitation prevention" in md
    assert "severity heuristic" in md


def test_no_advisory_controls_means_no_section():
    rep = audit(make_collection("hostname x\n"), load_controls(), tool_version="t", org_profile=ORG)
    assert rep.advisory_results == []
    assert "Vulnerability exploitation prevention" not in render_markdown(rep)


# --- red-team regressions: clustering accuracy & detection logic -----------

# The 10 advisory-2023-002 CVEs whose "block UDP/8211" line is boilerplate scoped
# to OTHER (PAPI) vulns — their real mitigation is AP<->controller segmentation.
_MIS_8211 = ["CVE-2023-22762", "CVE-2023-22763", "CVE-2023-22764", "CVE-2023-22765",
             "CVE-2023-22766", "CVE-2023-22767", "CVE-2023-22768", "CVE-2023-22769",
             "CVE-2023-22770", "CVE-2023-22778"]


def test_papi_8211_excludes_misattributed_cli_rce_cves():
    """The owner's #1 concern: never tell the operator to 'close UDP/8211' for CVEs
    whose real workaround is something else."""
    _, prevents, _ = build_advisory_controls()
    p8211 = set(prevents["ADV-PAPI-8211"].cves)
    pcpsec = set(prevents["ADV-CPSEC"].cves)
    # none of the mis-attributed CVEs are claimed by the 8211 family ...
    assert not (p8211 & set(_MIS_8211))
    # ... and they remain covered by the correct family (segmentation/CPSec).
    assert set(_MIS_8211) <= pcpsec
    # genuine UDP/8211 PAPI CVEs are retained.
    assert "CVE-2023-22747" in p8211


def test_no_cve_lost_after_clustering_fixes():
    _, prevents, meta = build_advisory_controls()
    covered = set()
    for adv in prevents.values():
        covered |= set(adv.cves)
    assert len(covered) == meta["total_cves"]  # every CVE lands somewhere
    assert meta["config_mitigable_cves"] + meta["patch_only_cves"] == meta["total_cves"]


def test_deny_intra_vlan_family_removed_but_cve_still_covered():
    # deny-intra-vlan-traffic is an AOS-10/Instant construct, not an AOS-8 controller
    # command, so that family was removed; its CVE must still be covered elsewhere.
    controls, prevents, _ = build_advisory_controls()
    assert "ADV-WIFI-DENYINTRAVLAN" not in {c.id for c in controls}
    assert "CVE-2026-23812" in set(prevents["ADV-CPSEC"].cves)
    assert "CVE-2026-23812" in set(prevents["ADV-RADIUS-RADSEC"].cves)


def _adv_status(cfg, cid):
    adv, prev, _ = build_advisory_controls()
    rep = audit(make_collection(cfg), [], tool_version="t", org_profile=ORG,
                advisory_controls=adv, advisory_prevents=prev)
    return next(f for f in rep.advisory_results if f.control_id == cid).status


@pytest.mark.parametrize("cid,enable,disable", [
    ("ADV-WIFI-GROUPFRAMEBLOCK", "group-frame-block", "no group-frame-block"),
    ("ADV-WIFI-ENFORCEDHCP", "enforce-dhcp", "no enforce-dhcp"),
    ("ADV-WIFI-MFP", "mfp-capable", "no mfp-capable"),
])
def test_disabled_feature_never_reads_as_applied(cid, enable, disable):
    assert _adv_status(f"profile p\n {enable}\n", cid) == Status.PASS
    # the explicit 'no <feature>' disable must NOT be reported as applied
    assert _adv_status(f"profile p\n {disable}\n", cid) == Status.WARN


def test_bcastarp_default_on_logic_is_not_inverted():
    # default (line absent) = enabled = pass; explicit disable = warn.
    assert _adv_status("hostname x\n", "ADV-WIFI-BCASTARP") == Status.PASS
    assert _adv_status("no broadcast-filter arp\n", "ADV-WIFI-BCASTARP") == Status.WARN


def test_cpsec_header_without_enable_is_not_a_pass():
    # the 'control-plane-security' profile header appears even when CPSec is off.
    assert _adv_status("control-plane-security\n cpsec-enable\n", "ADV-CPSEC") == Status.PASS
    assert _adv_status("control-plane-security\n no cpsec-enable\n", "ADV-CPSEC") == Status.WARN


def test_8444_cpsec_does_not_falsely_pass():
    # CPSec is NOT a UDP/8444 workaround; cpsec-on must not clear the 8444 family.
    assert _adv_status("control-plane-security\n cpsec-enable\n", "ADV-PAPI-8444") == Status.FAIL
    assert _adv_status("ip access-list session p\n any any udp 8444 deny\n", "ADV-PAPI-8444") == Status.WARN


def test_bare_port_token_does_not_falsely_pass():
    # a stray token equal to the port (VLAN id, web port) must not read as a restriction.
    assert _adv_status("vlan 8211\n", "ADV-PAPI-8211") == Status.FAIL
    assert _adv_status("web-server\n port 8444\n", "ADV-PAPI-8444") == Status.FAIL
