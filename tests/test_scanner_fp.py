"""Scanner false-positive triage: corpus integrity, matching, and safety rails.

The dangerous failure mode here is the opposite of the rest of the tool: not a
false FAIL, but a false REASSURANCE. A row that wrongly says "false positive"
tells an operator to close a real ticket. So the certificate row, the unmatched
case, and the "this never suppresses a control" property get the most coverage.
"""

import re

import pytest

from aos8_auditor.engine import audit, load_controls
from aos8_auditor.engine.models import ScannerVerdict, Status
from aos8_auditor.engine.scanner_fp import corpus, corpus_cves, load_findings, triage
from aos8_auditor.reporting.html import render_html
from aos8_auditor.reporting.report import render_markdown

from support import make_collection

CONTROLS = load_controls()
ORG = {"deployment_profile": "high_security", "fips_required": True, "stp_required": False,
       "ha_required": True, "wip_required": True, "ipv6_required": False,
       "machine_auth_required": False, "require_external_only_auth": False,
       "require_cert_auth": False}


def _report(rc="hostname w\n", findings=None):
    return audit(make_collection(rc, {}), CONTROLS, tool_version="t",
                 active_profile="high_security", org_profile=ORG,
                 scanner_findings=findings)


def _one(finding):
    return triage([finding]).items[0]


# --------------------------------------------------------------------------
# Corpus integrity (guide p.15-18)
# --------------------------------------------------------------------------

def test_corpus_covers_every_service_row_in_the_guide():
    ids = {n.id for n in corpus()}
    assert ids == {"openssh", "ssh-aes-cbc", "sssd", "dns-responder", "web-server",
                   "tls-ssl", "tls-ssl-certificate", "ip-stack", "cryptography", "jquery"}


@pytest.mark.parametrize("cid,count", [("openssh", 25), ("tls-ssl", 9), ("jquery", 9),
                                       ("ip-stack", 3), ("web-server", 3)])
def test_cve_lists_match_the_guides_counts(cid, count):
    n = next(x for x in corpus() if x.id == cid)
    assert len(n.cves) == count
    assert len(set(n.cves)) == count, "duplicate CVE in the row"


def test_every_row_carries_the_vendors_own_position():
    for n in corpus():
        assert n.vendor_position.strip(), f"{n.id} has no vendor position"
        assert n.page, f"{n.id} has no page citation"


def test_no_cve_is_claimed_by_two_services():
    seen: dict[str, str] = {}
    for n in corpus():
        for c in n.cves:
            assert c not in seen, f"{c} claimed by both {seen.get(c)} and {n.id}"
            seen[c] = n.id
    assert len(corpus_cves()) == len(seen)


def test_referenced_controls_all_exist():
    ids = {c.id for c in CONTROLS}
    for n in corpus():
        for cid in n.mitigating_controls + n.remediating_controls:
            assert cid in ids, f"{n.id} references unknown control {cid}"


# --------------------------------------------------------------------------
# The certificate row is NOT a false positive — the guide says so explicitly
# --------------------------------------------------------------------------

def test_certificate_row_is_action_required_and_routes_to_the_cert_control():
    n = next(x for x in corpus() if x.id == "tls-ssl-certificate")
    assert n.verdict is ScannerVerdict.ACTION_REQUIRED
    assert n.remediating_controls == ["AOS8-MGMT-CERT-001"]
    assert "NOT false positives" in n.vendor_position
    # It must also carry no CVEs, so no CVE lookup can land on it and be told
    # "false positive" by a neighbouring row's verdict.
    assert n.cves == []


@pytest.mark.parametrize("finding", [
    "Untrusted TLS/SSL server X.509 certificate",
    "X.509 Certificate Subject CN Does Not Match the Entity Name",
    "SHA-1 based Signature in TLS/SSL Server X.509 Certificate",
    "TLS Server Certificate Modulus less than 2048 bits",
    "SSL Certificate Name Mismatch",
    "Self-signed certificate securelogin.arubanetworks.com",
])
def test_certificate_findings_are_never_dismissed(finding):
    item = _one(finding)
    assert item.verdict is ScannerVerdict.ACTION_REQUIRED, finding
    assert "AOS8-MGMT-CERT-001" in item.controls


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

@pytest.mark.parametrize("finding,expect", [
    ("CVE-2011-3389", "tls-ssl"),
    ("cve-2008-5161", "ssh-aes-cbc"),                      # case-insensitive
    ("OpenSSH 5.8 multiple vulnerabilities (CVE-2016-6210)", "openssh"),
    ("SWEET32 birthday attack", "tls-ssl"),
    ("DNS Server Cache Snooping Remote Information Disclosure", "dns-responder"),
    ("jQuery 1.11.0 reflected XSS", "jquery"),
    ("Apache server mod_info is publicly available", "web-server"),
    ("ICMP timestamp request remote date disclosure", "ip-stack"),
    ("SSH Weak MAC Algorithms Enabled", "ssh-aes-cbc"),
])
def test_findings_match_the_right_service(finding, expect):
    assert _one(finding).matched == expect, finding


def test_cve_beats_keyword_when_both_are_present():
    # The title says "SSL"; the CVE says jQuery. The exact identifier wins.
    assert _one("SSL/TLS issue reported as CVE-2020-11023").matched == "jquery"


def test_unmatched_finding_is_flagged_unknown_not_dismissed():
    item = _one("CVE-2099-99999 hypothetical future flaw")
    assert item.matched is None
    assert item.verdict is ScannerVerdict.UNKNOWN
    assert item.vendor_position is None


def test_blank_and_comment_lines_are_ignored(tmp_path):
    p = tmp_path / "findings.txt"
    p.write_text("# my nessus export\n\nCVE-2011-3389\n\n  CVE-2009-2410  \n")
    assert load_findings(str(p)) == ["CVE-2011-3389", "CVE-2009-2410"]
    assert len(triage(load_findings(str(p))).items) == 2


# --------------------------------------------------------------------------
# Safety rails: reference only, never scoring, never suppressing
# --------------------------------------------------------------------------

def test_triage_never_changes_a_finding_status():
    plain = _report()
    triaged = _report(findings=["CVE-2011-3389", "CVE-2016-6210", "Weak MAC"])
    assert ({f.control_id: f.status for f in plain.results}
            == {f.control_id: f.status for f in triaged.results})
    assert plain.summary.posture_score == triaged.summary.posture_score
    assert not any(f.suppressed for f in triaged.results)


def test_matched_rows_report_the_live_status_of_their_controls():
    r = _report(findings=["SSL Certificate Name Mismatch"])
    item = r.scanner_triage.items[0]
    status = {f.control_id: f.status.value for f in r.results}["AOS8-MGMT-CERT-001"]
    assert item.control_status["AOS8-MGMT-CERT-001"] == status


def test_corpus_is_reported_even_with_no_submitted_findings():
    r = _report()
    st = r.scanner_triage
    assert st is not None and st.corpus and not st.items
    assert st.counts["corpus_entries"] == 10 and st.counts["corpus_cves"] == len(corpus_cves())


@pytest.mark.parametrize("render", [render_markdown, render_html])
def test_section_renders_with_and_without_submitted_findings(render):
    for findings in (None, ["CVE-2011-3389", "SSL Certificate Name Mismatch"]):
        text = render(_report(findings=findings))
        assert "Common False Positives" in text
        # The reassurance rail must be restated wherever the corpus is printed.
        assert "nothing here suppresses a control" in text.lower()
        # The certificate row must never render under a false-positive label.
        cert_at = text.find("TLS/SSL Certificate")
        assert cert_at != -1
        assert "ACTION REQUIRED" in text


def test_status_enum_untouched_by_triage():
    # Guards against a future refactor routing triage verdicts into Status.
    assert not any(v.value in {s.value for s in Status} for v in ScannerVerdict)

# A scanner export is pasted in by an operator, but its contents are not under
# their control: a finding title can carry a scanned host's banner or a cert CN.
# Markdown passes raw inline HTML through to any renderer that allows it, so an
# unescaped value would execute when report.md is published to a wiki.
# report.html has always escaped these; the markdown path did not.
XSS = "backtick`<img src=x onerror=alert(1)>"


def _code_spans(line):
    """The text inside each code span, per the CommonMark matching-run rule."""
    return re.findall(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)", line)


def test_submitted_finding_stays_inside_one_code_span():
    md = render_markdown(_report(findings=[XSS]))
    line = next(ln for ln in md.splitlines() if "onerror" in ln)
    spans = _code_spans(line)
    assert len(spans) == 1, f"payload escaped its span: {line}"
    # The whole value, backtick and all, is contained -- so the renderer emits
    # it as text, never as a tag.
    assert spans[0][1].strip() == XSS
    assert "<" not in line[line.index(spans[0][1]) + len(spans[0][1]):]


def test_submitted_finding_is_escaped_in_html():
    html = render_html(_report(findings=[XSS]))
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html


def test_device_supplied_observed_value_cannot_inject_markup():
    """`observed` is joined lines of device output and renders outside a code
    span, so it needs escaping rather than fencing."""
    from aos8_auditor.reporting.report import _md_text

    assert _md_text("<img src=x onerror=alert(1)>") == "&lt;img src=x onerror=alert(1)>"
    assert _md_text("a & b") == "a &amp; b"
    # Real config text is left alone -- escaping must not corrupt the report.
    assert _md_text("ip access-list session foo") == "ip access-list session foo"
