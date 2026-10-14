"""Vulnerability-scanner finding triage against the guide's false-positive table.

The guide's "Common False Positives" section (p.15-18) answers the single most
common question a PSIRT mailbox gets: *my scanner flagged the controller for
CVE-XXXX — is it real?* This module encodes that table
(``data/scanner_false_positives.yaml``) and, optionally, matches an operator's
scanner output against it.

Two properties matter more than coverage:

* **The certificate row is not a false positive.** The guide says so explicitly.
  A tool that let an operator wave away the default
  ``securelogin.arubanetworks.com`` certificate finding would be worse than no
  tool, so that row carries ``action_required`` and routes to the certificate
  control.
* **A match is not a clean bill of health.** Nothing here is scored, and nothing
  here suppresses a control. The vendor's position is about ArubaOS as shipped;
  the controller's version, licensed features and configuration still matter.
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources

import yaml

from .models import ScannerNote, ScannerTriage, ScannerTriageItem, ScannerVerdict

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


@lru_cache(maxsize=1)
def _load() -> tuple[str | None, str | None, tuple[ScannerNote, ...]]:
    try:
        text = resources.files("aos8_auditor.data").joinpath(
            "scanner_false_positives.yaml").read_text()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return None, None, ()
    data = yaml.safe_load(text) or {}
    notes = tuple(ScannerNote(**e) for e in (data.get("entries") or []))
    return data.get("version"), data.get("preamble"), notes


def corpus() -> list[ScannerNote]:
    return list(_load()[2])


def corpus_cves() -> set[str]:
    return {c.upper() for n in corpus() for c in n.cves}


def _match(finding: str) -> ScannerNote | None:
    """Match on CVE id first, then on a finding-name keyword.

    CVE first because it is exact: a scanner line naming CVE-2011-3389 is the
    BEAST row no matter how the tool words the title. Keyword matching is a
    fallback for the rows the guide lists by symptom rather than by CVE (the
    certificate warnings carry no CVE at all).
    """
    notes = _load()[2]
    ids = {c.upper() for c in _CVE_RE.findall(finding)}
    if ids:
        for n in notes:
            if ids & {c.upper() for c in n.cves}:
                return n
    low = finding.lower()
    best: ScannerNote | None = None
    best_len = 0
    for n in notes:
        for p in n.finding_patterns:
            if p and p.lower() in low and len(p) > best_len:
                best, best_len = n, len(p)
    return best


def triage(findings: list[str] | None = None, results=None) -> ScannerTriage:
    """Build the reference section, triaging ``findings`` when supplied.

    ``results`` is this run's findings; when given, each matched row reports the
    live status of the controls that close or fix it, so "the guide calls this a
    false positive" arrives next to "and the control that removes it is failing".
    """
    version, preamble, notes = _load()
    status_by = {f.control_id: f.status.value for f in (results or [])}

    items: list[ScannerTriageItem] = []
    for raw in findings or []:
        line = raw.strip()
        if not line:
            continue
        n = _match(line)
        if n is None:
            items.append(ScannerTriageItem(finding=line))
            continue
        controls = list(n.remediating_controls) + list(n.mitigating_controls)
        items.append(ScannerTriageItem(
            finding=line, matched=n.id, service=n.service, verdict=n.verdict,
            vendor_position=n.vendor_position, page=n.page, controls=controls,
            control_status={c: status_by[c] for c in controls if c in status_by}))

    counts: dict[str, int] = {"corpus_entries": len(notes), "corpus_cves": len(corpus_cves())}
    if items:
        counts["submitted"] = len(items)
        for i in items:
            counts[i.verdict.value] = counts.get(i.verdict.value, 0) + 1
    return ScannerTriage(version=version, preamble=preamble, corpus=list(notes),
                         counts=counts, items=items)


def load_findings(path: str) -> list[str]:
    """Read a scanner-findings file: one CVE id or finding title per line.

    Deliberately dumb — the point is that an operator can paste a column out of
    whatever their scanner exports. Blank lines and '#' comments are skipped.
    """
    from pathlib import Path

    out: list[str] = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


__all__ = ["corpus", "corpus_cves", "load_findings", "triage", "ScannerVerdict"]
