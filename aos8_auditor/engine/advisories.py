"""Advisory (PSIRT) workaround module — vulnerability-exploitation prevention.

Reads the AOS 8 advisory corpus (``advisories/aos8_workarounds.csv``: one row per
CVE), clusters CVEs into workaround *families* (``advisories/workarounds.yaml``)
by matching each CVE's workaround text, and builds advisory ``ControlDef``s whose
remediation is the workaround and whose justification is "applying this prevents
N vulnerabilities (...) across M advisories" — counts taken straight from the
corpus. CVEs no config family claims fall through to a generated patch-only
advisory control.

Nothing here invents data: counts/CVEs/years come from the CSV; severity is a
HEURISTIC from each vulnerability title (the corpus has no CVSS) and is labeled
as heuristic wherever shown.
"""

from __future__ import annotations

import csv
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import AdvisoryPrevents, ControlDef, ControlSource


def _pkg_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "advisories"


@dataclass
class CveRecord:
    cve: str
    advisory: str
    vuln_title: str
    workaround: str
    year: int | None
    severity: str  # heuristic


_CVE_YEAR = re.compile(r"CVE-(\d{4})-")

# Heuristic severity from the vulnerability TITLE (no CVSS in the corpus). Matched
# with word boundaries so "rce" does not match inside "inteRCEption" and the
# phrase tokens stay precise. "(remote )?command execution" is included alongside
# "code execution" because the corpus uses both wordings for the same bug class.
_EXEC = re.compile(
    r"\b("
    r"remote code execution|remote command execution|command execution|code execution|"
    r"command injections?|os command|rce|"
    r"buffer overflows?|stack[- ]based buffer overflows?|heap[- ]based buffer overflows?|"
    r"stack overflows?|heap overflows?|deserializ\w*|sql injections?"
    r")\b")
_HIGH = re.compile(
    r"\b("
    r"arbitrary file (write|overwrite|read|deletion|download|upload)|"
    r"path traversal|directory traversal|xml external entity|xxe|"
    r"root of trust|bootloader|boot sequence|disable boot|privilege escalation"
    r")\b")
_MEDIUM = re.compile(
    r"\b("
    r"cross-site scripting|xss|information disclosure|sensitive information|"
    r"denial of service|dos|session (expiration|invalidation)|isolation bypass|"
    r"spoofing|interception|manipulation|bypass|forgery|frame injection|"
    r"out-of-bounds read|read buffer|asn\.1"
    r")\b")


def heuristic_severity(title: str) -> str:
    t = title.lower()
    if _EXEC.search(t):
        # An exec/overflow bug reachable without auth is the worst case.
        return "critical" if "unauthenticated" in t else "high"
    if _HIGH.search(t):
        return "high"
    if _MEDIUM.search(t):
        return "medium"
    return "medium"


def load_corpus(csv_path: str | Path | None = None) -> list[CveRecord]:
    path = Path(csv_path) if csv_path else _pkg_dir() / "aos8_workarounds.csv"
    out: list[CveRecord] = []
    for row in csv.DictReader(path.open(encoding="utf-8")):
        cve = (row.get("cve") or "").strip()
        if not cve:
            continue
        m = _CVE_YEAR.search(cve)
        title = (row.get("vulnerability_title") or "").strip()
        out.append(CveRecord(
            cve=cve, advisory=(row.get("advisory") or "").strip(),
            vuln_title=title, workaround=(row.get("workaround") or "").strip(),
            year=int(m.group(1)) if m else None, severity=heuristic_severity(title),
        ))
    return out


@dataclass
class Family:
    control: ControlDef
    match: list[str]
    config_workaround: bool
    exclude: list[str] = field(default_factory=list)
    claimed: list[CveRecord] = field(default_factory=list)


def load_families(families_path: str | Path | None = None) -> list[Family]:
    path = Path(families_path) if families_path else _pkg_dir() / "workarounds.yaml"
    data = yaml.safe_load(path.read_text()) or []
    families: list[Family] = []
    for item in data:
        item = dict(item)
        match = [m.lower() for m in item.pop("match", [])]
        # `exclude` substrings veto a match: needed where one advisory's generic
        # boilerplate (e.g. "block UDP/8211") is scoped to OTHER CVEs in the same
        # advisory, so a family must NOT claim a CVE whose workaround also carries
        # the "no available workaround for the PAPI vulnerabilities" disclaimer.
        exclude = [m.lower() for m in item.pop("exclude", [])]
        config_workaround = item.pop("config_workaround", True)
        item.setdefault("source", ControlSource.PSIRT_ADVISORY.value)
        # advisory controls that read config require running_config (denied -> manual)
        if item.get("logic"):
            item.setdefault("applicability", {}).setdefault("requires_evidence", ["running_config"])
        families.append(Family(control=ControlDef.model_validate(item),
                               match=match, config_workaround=config_workaround, exclude=exclude))
    return families


def _prevents(records: list[CveRecord], config_workaround: bool) -> AdvisoryPrevents:
    cves = sorted({r.cve for r in records})
    advisories = sorted({r.advisory for r in records if r.advisory})
    years = [r.year for r in records if r.year]
    sev: dict[str, int] = {}
    by_cve: dict[str, str] = {}
    for r in records:  # one severity per distinct CVE
        by_cve[r.cve] = r.severity
    for s in by_cve.values():
        sev[s] = sev.get(s, 0) + 1
    return AdvisoryPrevents(
        cve_count=len(cves), cves=cves, advisories=advisories,
        year_min=min(years) if years else None, year_max=max(years) if years else None,
        severity_counts=sev, config_workaround=config_workaround,
    )


def build_advisory_controls(
    csv_path: str | Path | None = None,
    families_path: str | Path | None = None,
) -> tuple[list[ControlDef], dict[str, AdvisoryPrevents], dict]:
    """Return (advisory controls, id->AdvisoryPrevents, corpus_meta)."""
    corpus = load_corpus(csv_path)
    families = load_families(families_path)

    claimed_cves: set[str] = set()
    for fam in families:
        for rec in corpus:
            wl = rec.workaround.lower()
            if any(pat in wl for pat in fam.match) and not any(x in wl for x in fam.exclude):
                fam.claimed.append(rec)
                claimed_cves.add(rec.cve)

    controls: list[ControlDef] = []
    prevents: dict[str, AdvisoryPrevents] = {}
    for fam in families:
        if not fam.claimed:
            continue  # a family that matches no CVE in this corpus is omitted
        controls.append(fam.control)
        prevents[fam.control.id] = _prevents(fam.claimed, fam.config_workaround)

    # Residual: CVEs no family claimed -> patch/upgrade only (honest, not dropped).
    residual = [r for r in corpus if r.cve not in claimed_cves]
    if residual:
        patch = ControlDef.model_validate({
            "id": "ADV-PATCH-ONLY",
            "title": "Vulnerabilities with no configuration workaround (patch / upgrade required)",
            "category": "advisory",
            "severity": "informational",
            "source": ControlSource.PSIRT_ADVISORY.value,
            "remediation_hint": "These CVEs have no configuration workaround on AOS-8 — upgrade to a "
                                "fixed ArubaOS release (see each advisory's Resolution section).",
        })
        controls.append(patch)
        prevents[patch.id] = _prevents(residual, config_workaround=False)

    distinct = {r.cve for r in corpus}
    years = [r.year for r in corpus if r.year]
    digest = hashlib.sha256(
        "\n".join(sorted(f"{r.cve}|{r.advisory}|{r.workaround}" for r in corpus)).encode()
    ).hexdigest()[:16]
    meta = {
        "total_cves": len(distinct),
        "advisories": len({r.advisory for r in corpus if r.advisory}),
        "year_min": min(years) if years else None,
        "year_max": max(years) if years else None,
        "config_mitigable_cves": len(claimed_cves),
        "patch_only_cves": len(distinct - claimed_cves),
        "version": f"sha256:{digest}",
    }
    return controls, prevents, meta
