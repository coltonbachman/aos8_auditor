"""Engine contract: the shapes a control evaluation produces.

This module is the data contract (Status, Severity, ControlDef, Finding, Report)
that keeps the JSON report shape stable; the evaluator/predicate DSL and YAML
loader live in ``classifier``/``predicates``/``loader``. The advisory module
emits the same ``Finding`` shape into the same ``Report``.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from ..model.evidence import Evidence, utcnow_iso


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    MANUAL = "manual"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"  # command/parse/permission failure — never scored as pass/fail


# Statuses that participate in the weighted posture score denominator.
SCORED_STATUSES = {Status.PASS, Status.FAIL, Status.WARN}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MANUAL = "manual"  # non-scoring bucket
    INFORMATIONAL = "informational"  # non-scoring bucket


class ClassificationBasis(str, Enum):
    MACHINE = "machine"  # decided from collected evidence
    ATTESTATION = "attestation"  # rests on operator-supplied answer
    CAPABILITY_GATED = "capability_gated"  # evidence unavailable to the read-only role


class ControlSource(str, Enum):
    HARDENING_GUIDE = "hardening_guide"
    PSIRT_ADVISORY = "psirt_advisory"  # emitted by the advisory module


class DisruptionLevel(str, Enum):
    """How disruptive APPLYING this control's remediation is (the audit itself is
    always read-only and non-disruptive)."""

    NONE = "none"      # hot change, no impact to mgmt, clients, or APs
    LOW = "low"        # management-plane only / your own admin session may reconnect
    MEDIUM = "medium"  # brief data-plane impact: wireless clients reauth, or specific AP(s) reboot
    HIGH = "high"      # controller reboot / outage, or broad client/AP downtime


class RemediationImpact(BaseModel):
    """Operational impact of remediating a control. Advisory planning guidance."""

    level: DisruptionLevel = DisruptionLevel.LOW
    reboot_required: bool = False     # controller reload needed (full outage)
    client_impact: bool = False       # wireless clients deauth / reauthenticate
    ap_impact: bool = False           # one or more APs reboot
    mgmt_plane_only: bool = True       # change confined to the management plane
    detail: str | None = None         # plain-language description of what happens
    # Applying this can cut off your own admin access — a mistyped credential, an
    # ACL that omits your host, an auth server that turns out to be unreachable.
    # Orthogonal to `level`: every one of these is a hot, management-plane-only
    # change that disrupts no client and reboots nothing, which is exactly why the
    # disruption rating alone cannot be used to decide how carefully to apply it.
    lockout_risk: bool = False


class Applicability(BaseModel):
    platforms: list[str] = Field(default_factory=list)
    profiles: list[str] = Field(default_factory=list)
    requires_evidence: list[str] = Field(default_factory=list)
    condition: str | None = None


class Clause(BaseModel):
    when: dict | None = None  # {source, predicate, arg}
    then: Status | None = None
    else_: Status | None = Field(default=None, alias="else")

    model_config = {"populate_by_name": True}


class Logic(BaseModel):
    type: str = "first_match"  # all_of | any_of | first_match
    clauses: list[Clause] = Field(default_factory=list)


class EvidenceSpec(BaseModel):
    key: str
    command: str


class GuideDocument(str, Enum):
    """Which hardening guide backs a citation.

    Two complementary documents, not two editions of one: the Federal Technology
    Guide is deeper on FIPS/JITC posture, physical handling, licensing and VRRP;
    the Controller Hardening Guide is deeper on cryptography configuration,
    firewall/control-plane defense, open ports and scanner false positives.
    """

    FEDERAL_2020 = "federal_2020"        # Aruba OS Hardening Guide (Federal Technology Guide), v1.0, 2020-01-13
    CONTROLLER_2023 = "controller_2023"  # ArubaOS 8 Controller Hardening Guide, rev 10, 2023-01


class Reference(BaseModel):
    guide_section: str | None = None
    ref: str | None = None
    page: int | None = None
    document: GuideDocument = GuideDocument.FEDERAL_2020


class ControlDef(BaseModel):
    """Declarative control definition loaded from a ``controls/*.yaml`` file."""

    id: str
    title: str
    description: str | None = None
    category: str
    severity: Severity
    source: ControlSource = ControlSource.HARDENING_GUIDE
    applicability: Applicability = Field(default_factory=Applicability)
    evidence: list[EvidenceSpec] = Field(default_factory=list)
    logic: Logic | None = None
    manual_when: str | None = None
    remediation_hint: str | None = None
    references: list[Reference] = Field(default_factory=list)


class AdvisoryPrevents(BaseModel):
    """What applying an advisory workaround prevents (computed from the corpus).

    Counts/CVEs/years come straight from the advisory data; ``severity_counts`` is
    a HEURISTIC classification from each vulnerability's title (the corpus has no
    CVSS field) and is labeled as such in reports.
    """

    cve_count: int = 0
    cves: list[str] = Field(default_factory=list)
    advisories: list[str] = Field(default_factory=list)
    year_min: int | None = None
    year_max: int | None = None
    severity_counts: dict[str, int] = Field(default_factory=dict)  # heuristic, from titles
    config_workaround: bool = True


class Finding(BaseModel):
    """The result of evaluating one control (or, later, one advisory)."""

    control_id: str
    title: str
    category: str
    status: Status
    severity: Severity
    source: ControlSource = ControlSource.HARDENING_GUIDE
    applicability_resolved: bool = True
    classification_basis: ClassificationBasis = ClassificationBasis.MACHINE
    evidence: Evidence = Field(default_factory=Evidence)
    expected: str | None = None
    observed: str | None = None
    remediation_hint: str | None = None
    references: list[Reference] = Field(default_factory=list)
    confidence: str = "high"  # high | medium | low
    reason: str | None = None  # why not_applicable / manual / error
    impact: RemediationImpact | None = None  # disruption of applying the fix
    advisory: AdvisoryPrevents | None = None  # vulns this workaround prevents (advisory findings)
    suppressed: bool = False
    suppression_reason: str | None = None
    notes: str | None = None


class RunMetadata(BaseModel):
    schema_version: str = "1.0"
    tool_version: str
    controls_content_version: str | None = None
    run_id: str
    started_at: str = Field(default_factory=utcnow_iso)
    finished_at: str | None = None
    operator: str | None = None
    profile: str | None = None
    target: dict = Field(default_factory=dict)
    commands_run: list[str] = Field(default_factory=list)
    redaction_applied: bool = True
    suppression_warnings: list[str] = Field(default_factory=list)
    advisory_catalog_version: str | None = None  # set by the advisory module


class ScoreSummary(BaseModel):
    posture_score: float | None = None
    worst_severity_failed: Severity | None = None
    fips_gate: bool = False
    fips_gate_failed: bool = False
    weights: dict[str, float] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)  # status -> count
    matrix: dict[str, dict[str, int]] = Field(default_factory=dict)  # severity -> status -> count


class PortGuidance(str, Enum):
    """What the guide says about closing a documented open port."""

    DO_NOT_BLOCK = "do_not_block"          # blocking breaks the product
    RESTRICT = "restrict"                  # permitted, but limit the source
    BLOCK_IF_UNUSED = "block_if_unused"    # blockable when the feature is not in use
    SAFE_TO_BLOCK = "safe_to_block"        # blockable with no loss of service
    SEE_NOTES = "see_notes"                # conditional; read the notes


class PortUsage(str, Enum):
    """Whether the service behind a port is in use on THIS controller."""

    IN_USE = "in_use"
    NOT_NEEDED = "not_needed"
    UNKNOWN = "unknown"  # no backing fact, or the fact is undeterminable


class PortEntry(BaseModel):
    """One row of the guide's open-port table, annotated for this controller.

    ``purpose``/``notes`` are the guide's own wording; ``guidance`` normalises the
    notes; ``usage``/``blockable`` are computed from audit facts. Port state is
    never probed.
    """

    port: str
    transport: str | None = None  # the guide leaves it blank for a few rows
    purpose: str | None = None
    guidance: PortGuidance = PortGuidance.SEE_NOTES
    notes: str | None = None
    in_use_fact: str | None = None
    usage: PortUsage = PortUsage.UNKNOWN
    blockable: bool = False  # the guide permits closing it given this controller's state


class ControlPlaneProtocol(BaseModel):
    """One row of "Aruba Core Protocols & Ports" (guide p.30-53)."""

    name: str
    transport: str | None = None
    protocol: int | str | None = None
    ports: list[int] = Field(default_factory=list)
    flows: str | None = None
    description: str | None = None
    notes: str | None = None
    guidance: PortGuidance = PortGuidance.SEE_NOTES
    default_rules: list[str] = Field(default_factory=list)
    example_rules: list[str] = Field(default_factory=list)


class PortExposure(BaseModel):
    """Reference section: documented ports joined against this controller's facts."""

    controller_ports: list[PortEntry] = Field(default_factory=list)
    access_point_ports: list[PortEntry] = Field(default_factory=list)
    control_plane_protocols: list[ControlPlaneProtocol] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


class ScannerVerdict(str, Enum):
    """The vendor's position on a vulnerability-scanner finding."""

    FALSE_POSITIVE = "false_positive"    # does not apply to ArubaOS
    ACTION_REQUIRED = "action_required"  # real; the administrator must fix it
    ACCEPTED_RISK = "accepted_risk"      # unfixable; vendor judged the risk acceptable
    BY_DESIGN = "by_design"              # intentional tradeoff or standards mandate
    UNKNOWN = "unknown"                  # not in the corpus — triage it yourself


class ScannerNote(BaseModel):
    """One row of the guide's "Common False Positives" table (p.15-18)."""

    id: str
    service: str
    page: int | None = None
    verdict: ScannerVerdict = ScannerVerdict.FALSE_POSITIVE
    cves: list[str] = Field(default_factory=list)
    finding_patterns: list[str] = Field(default_factory=list)
    vendor_position: str = ""
    mitigating_controls: list[str] = Field(default_factory=list)
    remediating_controls: list[str] = Field(default_factory=list)


class ScannerTriageItem(BaseModel):
    """One operator-supplied scanner finding, matched against the corpus."""

    finding: str                       # what the operator supplied, verbatim
    matched: str | None = None         # ScannerNote.id, or None if unmatched
    service: str | None = None
    verdict: ScannerVerdict = ScannerVerdict.UNKNOWN
    vendor_position: str | None = None
    page: int | None = None
    controls: list[str] = Field(default_factory=list)  # controls that close or fix it
    control_status: dict[str, str] = Field(default_factory=dict)  # control id -> this run's status


class ScannerTriage(BaseModel):
    """Reference corpus, plus the triage of any operator-supplied findings."""

    version: str | None = None
    preamble: str | None = None
    corpus: list[ScannerNote] = Field(default_factory=list)
    items: list[ScannerTriageItem] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


class Report(BaseModel):
    run_metadata: RunMetadata
    summary: ScoreSummary = Field(default_factory=ScoreSummary)
    results: list[Finding] = Field(default_factory=list)
    advisory_results: list[Finding] = Field(default_factory=list)  # set by the advisory module
    port_exposure: PortExposure | None = None  # reference data, never scored
    scanner_triage: ScannerTriage | None = None  # reference data, never scored
