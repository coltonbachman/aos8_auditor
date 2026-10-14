"""Two questions asked of the controller before anything is sent to it.

    1. Is this the controller the audit ran against?
    2. Are these findings still true?

Both are asked entirely with read-only commands, and both have to be asked *now*
rather than trusted from the export. An artifact is a file: it can be carried to
the wrong controller, and it can sit for a week while someone else fixes half of
what it describes. Neither is a hypothetical — the second is the ordinary case
when an apply stops half-way and is resumed.

The answers are used narrowly. A control that has since been fixed is dropped
from the run rather than re-applied; a control whose current state cannot be
determined is dropped too, because "apply a change whose precondition you could
not check" is how a fix lands on a configuration it was not written for. Neither
of those stops the rest of the run. What stops the run is being on the wrong
controller.

The re-audit is a full read-only capture through the same collector the auditor
uses, so it is the same evidence, the same controls and the same classifier that
produced the artifact in the first place. Anything cheaper would be a second,
weaker opinion about what "still failing" means.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..collection.collector import Collector
from ..engine import audit, build_advisory_controls, load_controls
from ..engine.models import Report, Status
from ..model.evidence import CollectionResult, CommandResult, ControllerIdentity, ExitKind
from .. import __version__
from .approve import Artifact


class Drift(str, Enum):
    """What the controller says about one control, right now."""

    STILL_FAILING = "still_failing"          # apply it
    ALREADY_SATISFIED = "already_satisfied"  # someone got there first; skip
    UNDETERMINED = "undetermined"            # could not be evaluated; skip


@dataclass
class ControlDrift:
    control_id: str
    verdict: Drift
    status: Status | None = None
    observed_now: str | None = None
    observed_at_export: str | None = None
    reason: str | None = None

    @property
    def changed_but_still_failing(self) -> bool:
        """Still broken, but not in the way the plan described it."""
        return (self.verdict is Drift.STILL_FAILING
                and self.observed_at_export is not None
                and self.observed_now != self.observed_at_export)


@dataclass
class PreflightReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    drift: list[ControlDrift] = field(default_factory=list)
    identity: ControllerIdentity | None = None
    collection: CollectionResult | None = None
    report: Report | None = None
    skipped: bool = False  # dry run: the controller was never contacted

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def apply_ids(self) -> list[str]:
        return [d.control_id for d in self.drift if d.verdict is Drift.STILL_FAILING]

    def verdict_for(self, control_id: str) -> ControlDrift | None:
        for d in self.drift:
            if d.control_id == control_id:
                return d
        return None


class _ReadOnlyView:
    """The collector's runner interface, backed by an apply session's probe().

    The collector asks for ``run(command, timeout_s=...)``. Handing it the apply
    session directly would give it an object with ``send_block`` on it; this
    exposes only the read-only half, so the re-audit cannot write even by
    programming error.
    """

    def __init__(self, session):
        self._session = session

    def run(self, command: str, *, timeout_s: int | None = None) -> CommandResult:
        return self._session.probe(command, timeout_s=timeout_s)


def recheck(session, artifact: Artifact, control_ids: list[str], *,
            controls=None, tool_version: str = __version__) -> dict[str, Status | None]:
    """Re-evaluate a few controls from a fresh, narrow read-only capture.

    Used after each block lands. A full catalog capture per block would be the
    same work as a whole audit repeated once per change; this collects the
    running-config plus whatever else those particular controls name as evidence,
    which is what actually decides them.

    Returns ``{control_id: Status}``, with ``None`` where no verdict was reached —
    never a guess, because "we could not tell" and "it worked" have to stay
    distinguishable in the record of what was applied.
    """
    controls = controls if controls is not None else load_controls()
    wanted = [c for c in controls if c.id in set(control_ids)]
    if _has_advisory_changes(artifact):
        try:
            adv, _, _ = build_advisory_controls(None)
            wanted += [c for c in adv if c.id in set(control_ids)]
        except Exception:
            pass
    if not wanted:
        return {cid: None for cid in control_ids}

    commands = {"show running-config"}
    for c in wanted:
        commands.update(spec.command for spec in c.evidence)

    results = []
    for command in sorted(commands):
        try:
            results.append(session.probe(command))
        except Exception:
            return {cid: None for cid in control_ids}
    if not any(r.command == "show running-config" and r.usable for r in results):
        return {cid: None for cid in control_ids}

    collection = CollectionResult(
        run_id=f"recheck-{artifact.node_path}", controller=ControllerIdentity(
            host=artifact.target.get("host") or "unknown"),
        results=results, redaction_applied=True)
    source = artifact.record.get("source_run") or {}
    report = audit(collection, wanted, tool_version=tool_version,
                   active_profile=source.get("profile") or "high_security",
                   node_path=artifact.node_path)
    found = {f.control_id: f.status for f in report.results + report.advisory_results}
    return {cid: found.get(cid) for cid in control_ids}


def preflight(session, artifact: Artifact, *, tool_version: str = __version__,
              controls=None) -> PreflightReport:
    """Ask the controller both questions. Sends nothing but read-only commands."""
    r = PreflightReport()

    if getattr(session, "dry_run", False):
        r.skipped = True
        r.warnings.append(
            "dry run: the controller was not contacted, so nothing was checked "
            "against it. What follows is the artifact's own account of itself.")
        for c in artifact.record.get("changes") or []:
            r.drift.append(ControlDrift(
                control_id=c.get("control_id"), verdict=Drift.STILL_FAILING,
                observed_at_export=c.get("observed"),
                reason="not checked — dry run"))
        return r

    if artifact.node_path and artifact.node_path != "/":
        moved = session.probe(f"cd {artifact.node_path}")
        if moved.exit_kind not in (ExitKind.OK, ExitKind.EMPTY):
            r.errors.append(
                f"cannot reach node {artifact.node_path} on this controller "
                f"('cd' returned {moved.exit_kind.value}). The artifact was "
                "generated for that node and its blocks navigate to it.")
            return r

    # The collector's out_root is only used by write_bundle, which is not called
    # here: a preflight capture is for deciding, not for keeping.
    collector = Collector(_ReadOnlyView(session))
    # The address actually dialled, not the one the record remembers — passing the
    # recorded one would make the identity object agree with the record by
    # construction, and the comparison below would be checking nothing.
    connected_to = getattr(getattr(session, "config", None), "host", None)
    collection = collector.collect(host=connected_to or artifact.target.get("host"))
    r.collection = collection
    r.identity = collection.controller

    _check_capture(collection, collector.warnings, r)
    if not r.ok:
        return r

    _check_identity(artifact, collection.controller, r)
    if not r.ok:
        # Do not go on to describe the drift of a controller we have just decided
        # is the wrong one — every line of it would be about the wrong device.
        return r

    r.report = _reaudit(artifact, collection, tool_version=tool_version,
                        controls=controls)
    _check_drift(artifact, r)
    return r


def _check_capture(collection: CollectionResult, collector_warnings: list[str],
                   r: PreflightReport) -> None:
    """Is the capture good enough to draw a conclusion from?

    This has to be checked explicitly rather than inferred from the absence of an
    exception, because a read-only command reports its failure in the result
    instead of raising — which is right for an audit, where one denied command
    should not abandon the run, and wrong here, where a control that could not be
    evaluated would read as one that now passes.
    """
    for w in collector_warnings:
        r.errors.append(f"the read-only re-audit did not complete: {w}")

    rc = next((res for res in collection.results
               if res.command == "show running-config"), None)
    if rc is None or not rc.usable:
        why = "was not collected" if rc is None else f"returned {rc.exit_kind.value}"
        r.errors.append(
            f"cannot re-audit this controller: 'show running-config' {why}. "
            "Nearly every control is decided from it, so without it the drift "
            "check would report findings as fixed when they were merely "
            "unreadable.")
        return

    broken = [res for res in collection.results
              if res.exit_kind in (ExitKind.TIMEOUT, ExitKind.SKIPPED)]
    if broken:
        r.errors.append(
            f"{len(broken)} read-only command(s) did not come back "
            f"({', '.join(sorted({res.command for res in broken}))}). That is a "
            "link problem, not a device answer, and half a capture is not "
            "something to plan a change from.")


# --------------------------------------------------------------------------
# question 1: is this the same controller?
# --------------------------------------------------------------------------

def _check_identity(artifact: Artifact, ident: ControllerIdentity,
                    r: PreflightReport) -> None:
    target = artifact.target
    was_serial, now_serial = target.get("serial"), ident.serial
    was_model, now_model = target.get("model"), ident.model
    was_version, now_version = target.get("aos_version"), ident.aos_version

    if was_serial and now_serial and was_serial != now_serial:
        r.errors.append(
            f"this is not the controller the audit ran against: serial "
            f"{now_serial}, but the artifact was generated for {was_serial}.")
    if was_model and now_model and was_model != now_model:
        r.errors.append(
            f"this controller is a {now_model}; the artifact was generated for a "
            f"{was_model}. The plan may not be valid for this platform.")

    if was_version and now_version and was_version != now_version:
        if _same_train(was_version, now_version):
            r.warnings.append(
                f"the controller has been upgraded since the audit "
                f"({was_version} -> {now_version}). Same train, so the commands "
                "should still parse, but the drift check below is what actually "
                "confirms the findings survived it.")
        else:
            r.errors.append(
                f"the controller is running {now_version}; the artifact was "
                f"generated against {was_version}. Command syntax and defaults "
                "move between trains — re-audit and generate a fresh plan.")

    if not (was_serial and now_serial):
        # Worth saying out loud rather than passing quietly: the strongest check
        # available did not run, and the weaker ones cannot tell two identical
        # controllers apart.
        r.warnings.append(
            "could not confirm this is the same controller by serial number "
            "(one side did not report one). Model and version matched, which two "
            "sibling controllers would also do.")

    if (host := target.get("host")) and host != ident.host:
        r.warnings.append(
            f"connected to {ident.host}; the audit recorded {host}. Addresses and "
            "names change, so this is not treated as a different controller.")


def _same_train(a: str, b: str) -> bool:
    """8.6.0.4 and 8.6.0.9 are the same train; 8.6 and 8.10 are not."""
    def parts(v):
        return [p for p in str(v).replace("-", ".").split(".") if p.isdigit()][:2]
    pa, pb = parts(a), parts(b)
    return bool(pa) and pa == pb


# --------------------------------------------------------------------------
# question 2: are these findings still true?
# --------------------------------------------------------------------------

def _reaudit(artifact: Artifact, collection: CollectionResult, *,
             tool_version: str, controls=None) -> Report:
    controls = controls if controls is not None else load_controls()
    advisory_controls: list = []
    advisory_prevents: dict = {}
    if _has_advisory_changes(artifact):
        try:
            advisory_controls, advisory_prevents, _ = build_advisory_controls(None)
        except Exception:  # the corpus is optional data; drift just goes unknown
            advisory_controls, advisory_prevents = [], {}

    source = artifact.record.get("source_run") or {}
    return audit(
        collection, controls,
        tool_version=tool_version,
        active_profile=source.get("profile") or "high_security",
        node_path=artifact.node_path,
        advisory_controls=advisory_controls,
        advisory_prevents=advisory_prevents,
    )


def _has_advisory_changes(artifact: Artifact) -> bool:
    return any(c.get("source") == "psirt_advisory" or c.get("advisory")
               for c in artifact.record.get("changes") or [])


def _check_drift(artifact: Artifact, r: PreflightReport) -> None:
    findings = {f.control_id: f for f in
                (r.report.results + r.report.advisory_results)}

    for change in artifact.record.get("changes") or []:
        control_id = change.get("control_id")
        was_observed = change.get("observed")
        finding = findings.get(control_id)

        if finding is None:
            r.drift.append(ControlDrift(
                control_id=control_id, verdict=Drift.UNDETERMINED,
                observed_at_export=was_observed,
                reason="the control was not evaluated in the re-audit"))
            continue

        # WARN is deliberately not treated as satisfied: it is a partial fix, and
        # the block is the rest of it.
        if finding.status in (Status.FAIL, Status.WARN):
            verdict, reason = Drift.STILL_FAILING, None
        elif finding.status is Status.PASS:
            verdict, reason = Drift.ALREADY_SATISFIED, "already satisfied on the controller"
        elif finding.status is Status.NOT_APPLICABLE:
            verdict, reason = Drift.ALREADY_SATISFIED, "no longer applies to this controller"
        else:
            verdict = Drift.UNDETERMINED
            reason = (f"the re-audit could not decide this control "
                      f"({finding.status.value}"
                      f"{': ' + finding.reason if finding.reason else ''})")

        r.drift.append(ControlDrift(
            control_id=control_id, verdict=verdict, reason=reason,
            status=finding.status, observed_now=finding.observed,
            observed_at_export=was_observed))

    _summarise(r)


def _summarise(r: PreflightReport) -> None:
    satisfied = [d for d in r.drift if d.verdict is Drift.ALREADY_SATISFIED]
    undetermined = [d for d in r.drift if d.verdict is Drift.UNDETERMINED]
    changed = [d for d in r.drift if d.changed_but_still_failing]

    if satisfied:
        r.warnings.append(
            f"{len(satisfied)} change(s) are no longer needed and will be skipped: "
            + ", ".join(f"{d.control_id} ({d.reason})" for d in satisfied))
    if undetermined:
        r.warnings.append(
            f"{len(undetermined)} change(s) will be skipped because their current "
            "state could not be determined: "
            + ", ".join(f"{d.control_id} — {d.reason}" for d in undetermined))
    if changed:
        r.warnings.append(
            f"{len(changed)} change(s) still fail, but the controller no longer "
            "looks the way the plan describes it: "
            + ", ".join(d.control_id for d in changed)
            + ". Read those blocks again before continuing.")
    if not r.apply_ids:
        r.warnings.append(
            "nothing in this artifact still needs applying to this controller.")
