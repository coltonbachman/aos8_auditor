"""Orchestrate read-only collection into a persisted, replayable evidence bundle.

The collector is transport-agnostic: it needs only an object with a
``run(command, timeout_s=...) -> CommandResult`` method (the live
:class:`~aos8_auditor.transport.ssh_session.Session`, or a fake in tests). It
never decides pass/fail. On transport failure it returns a PARTIAL result with
the remaining commands marked ``SKIPPED`` rather than raising, so a flaky link
yields a useful-but-incomplete report and never half-mutates anything.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Protocol

from ..model.evidence import (
    CollectionResult,
    CommandResult,
    ControllerIdentity,
    ExitKind,
    NodeRole,
    NodeTarget,
    utcnow_iso,
)
from ..transport.topology import detect_identity
from .command_catalog import CAPABILITY_PROBE, COMMAND_CATALOG, CommandSpec


class _Runner(Protocol):
    def run(self, command: str, *, timeout_s: int | None = ...) -> CommandResult: ...


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


class Collector:
    def __init__(self, runner: _Runner | None, *, out_root: str | Path = "runs", run_id: str | None = None):
        self.runner = runner
        self.out_root = Path(out_root)
        self.run_id = run_id or _new_run_id()
        self.node_path = "/"  # current config node (changes on a Mobility Master)
        self._collected: dict[tuple[str, str], CommandResult] = {}  # (node, command) -> result
        self.results: list[CommandResult] = []
        self.warnings: list[str] = []
        self._transport_failed = False

    # -- collection --------------------------------------------------------
    def _run_once(self, command: str, timeout_s: int) -> CommandResult:
        key = (self.node_path, command)
        if key in self._collected:
            return self._collected[key]
        if self.runner is None or self._transport_failed:
            res = CommandResult(command=command, exit_kind=ExitKind.SKIPPED, node_path=self.node_path)
        else:
            try:
                res = self.runner.run(command, timeout_s=timeout_s)
                res.node_path = self.node_path  # tag with the node it was run at
            except Exception as e:  # TransportError or netmiko failure
                self._transport_failed = True
                self.warnings.append(f"transport failed during {command!r} at {self.node_path}: {e}; remaining commands skipped")
                res = CommandResult(command=command, exit_kind=ExitKind.SKIPPED,
                                    node_path=self.node_path, error_signature=type(e).__name__)
        self._collected[key] = res
        self.results.append(res)
        return res

    def _mark_skipped(self, command: str) -> CommandResult:
        key = (self.node_path, command)
        if key in self._collected:
            return self._collected[key]
        res = CommandResult(command=command, exit_kind=ExitKind.SKIPPED, node_path=self.node_path)
        self._collected[key] = res
        self.results.append(res)
        return res

    def collect(
        self,
        specs: Iterable[CommandSpec] = COMMAND_CATALOG,
        *,
        host: str | None = None,
    ) -> CollectionResult:
        started = utcnow_iso()
        specs = list(specs)

        # A primary that is DENIED to the read-only role, UNSUPPORTED on this
        # train, or errored/timed out should fall back to its alternates (e.g.
        # 'show banner' denied -> 'show running-config'). EMPTY is a legitimate
        # "no config" and SKIPPED means transport already failed — neither falls
        # back.
        _FALLBACK = {ExitKind.UNSUPPORTED, ExitKind.DENIED, ExitKind.ERROR, ExitKind.TIMEOUT}
        for spec in specs:
            res = self._run_once(spec.command, spec.timeout_s)
            if res.exit_kind in _FALLBACK and spec.alternates:
                for alt in spec.alternates:
                    alt_res = self._run_once(alt, spec.timeout_s)
                    if alt_res.usable:
                        break

        capability: dict[str, ExitKind] = {}
        for probe in CAPABILITY_PROBE:
            key = ("/", probe)
            capability[probe] = (self._collected[key].exit_kind if key in self._collected
                                 else self._run_once(probe, 60).exit_kind)

        identity = self._build_identity(host)
        return CollectionResult(
            run_id=self.run_id,
            controller=identity,
            nodes=[NodeTarget(node_path="/", role=identity.role)],
            results=self.results,
            capability=capability,
            collection_warnings=self.warnings,
            redaction_applied=True,
            started_at=started,
            finished_at=utcnow_iso(),
        )

    def collect_topology(self, specs: Iterable[CommandSpec] = COMMAND_CATALOG,
                         *, host: str | None = None) -> CollectionResult:
        """Collect from the connect node, then (on a Mobility Master) walk each
        managed device node and collect its per-node evidence. Standalone /
        Master-Local collapses to a single-node collect()."""
        from ..collection.command_catalog import GLOBAL_KEYS
        from ..transport.topology import enumerate_nodes

        specs = list(specs)
        base = self.collect(specs, host=host)  # connect node ("/" == /mm on an MM)
        nodes = enumerate_nodes(self._text("show configuration node-hierarchy"), self._text("show switches"))
        if not nodes or self._transport_failed:
            return base  # standalone / Master-Local / could not enumerate

        per_node = [s for s in specs if s.key not in GLOBAL_KEYS]
        supports_cd = self.runner is not None and hasattr(self.runner, "set_node")
        if not supports_cd:
            # Without read-only node navigation we cannot actually visit a managed
            # device — collecting its commands at the connect node would mislabel
            # the MM's own config as per-device. Record the nodes but do not walk.
            self.warnings.append(
                f"transport has no node navigation (cd); {len(nodes)} managed node(s) "
                "enumerated but NOT collected per-node — audit limited to the connect node")
            base.nodes = nodes
            base.controller.detected_topology = "mobility_master"
            base.collection_warnings = list(self.warnings)
            return base

        for nt in nodes:
            self.node_path = nt.node_path
            node_failed = self._transport_failed
            if not node_failed:
                try:
                    self.runner.set_node(nt.node_path)
                except Exception as e:
                    self.warnings.append(f"could not cd to {nt.node_path}: {e}; node marked skipped")
                    node_failed = True
            for spec in per_node:
                if node_failed:
                    self._mark_skipped(spec.command)  # keep the partial-result promise
                else:
                    self._run_once(spec.command, spec.timeout_s)
        try:
            self.runner.set_node("/mm")
        except Exception:
            pass
        self.node_path = "/"

        base.nodes = nodes
        base.results = self.results
        base.collection_warnings = list(self.warnings)
        base.controller.detected_topology = "mobility_master"
        return base

    def _build_identity(self, host: str | None) -> ControllerIdentity:
        version_text = self._text("show version")
        switchinfo = self._text("show switches") or self._text("show running-config")
        if version_text or host:
            return detect_identity(host or "unknown", version_text, switchinfo)
        return ControllerIdentity(host=host or "unknown", role=NodeRole.UNKNOWN)

    def _text(self, command: str, node: str = "/") -> str:
        r = self._collected.get((node, command))
        return r.redacted_output if r else ""

    # -- persistence / replay ---------------------------------------------
    def write_bundle(self, result: CollectionResult) -> Path:
        run_dir = self.out_root / result.run_id
        raw_dir = run_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        for r in result.results:
            if r.exit_kind == ExitKind.SKIPPED:
                continue
            slug = r.slug
            path = raw_dir / f"{slug}.txt"
            header = (
                f"# command: {r.command}\n# node: {r.node_path}\n"
                f"# exit_kind: {r.exit_kind.value}\n# captured: {r.started_at}\n"
                f"# sha256: {r.sha256}\n# redactions: {r.redaction_count} {r.redaction_kinds}\n"
                f"{'-' * 60}\n"
            )
            path.write_text(header + r.redacted_output, encoding="utf-8")
            try:
                path.chmod(0o600)
            except OSError:
                pass
            r.raw_ref = str(path.relative_to(self.out_root))

        result_path = run_dir / "collection_result.json"
        result_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        try:
            result_path.chmod(0o600)
        except OSError:
            pass

        manifest = {
            "run_id": result.run_id,
            "host": result.controller.host,
            "aos_version": result.controller.aos_version,
            "model": result.controller.model,
            "role": result.controller.role.value,
            "commands": [
                {"command": r.command, "exit_kind": r.exit_kind.value, "sha256": r.sha256, "raw_ref": r.raw_ref}
                for r in result.results
            ],
            "capability": {k: v.value for k, v in result.capability.items()},
            "warnings": result.collection_warnings,
        }
        (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        return run_dir

    @staticmethod
    def from_evidence(run_dir: str | Path) -> CollectionResult:
        """Reload a prior capture for offline re-classification (zero device access)."""
        path = Path(run_dir) / "collection_result.json"
        if not path.exists():
            raise FileNotFoundError(f"no collection_result.json under {run_dir}")
        return CollectionResult.model_validate_json(path.read_text(encoding="utf-8"))
