"""Shared test helpers for building synthetic collections."""

from __future__ import annotations

from aos8_auditor.model.evidence import (
    CollectionResult,
    CommandResult,
    ControllerIdentity,
    ExitKind,
    NodeRole,
)


def make_collection(rc: str = "", outputs: dict | None = None, *, identity=None) -> CollectionResult:
    """Build a CollectionResult. ``outputs`` maps command -> (text, ExitKind)."""
    results = [CommandResult(command="show running-config", redacted_output=rc, exit_kind=ExitKind.OK)]
    for cmd, val in (outputs or {}).items():
        text, kind = val if isinstance(val, tuple) else (val, ExitKind.OK)
        results.append(CommandResult(command=cmd, redacted_output=text, exit_kind=kind))
    ident = identity or ControllerIdentity(
        host="wlc-test", model="7240", platform_family="7200",
        aos_version="8.6.0.4", role=NodeRole.STANDALONE,
    )
    return CollectionResult(run_id="test", controller=ident, results=results, redaction_applied=True)
