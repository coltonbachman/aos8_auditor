"""Evidence and collection data shapes.

These are the contract between the collection layer and everything downstream.
A ``CommandResult`` stores only REDACTED output text (redaction happens in the
collector before any of these objects are persisted), plus an ``exit_kind`` that
classifies *why* output is present/absent so the engine never mistakes
"role denied" or "command unsupported" for "feature disabled".
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class ExitKind(str, Enum):
    """Why a command produced (or failed to produce) usable evidence.

    Classified from AOS8 *output text*, never SSH exit status — AOS8 returns
    human-readable errors with a normal exit code.
    """

    OK = "ok"
    EMPTY = "empty"  # ran fine, no matching config/state present
    ERROR = "error"  # generic device error
    DENIED = "denied"  # read-only role not permitted to see this
    UNSUPPORTED = "unsupported"  # command not valid on this train/platform
    TIMEOUT = "timeout"  # read timed out
    SKIPPED = "skipped"  # not run (e.g. partial collection after failure)
    # The command did not fail — it opened a prompt and is waiting for an answer.
    # Distinct from TIMEOUT because the session is not stalled but *captured*: the
    # next thing written to the channel is consumed as the answer. See
    # Connection.interactive_prompt for how this is told apart from a slow device.
    INTERACTIVE = "interactive"


class NodeRole(str, Enum):
    STANDALONE = "standalone"
    MASTER = "master"
    LOCAL = "local"
    MM = "mm"  # Mobility Master
    MANAGED = "managed"  # managed device under MM
    UNKNOWN = "unknown"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def slugify_command(command: str) -> str:
    """Turn a command into a filesystem-safe slug for the raw evidence file."""
    slug = re.sub(r"[^a-z0-9]+", "-", command.strip().lower()).strip("-")
    return slug or "command"


class CommandResult(BaseModel):
    """One executed (or replayed) read-only command and its redacted output."""

    command: str
    redacted_output: str = ""
    exit_kind: ExitKind = ExitKind.OK
    node_path: str = "/"  # "/" for standalone; "/md/<group>/<dev>" on MM
    error_signature: str | None = None  # which signature matched, if any
    started_at: str | None = None
    duration_ms: int | None = None
    raw_ref: str | None = None  # path to runs/<id>/raw/<slug>.txt
    sha256: str | None = None
    redaction_count: int = 0
    redaction_kinds: list[str] = Field(default_factory=list)

    @property
    def slug(self) -> str:
        return slugify_command(self.command)

    def compute_sha256(self) -> str:
        digest = hashlib.sha256(self.redacted_output.encode("utf-8")).hexdigest()
        return digest

    @property
    def usable(self) -> bool:
        """True when output reflects real device state suitable for pass/fail."""
        return self.exit_kind in (ExitKind.OK, ExitKind.EMPTY)


class NodeTarget(BaseModel):
    node_path: str = "/"
    role: NodeRole = NodeRole.UNKNOWN
    platform_hint: str | None = None


class ControllerIdentity(BaseModel):
    host: str
    model: str | None = None
    platform_family: str | None = None  # e.g. "7200", "7000", "vmc", "mm"
    aos_version: str | None = None  # raw string from show version
    serial: str | None = None
    role: NodeRole = NodeRole.UNKNOWN
    detected_topology: str | None = None


class Evidence(BaseModel):
    """The evidence attached to a single control Finding (engine layer)."""

    commands: list[str] = Field(default_factory=list)
    matched: list[str] = Field(default_factory=list)  # the lines that drove the verdict
    raw_refs: list[str] = Field(default_factory=list)
    masked: bool = False  # a secret value was deliberately not evaluated
    node_context: str | None = None


class CollectionResult(BaseModel):
    """Everything captured in one read-only run, before classification.

    This is the unit that ``--from-evidence`` reloads for offline re-analysis,
    and the fact source the future advisory module consumes.
    """

    run_id: str
    controller: ControllerIdentity
    nodes: list[NodeTarget] = Field(default_factory=list)
    results: list[CommandResult] = Field(default_factory=list)
    capability: dict[str, ExitKind] = Field(default_factory=dict)
    collection_warnings: list[str] = Field(default_factory=list)
    redaction_applied: bool = True
    started_at: str | None = None
    finished_at: str | None = None

    def by_command(self, command: str, node_path: str | None = None) -> CommandResult | None:
        for r in self.results:
            if r.command == command and (node_path is None or r.node_path == node_path):
                return r
        return None
