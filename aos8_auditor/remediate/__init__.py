"""Guided remediation — turn a finished audit into a config change an operator applies.

Phase 1, which is all of this package, is **export only**. It reads a report,
walks the operator through the fixes one change at a time, and writes three files:

* ``remediation.cfg``  — the proposed change, in self-contained blocks
* ``rollback.cfg``     — the reverse, where a reverse exists
* ``remediation.json`` — the machine-readable record, with the .cfg hashes

Nothing here opens a session, sends a command, or touches a controller. The
auditor's read-only guarantee is unchanged: a human reads the file, edits it if
they disagree with it, and pastes it themselves.

An automatic apply path is deliberately not here. If it is ever built, its
permission model is "apply exactly this reviewed, hash-pinned artifact" rather
than a list of allowed verbs — which is why destructive commands are excluded at
the point the artifact is *built*, in :func:`emit._finalize`, not at the point one
would be sent.
"""

from .context import DeviceContext, context_from_config, context_from_model
from .emit import ExportOptions, ExportResult, UnsafeExportError, write_artifacts
from .fields import Field, FieldType, fields_for
from .hints import Segment, SegmentKind, is_destructive, parse_hint
from .plan import BAND_TITLE, Change, ChangeState, ImpactBand, RemediationPlan, build_plan
from .recipes import Recipe, recipe_for
from .session import Session
from .suppress import entries_from_plan, write_suppressions
from .validate import ValidationResult, completions, validate
from .values import ApplyReport, apply_values, load_values, template_for

__all__ = [
    "BAND_TITLE",
    "ApplyReport",
    "Change",
    "ChangeState",
    "DeviceContext",
    "ExportOptions",
    "ExportResult",
    "Field",
    "FieldType",
    "ImpactBand",
    "Recipe",
    "RemediationPlan",
    "Segment",
    "SegmentKind",
    "Session",
    "UnsafeExportError",
    "ValidationResult",
    "apply_values",
    "build_plan",
    "completions",
    "context_from_config",
    "context_from_model",
    "entries_from_plan",
    "fields_for",
    "is_destructive",
    "load_values",
    "parse_hint",
    "recipe_for",
    "template_for",
    "validate",
    "write_artifacts",
    "write_suppressions",
]
