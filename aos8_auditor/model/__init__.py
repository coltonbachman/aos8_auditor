"""Typed data shapes shared across layers."""

from .evidence import (
    CollectionResult,
    CommandResult,
    ControllerIdentity,
    Evidence,
    ExitKind,
    NodeRole,
    NodeTarget,
    slugify_command,
    utcnow_iso,
)
from .controller import ControllerFacts, ParsedVersion
from .version import AOSVersion, parse_aos_version, version_in_range

__all__ = [
    "CollectionResult",
    "CommandResult",
    "ControllerIdentity",
    "Evidence",
    "ExitKind",
    "NodeRole",
    "NodeTarget",
    "slugify_command",
    "utcnow_iso",
    "ControllerFacts",
    "ParsedVersion",
    "AOSVersion",
    "parse_aos_version",
    "version_in_range",
]
