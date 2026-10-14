"""Collection layer: safelisted read-only capture, redaction, evidence bundle.

Knows nothing about pass/fail. Its only output is a ``CollectionResult``.
"""

from .classify import classify_exit_kind, load_signatures
from .collector import Collector
from .command_catalog import (
    CAPABILITY_PROBE,
    COMMAND_CATALOG,
    CommandSpec,
    UnsafeCommandError,
    assert_safe,
    is_safe,
)
from .redaction import RedactionResult, is_masked, redact

__all__ = [
    "classify_exit_kind",
    "load_signatures",
    "Collector",
    "CAPABILITY_PROBE",
    "COMMAND_CATALOG",
    "CommandSpec",
    "UnsafeCommandError",
    "assert_safe",
    "is_safe",
    "RedactionResult",
    "is_masked",
    "redact",
]
