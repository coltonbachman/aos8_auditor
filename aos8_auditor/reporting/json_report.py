"""Collection-coverage reporting.

The full control Report renderer (JSON + Markdown + HTML) lives in ``report.py``
and ``html.py``. This module summarizes a ``CollectionResult`` so the CLI can
show coverage (what was collected, what the read-only role could not see).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from ..model.evidence import CollectionResult, ExitKind


def collection_summary(result: CollectionResult) -> dict:
    counts = Counter(r.exit_kind.value for r in result.results)
    redactions = sum(r.redaction_count for r in result.results)
    denied = [r.command for r in result.results if r.exit_kind == ExitKind.DENIED]
    unsupported = [r.command for r in result.results if r.exit_kind == ExitKind.UNSUPPORTED]
    skipped = [r.command for r in result.results if r.exit_kind == ExitKind.SKIPPED]
    return {
        "run_id": result.run_id,
        "host": result.controller.host,
        "model": result.controller.model,
        "aos_version": result.controller.aos_version,
        "role": result.controller.role.value,
        "commands_total": len(result.results),
        "exit_kind_counts": dict(counts),
        "redactions_applied": redactions,
        "commands_denied_to_role": denied,
        "commands_unsupported": unsupported,
        "commands_skipped": skipped,
        "warnings": result.collection_warnings,
    }


def write_collection_summary(result: CollectionResult, path: str | Path) -> Path:
    p = Path(path)
    p.write_text(json.dumps(collection_summary(result), indent=2, sort_keys=True), encoding="utf-8")
    return p
