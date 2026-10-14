"""PSIRT / security-advisory workaround data.

Packaged corpus for the advisory checker (``engine/advisories.py``), enabled with
``--checks advisories`` / ``--checks both``:

  * ``aos8_workarounds.csv`` — one row per disclosed CVE (advisory, title, CVE,
    vulnerability title, workaround). Override with ``--advisory-data <csv>``.
  * ``workarounds.yaml`` — the workaround *families* the CVEs cluster into
    (match patterns, remediation, change impact).

The checker consumes the same audit context as the hardening controls and emits
the same ``Finding`` shape into ``Report.advisory_results``, so scoring,
redaction, and reporting need no special-casing. Matching is fully offline. A
"workaround present" check asserts only whether the config indicator is there —
it reports fail/warn/manual and never claims a controller is "patched".
"""
