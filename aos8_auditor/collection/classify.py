"""Classify a command's output into an :class:`ExitKind`.

AOS8 reports problems as human-readable text with a normal exit status, so we
must inspect the *text*. The hard part is not misreading real config as an error:

* A login **banner** ("...you do not have permission...") or an admin-chosen
  object **name**/description ("parse error block") must NOT be read as a
  device error — that would falsely fail every control keyed off the capture.
* Genuine AOS errors are short and/or prefixed with ``%``.

So we strip prompts, banner blocks, and quoted strings, then match signatures
either anywhere in *short* output (errors are 1-3 lines) or only on ``%``/``error``
prefixed lines in *large* output (e.g. a multi-KB ``show running-config``).
Signatures live in ``data/error_signatures.yaml`` (they drift across trains).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml

from ..model.evidence import ExitKind

# Strip leading CLI prompts like "(host) [mynode] #" / "(host) ^[mm] (config) #"
_PROMPT_RE = re.compile(r"^\([^)]*\)\s*\^?\[[^\]]*\]\s*(\([^)]*\)\s*)?[#>]\s?", re.MULTILINE)
# A banner block: 'banner <type> <delim> ...text... <delim>' (delim is one char).
_BANNER_RE = re.compile(r"(?is)\bbanner\s+\w+\s+(\S)(.*?)\1")
_QUOTED_RE = re.compile(r'"[^"]*"')

# Output with more than this many meaningful lines is treated as "large": only
# %/error-prefixed lines are trusted as error signals there.
_SMALL_MAX_LINES = 3


@dataclass(frozen=True)
class Signatures:
    denied: tuple[str, ...]
    unsupported: tuple[str, ...]
    error: tuple[str, ...]
    noise_prefixes: tuple[str, ...]


_DEFAULT = Signatures(
    denied=("you do not have permission", "access denied", "permission denied"),
    unsupported=("parse error", "invalid input", "unrecognized command", "% invalid", "not supported"),
    error=("error:",),
    noise_prefixes=("--More--",),
)


@lru_cache(maxsize=1)
def load_signatures() -> Signatures:
    try:
        text = resources.files("aos8_auditor.data").joinpath("error_signatures.yaml").read_text()
        data = yaml.safe_load(text) or {}
        return Signatures(
            denied=tuple(s.lower() for s in data.get("denied", [])),
            unsupported=tuple(s.lower() for s in data.get("unsupported", [])),
            error=tuple(s.lower() for s in data.get("error", [])),
            noise_prefixes=tuple(data.get("noise_prefixes", [])),
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return _DEFAULT


def _meaningful_lines(text: str, sigs: Signatures) -> list[str]:
    return [
        ln for ln in text.splitlines()
        if ln.strip() and not any(ln.lstrip().startswith(p) for p in sigs.noise_prefixes)
    ]


def classify_exit_kind(
    output: str,
    *,
    echoed_command: str | None = None,
    signatures: Signatures | None = None,
) -> tuple[ExitKind, str | None]:
    """Return ``(exit_kind, matched_signature)`` for a command's raw output.

    Precedence: DENIED > UNSUPPORTED > ERROR > EMPTY > OK.
    """
    sigs = signatures or load_signatures()
    text = output or ""

    cleaned = _PROMPT_RE.sub("", text)
    cleaned = _BANNER_RE.sub("banner", cleaned)  # neutralize banner content
    scan = _QUOTED_RE.sub('""', cleaned)  # neutralize admin-chosen names/descriptions

    scan_lines = _meaningful_lines(scan, sigs)
    small = len(scan_lines) <= _SMALL_MAX_LINES

    def find(siglist: tuple[str, ...]) -> str | None:
        for ln in scan_lines:
            low = ln.strip().lower()
            if small:
                for s in siglist:
                    if s in low:
                        return s
            elif low.startswith("%") or low.startswith("error"):
                for s in siglist:
                    if s in low:
                        return s
        return None

    if (s := find(sigs.denied)):
        return ExitKind.DENIED, s
    if (s := find(sigs.unsupported)):
        return ExitKind.UNSUPPORTED, s
    if (s := find(sigs.error)):
        return ExitKind.ERROR, s

    # EMPTY vs OK based on real (banner-preserved, prompt-stripped) content.
    content_lines = _meaningful_lines(cleaned, sigs)
    content = "\n".join(content_lines).strip()
    if echoed_command:
        content = content.replace(echoed_command.strip(), "", 1).strip()
    if not content:
        return ExitKind.EMPTY, None
    return ExitKind.OK, None
