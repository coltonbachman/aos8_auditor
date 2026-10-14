"""Deterministic, idempotent pre-clean of captured CLI text before parsing.

Strips CLI prompts and pager noise and tolerates the PDF/transcript quoting
artifacts the hardening guide exhibits (e.g. the stray double-quote in
``alias user" any udp 68 69 deny`` at guide line 4009), while *recording* what
it touched so evidence can still be tied back. The sanitizer never deletes
config lines — it only removes prompt/footer noise and normalizes oddities.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# "(host) [mynode] #" / "(host) ^[mm] (config) #" prompt at the start of a line.
_PROMPT_RE = re.compile(r"^\([^)]*\)\s*\^?\[[^\]]*\]\s*(?:\([^)]*\)\s*)?[#>]\s?")
# Repeating PDF page footer/headers from the guide (harmless on live output).
_FOOTER_RE = re.compile(
    r"^(?:Aruba, a Hewlett Packard Enterprise company.*|.*Aruba OS Hardening Guide\s*|.*January 13, 2020\s*|\s*\d+\s*)$"
)
_PAGER_RE = re.compile(r"--More--\s*")
# 'banner <type> <delim> ...multiline... <delim>' -> collapse to 'banner <type>'
# so free-text banner content is not mis-parsed into config nodes.
_BANNER_RE = re.compile(r"(?is)(\bbanner\s+\w+)\s+(\S)(.*?)\2")


@dataclass
class SanitizeResult:
    text: str
    notes: list[str] = field(default_factory=list)


def sanitize(text: str, *, strip_footers: bool = False) -> SanitizeResult:
    """Return cleaned text plus a log of transformations.

    ``strip_footers`` is for ingesting PDF-extracted text; it is off by default
    so live ``show`` output is touched as little as possible.
    """
    if not text:
        return SanitizeResult(text="", notes=[])

    notes: list[str] = []
    if _BANNER_RE.search(text):
        text = _BANNER_RE.sub(r"\1", text)
        notes.append("collapsed banner block(s) to the directive line")
    out_lines: list[str] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = _PAGER_RE.sub("", raw)
        new = _PROMPT_RE.sub("", line)
        if new != line:
            notes.append(f"line {i}: stripped CLI prompt")
            line = new
        if strip_footers and _FOOTER_RE.match(line.strip()):
            notes.append(f"line {i}: dropped page footer/number")
            continue
        # Tolerate a stray unbalanced double-quote in alias/acl lines: keep the
        # line but record it, and remove the orphan quote so the tokenizer is
        # not thrown off. Only acts when there is an odd number of quotes.
        if line.count('"') % 2 == 1:
            notes.append(f"line {i}: removed unbalanced quote artifact")
            line = line.replace('"', "")
        out_lines.append(line)

    return SanitizeResult(text="\n".join(out_lines), notes=notes)
