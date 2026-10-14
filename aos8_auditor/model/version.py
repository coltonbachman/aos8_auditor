"""ArubaOS version parsing and comparison.

AOS versions are NOT plain semver. Real-world strings look like::

    8.2.0.0
    8.6.0.4
    8.6.0.4-2.3.1.0
    8.10.0.7_87826
    8.6.0.4-FIPS
    ArubaOS (MODEL: Aruba7240), Version 8.6.0.4

We parse the leading dotted-numeric components for ordering and keep the raw
string + suffix for display. Every PSIRT advisory match keys off this comparator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence

# Prefer a 'Version <x>' marker so we never grab an IP address / uptime that
# precedes the real version in 'show version' output.
_ANCHORED_RE = re.compile(r"(?i)version\s+(?P<core>\d+(?:\.\d+){1,7})(?P<suffix>[-_][0-9A-Za-z.\-_]+)?")
# Fallback: a dotted-numeric core (>=2 components) anywhere, plus optional suffix.
_VERSION_RE = re.compile(r"(?P<core>\d+(?:\.\d+){1,7})(?P<suffix>[-_][0-9A-Za-z.\-_]+)?")


@dataclass(frozen=True)
class AOSVersion:
    """A parsed ArubaOS version.

    ``components`` is the tuple used for ordering; ``train`` is the first two
    components (e.g. ``8.6``); ``raw`` is the original string for evidence.
    """

    raw: str
    components: tuple[int, ...]
    suffix: str = ""

    @property
    def train(self) -> str:
        return ".".join(str(c) for c in self.components[:2])

    @property
    def base(self) -> str:
        return ".".join(str(c) for c in self.components)

    def _cmp_key(self, width: int) -> tuple[int, ...]:
        padded = list(self.components) + [0] * (width - len(self.components))
        return tuple(padded[:width])

    def compare(self, other: "AOSVersion") -> int:
        """Return -1 / 0 / 1 comparing numeric components only (suffix ignored)."""
        width = max(len(self.components), len(other.components))
        a, b = self._cmp_key(width), other._cmp_key(width)
        return (a > b) - (a < b)

    def __lt__(self, other: "AOSVersion") -> bool:
        return self.compare(other) < 0

    def __le__(self, other: "AOSVersion") -> bool:
        return self.compare(other) <= 0

    def __gt__(self, other: "AOSVersion") -> bool:
        return self.compare(other) > 0

    def __ge__(self, other: "AOSVersion") -> bool:
        return self.compare(other) >= 0

    def __str__(self) -> str:
        return self.raw


def parse_aos_version(text: str) -> AOSVersion | None:
    """Extract an :class:`AOSVersion` from arbitrary text (e.g. ``show version``).

    Returns ``None`` if no dotted-numeric version can be found, so callers can
    distinguish "unknown version" from a real value rather than guessing.
    """
    if not text:
        return None
    m = _ANCHORED_RE.search(text) or _VERSION_RE.search(text)
    if not m:
        return None
    core = m.group("core")
    components = tuple(int(p) for p in core.split("."))
    suffix = (m.group("suffix") or "").lstrip("-_")
    return AOSVersion(raw=m.group(0), components=components, suffix=suffix)


_CONSTRAINT_RE = re.compile(r"^\s*(?P<op><=|>=|==|<|>)?\s*(?P<ver>\d+(?:\.\d+){1,5})\s*$")


def _coerce(v: AOSVersion | str) -> AOSVersion | None:
    if isinstance(v, AOSVersion):
        return v
    return parse_aos_version(v)


def version_in_range(version: AOSVersion | str, spec: str) -> bool | None:
    """Evaluate a comma-separated constraint spec against ``version``.

    Spec grammar: comma-separated constraints, ALL must hold (logical AND).
    Each constraint is ``<op><version>`` where op is one of
    ``>= <= > < ==`` (default ``==`` if omitted). Examples::

        ">=8.6.0.0,<8.6.0.10"
        "==8.2.0.0"
        ">=8.10.0.0"

    Returns ``None`` if the version is unparseable, so an advisory match never
    silently treats an unknown version as in/out of range.
    """
    ver = _coerce(version)
    if ver is None:
        return None
    constraints = [c for c in spec.split(",") if c.strip()]
    if not constraints:
        return None
    for c in constraints:
        m = _CONSTRAINT_RE.match(c)
        if not m:
            raise ValueError(f"unparseable version constraint: {c!r}")
        op = m.group("op") or "=="
        bound = parse_aos_version(m.group("ver"))
        if bound is None:
            raise ValueError(f"unparseable version in constraint: {c!r}")
        cmp = ver.compare(bound)
        ok = {
            "==": cmp == 0,
            ">=": cmp >= 0,
            "<=": cmp <= 0,
            ">": cmp > 0,
            "<": cmp < 0,
        }[op]
        if not ok:
            return False
    return True


def sort_versions(versions: Sequence[AOSVersion]) -> list[AOSVersion]:
    return sorted(versions, key=lambda v: v._cmp_key(6))
