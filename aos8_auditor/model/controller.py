"""Normalized controller facts.

``ControllerModel`` (the full object graph: global/management/snmp/network/aaa/
wireless/policy/wip) is filled by the parsers in :mod:`aos8_auditor.parse`.
:class:`ControllerFacts` is the small, stable, versioned fact bundle that the
control engine and the advisory module both rely on. We emit it as
``controller_facts.json`` so the advisory module can match a device's
version/platform/license set without re-parsing.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .evidence import NodeRole
from .version import AOSVersion, parse_aos_version

# Schema version for the facts artifact. Bump (and keep back-compatible) on any
# change, so consumers can assert they understand the shape.
FACTS_SCHEMA_VERSION = "1.0"


class ParsedVersion(BaseModel):
    raw: str | None = None
    train: str | None = None  # "8.6"
    base: str | None = None  # "8.6.0.4"
    suffix: str | None = None

    @classmethod
    def from_text(cls, text: str | None) -> "ParsedVersion":
        if not text:
            return cls()
        v: AOSVersion | None = parse_aos_version(text)
        if v is None:
            return cls(raw=text)
        return cls(raw=v.raw, train=v.train, base=v.base, suffix=v.suffix or None)


class ControllerFacts(BaseModel):
    facts_schema_version: str = FACTS_SCHEMA_VERSION
    host: str
    model: str | None = None
    platform_family: str | None = None
    serial: str | None = None
    role: NodeRole = NodeRole.UNKNOWN
    version: ParsedVersion = Field(default_factory=ParsedVersion)
    license_set: list[str] = Field(default_factory=list)
    feature_inventory: dict[str, str] = Field(default_factory=dict)
    node_paths: list[str] = Field(default_factory=list)
