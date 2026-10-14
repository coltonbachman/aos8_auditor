"""Load and validate declarative controls from ``controls/**/*.yaml``.

Each YAML file is one control (or a list of controls). IDs must be unique. A
content hash over the loaded set is recorded in the report so "the audit changed"
becomes a precise "controls v1.3 -> v1.4".
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from .models import ControlDef


def _iter_yaml_paths(controls_dir: Path):
    for p in sorted(controls_dir.rglob("*.yaml")):
        # Skip the profile overlays directory — those are not controls.
        if "_profiles" in p.parts:
            continue
        yield p


def load_controls_from_dir(controls_dir: str | Path) -> list[ControlDef]:
    controls_dir = Path(controls_dir)
    if not controls_dir.exists():
        raise FileNotFoundError(f"controls directory not found: {controls_dir}")
    controls: list[ControlDef] = []
    seen: dict[str, str] = {}
    for path in _iter_yaml_paths(controls_dir):
        data = yaml.safe_load(path.read_text()) or {}
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not item:
                continue
            control = ControlDef.model_validate(item)
            if control.id in seen:
                raise ValueError(
                    f"duplicate control id {control.id!r} in {path} (also in {seen[control.id]})"
                )
            seen[control.id] = str(path)
            controls.append(control)
    return controls


def default_controls_dir() -> Path:
    """Path to the packaged ``controls/`` directory (resolved via package file)."""
    return Path(__file__).resolve().parent.parent / "controls"


def load_controls(controls_dir: str | Path | None = None) -> list[ControlDef]:
    return load_controls_from_dir(controls_dir or default_controls_dir())


def controls_content_version(controls: list[ControlDef]) -> str:
    blob = json.dumps(
        [c.model_dump(mode="json") for c in sorted(controls, key=lambda c: c.id)],
        sort_keys=True,
    )
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()[:16]
