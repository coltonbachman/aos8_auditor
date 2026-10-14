"""Per-control remediation recipes: ordering hints and rollback commands.

The hint parser gets the command lines right for most of the catalog, so this
table is deliberately sparse — it carries only the two things a hint string
cannot express:

* **order** — a dependency hint, so a server group is created before the thing
  that references it and ``no mgmt-user localauth`` is never emitted ahead of the
  central authentication it depends on. Lower runs first; the default is 500.
* **rollback** — the inverse commands, where an inverse exists. Most are the
  obvious ``no`` form, but "obvious" is not something to guess at for a config
  that will be pasted into a production controller, so they are written out and
  reviewed rather than derived.

``lines`` overrides the parsed hint outright, for the handful of controls whose
hint prose the parser cannot safely split. Nothing here changes what the audit
reports — only what the wizard offers to write.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

import yaml

DEFAULT_ORDER = 500


@dataclass(frozen=True)
class Recipe:
    order: int = DEFAULT_ORDER
    lines: tuple[str, ...] = ()
    rollback: tuple[str, ...] = ()
    rollback_note: str | None = None
    notes: tuple[str, ...] = ()


_EMPTY = Recipe()


@lru_cache(maxsize=1)
def _load() -> dict[str, Recipe]:
    try:
        text = resources.files("aos8_auditor.data").joinpath("remediation_recipes.yaml").read_text()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return {}
    data = yaml.safe_load(text) or {}
    out: dict[str, Recipe] = {}
    for cid, d in (data.get("recipes") or {}).items():
        d = d or {}
        out[cid] = Recipe(
            order=int(d.get("order", DEFAULT_ORDER)),
            lines=tuple(d.get("lines") or ()),
            rollback=tuple(d.get("rollback") or ()),
            rollback_note=d.get("rollback_note"),
            notes=tuple(d.get("notes") or ()),
        )
    return out


def recipe_for(control_id: str) -> Recipe:
    return _load().get(control_id, _EMPTY)


def recipe_ids() -> set[str]:
    return set(_load())
