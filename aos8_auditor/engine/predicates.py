"""The closed predicate DSL controls use in their logic clauses.

A predicate is ``fn(ctx, when) -> (bool, matched_lines)``. ``when`` is the clause
dict ``{source, predicate, arg}``. There is NO arbitrary code/eval — only this
registry is callable from YAML, which keeps captured device output from ever
being executed and keeps control logic reviewable.

Two source families:
* text sources (an evidence key or ``running_config``) — regex/line/substring.
* the ``fact`` source — typed lookups into the computed facts dict, including an
  explicit ``fact_unknown`` so a control can route an undeterminable fact to
  ``manual`` instead of a false fail.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Ctx:
    source_text: Callable[[str], str]
    facts: dict = field(default_factory=dict)

    def text(self, when: dict) -> str:
        return self.source_text(when.get("source", "running_config"))


class PredicateError(ValueError):
    pass


def _matching_lines(text: str, pattern: str, limit: int = 5) -> list[str]:
    out = []
    rx = re.compile(pattern, re.IGNORECASE)
    for ln in text.splitlines():
        if rx.search(ln):
            out.append(ln.strip())
            if len(out) >= limit:
                break
    return out


# -- text predicates -------------------------------------------------------
def _regex(ctx: Ctx, when: dict):
    text, pat = ctx.text(when), when["arg"]
    ok = bool(re.search(pat, text, re.IGNORECASE | re.MULTILINE))
    return ok, _matching_lines(text, pat)


def _regex_absent(ctx: Ctx, when: dict):
    ok, m = _regex(ctx, when)
    return (not ok), m


def _line_present(ctx: Ctx, when: dict):
    text, pat = ctx.text(when), when["arg"]
    m = _matching_lines(text, pat)
    return bool(m), m


def _line_absent(ctx: Ctx, when: dict):
    ok, m = _line_present(ctx, when)
    return (not ok), m


def _no_form_present(ctx: Ctx, when: dict):
    """A negation directive ``no <arg>`` is present (distinct from mere absence)."""
    text = ctx.text(when)
    pat = r"(?im)^\s*no\s+" + re.escape(when["arg"]).replace(r"\ ", r"\s+")
    m = [ln.strip() for ln in text.splitlines() if re.search(pat, ln)]
    return bool(m), m[:5]


def _contains(ctx: Ctx, when: dict):
    text = ctx.text(when)
    needle = when["arg"]
    ok = needle.lower() in text.lower()
    return ok, ([needle] if ok else [])


def _not_contains(ctx: Ctx, when: dict):
    ok, _ = _contains(ctx, when)
    return (not ok), []


# -- fact predicates -------------------------------------------------------
def _fval(ctx: Ctx, when: dict):
    path = when["arg"] if not isinstance(when.get("arg"), dict) else when["arg"]["path"]
    return path, ctx.facts.get(path)


def _fact_true(ctx: Ctx, when: dict):
    path, v = _fval(ctx, when)
    return (v is True), [f"{path}={v}"]


def _fact_false(ctx: Ctx, when: dict):
    path, v = _fval(ctx, when)
    return (v is False), [f"{path}={v}"]


def _fact_unknown(ctx: Ctx, when: dict):
    path, v = _fval(ctx, when)
    return (v is None), [f"{path}={v}"]


def _fact_present(ctx: Ctx, when: dict):
    path, v = _fval(ctx, when)
    return (v is not None), [f"{path}={v}"]


def _fact_equals(ctx: Ctx, when: dict):
    arg = when["arg"]
    path, expected = arg["path"], arg["value"]
    v = ctx.facts.get(path)
    return (v == expected), [f"{path}={v}"]


def _fact_gte(ctx: Ctx, when: dict):
    arg = when["arg"]
    path, bound = arg["path"], arg["value"]
    v = ctx.facts.get(path)
    return (isinstance(v, (int, float)) and v >= bound), [f"{path}={v}"]


def _fact_lte(ctx: Ctx, when: dict):
    arg = when["arg"]
    path, bound = arg["path"], arg["value"]
    v = ctx.facts.get(path)
    return (isinstance(v, (int, float)) and v <= bound), [f"{path}={v}"]


_REGISTRY = {
    "regex": _regex,
    "regex_absent": _regex_absent,
    "line_present": _line_present,
    "line_absent": _line_absent,
    "no_form_present": _no_form_present,
    "contains": _contains,
    "not_contains": _not_contains,
    "fact_true": _fact_true,
    "fact_false": _fact_false,
    "fact_unknown": _fact_unknown,
    "fact_present": _fact_present,
    "fact_equals": _fact_equals,
    "fact_gte": _fact_gte,
    "fact_lte": _fact_lte,
}


def evaluate(when: dict, ctx: Ctx) -> tuple[bool, list[str]]:
    name = when.get("predicate")
    fn = _REGISTRY.get(name)
    if fn is None:
        raise PredicateError(f"unknown predicate: {name!r}")
    return fn(ctx, when)


def predicate_names() -> set[str]:
    return set(_REGISTRY)
