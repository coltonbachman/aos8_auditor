"""Generic running-config parser: text -> ConfigNode tree.

ArubaOS running-config is a recursive, indentation-delimited structure whose
blocks are closed by a ``!`` at column 0 (or by a dedent to column 0). A single
tested tree-builder lets every per-object parser consume structured nodes instead
of re-implementing indentation logic. Every node keeps ``raw_line`` + ``line_no``
so evidence maps straight back to the source.

Membership is by relative indentation (more-indented-than-the-open-header is a
child), NOT exact column counts — AOS output mixes tabs/spaces and the guide's
examples are raggedly indented. ``!`` and dedent-to-0 are the authoritative block
terminators. Child order is preserved (``position`` matters in netdestinations).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_LEADING_WS = re.compile(r"^[ \t]*")


def _indent(line: str) -> int:
    m = _LEADING_WS.match(line)
    # Treat a tab as 8 columns so tab/space mixes order consistently.
    return sum(8 if c == "\t" else 1 for c in (m.group(0) if m else ""))


@dataclass
class ConfigNode:
    keyword: str = ""  # first token of the line ("" for the synthetic root)
    args: list[str] = field(default_factory=list)  # remaining tokens
    raw_line: str = ""
    line_no: int = 0
    children: list["ConfigNode"] = field(default_factory=list)

    # -- query helpers -----------------------------------------------------
    @property
    def text(self) -> str:
        return self.raw_line.strip()

    @property
    def tokens(self) -> list[str]:
        return ([self.keyword] if self.keyword else []) + self.args

    def find_all(self, keyword: str) -> list["ConfigNode"]:
        """Direct children whose keyword matches (case-insensitive)."""
        kw = keyword.lower()
        return [c for c in self.children if c.keyword.lower() == kw]

    def find(self, keyword: str) -> "ConfigNode | None":
        found = self.find_all(keyword)
        return found[0] if found else None

    def find_all_deep(self, keyword: str) -> list["ConfigNode"]:
        kw = keyword.lower()
        out: list[ConfigNode] = []
        stack = list(self.children)
        while stack:
            n = stack.pop(0)
            if n.keyword.lower() == kw:
                out.append(n)
            stack[:0] = n.children
        return out

    def child(self, keyword: str) -> "ConfigNode | None":
        return self.find(keyword)

    def has_child(self, keyword: str) -> bool:
        return self.find(keyword) is not None

    def matches(self, keyword: str, *args: str) -> bool:
        """True if this node's keyword and leading args match (case-insensitive)."""
        if self.keyword.lower() != keyword.lower():
            return False
        return [a.lower() for a in self.args[: len(args)]] == [a.lower() for a in args]


def _split(line: str) -> tuple[str, list[str]]:
    parts = line.split()
    if not parts:
        return "", []
    return parts[0], parts[1:]


def parse_config(text: str) -> ConfigNode:
    """Parse running-config text into a ConfigNode tree rooted at a synthetic node."""
    root = ConfigNode(keyword="", args=[], raw_line="", line_no=0)
    # Stack of (indent, node); root sits at indent -1 so column-0 lines attach to it.
    stack: list[tuple[int, ConfigNode]] = [(-1, root)]

    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        stripped = raw.strip()
        if stripped == "!":
            # Block terminator: pop back to column 0.
            while len(stack) > 1 and stack[-1][0] >= 0:
                stack.pop()
            continue

        ind = _indent(raw)
        kw, args = _split(stripped)
        node = ConfigNode(keyword=kw, args=args, raw_line=raw, line_no=lineno)

        # Pop until the top of stack is strictly less indented than this line.
        while len(stack) > 1 and stack[-1][0] >= ind:
            stack.pop()
        stack[-1][1].children.append(node)
        stack.append((ind, node))

    return root
