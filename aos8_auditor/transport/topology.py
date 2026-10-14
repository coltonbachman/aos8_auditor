"""Lightweight controller identity / topology detection from collected output.

Pure functions over already-collected text so they are testable offline. v1
targets standalone + Master-Local; Mobility Master node-hierarchy walking is a
later phase, but :func:`platform_family` / version parsing are needed now.
"""

from __future__ import annotations

import re

from ..model.evidence import ControllerIdentity, NodeRole

# Consume the 'Aruba' brand and any separator so the model is '7210', not '-7210'.
_MODEL_RE = re.compile(r"MODEL:\s*(?:Aruba[\-_ ]?)?([A-Za-z0-9][A-Za-z0-9\-]*)", re.IGNORECASE)
# Allow 2-5 numeric components (legacy 6.5.4 and full 8.6.0.4 builds).
_VERSION_LINE_RE = re.compile(r"(?im)^.*\bversion\s+(\d+(?:\.\d+){1,4}(?:[-_]\S+)?).*$")
_SERIAL_RE = re.compile(r"(?:Serial(?:\s*Number)?|S/N)\s*[:#]?\s*([A-Za-z0-9]+)", re.IGNORECASE)
_SWITCHROLE_RE = re.compile(r"switch\s*role\s*[:=]?\s*(master|standalone|local|md|mm|managed)", re.IGNORECASE)
_MM_MARKER_RE = re.compile(r"(?i)mobility\s+master|\[mm\]|\bvmm\b")


def platform_family(model: str | None) -> str | None:
    if not model:
        return None
    m = model.lower()
    if "72" in m or m.startswith("72"):
        return "7200"
    if "70" in m or m.startswith("70"):
        return "7000"
    if "mm" in m or "mobility-master" in m or "vmm" in m:
        return "mm"
    if "vmc" in m or "virtual" in m:
        return "vmc"
    return model


def _extract_version(text: str) -> str | None:
    """Pick the AOS version, preferring the 'ArubaOS ... Version' line and
    skipping ROM/bootstrap lines whose version is not the OS version."""
    fallback: str | None = None
    for m in _VERSION_LINE_RE.finditer(text):
        line = m.group(0).lower()
        if "rom" in line or "bootstrap" in line:
            continue
        if "arubaos" in line or "aruba operating system" in line:
            return m.group(1)
        if fallback is None:
            fallback = m.group(1)
    return fallback


def parse_show_version(text: str) -> dict:
    out: dict[str, str] = {}
    if not text:
        return out
    if (m := _MODEL_RE.search(text)):
        out["model"] = m.group(1)
    if (ver := _extract_version(text)):
        out["aos_version"] = ver
    if (m := _SERIAL_RE.search(text)):
        out["serial"] = m.group(1)
    return out


def detect_role(version_text: str = "", switchinfo_text: str = "") -> NodeRole:
    """Return the node role from positive evidence only — never guess STANDALONE.

    When there is no role evidence (including when the source command was denied
    or empty), return UNKNOWN so topology-scoped controls degrade to manual
    rather than being mis-scoped against a wrongly-assumed standalone.
    """
    blob = f"{version_text}\n{switchinfo_text}"
    if (m := _SWITCHROLE_RE.search(blob)):
        return {
            "master": NodeRole.MASTER,
            "standalone": NodeRole.STANDALONE,
            "local": NodeRole.LOCAL,
            "md": NodeRole.MANAGED,
            "mm": NodeRole.MM,
            "managed": NodeRole.MANAGED,
        }.get(m.group(1).lower(), NodeRole.UNKNOWN)
    if _MM_MARKER_RE.search(blob):
        return NodeRole.MM
    return NodeRole.UNKNOWN


_MD_PATH_RE = re.compile(r"/md(?:/[^/\s]+)*$")
_NODE_HEADER = ("default-node", "configuration", "config node", "switch", "ip address",
                "total", "name", "type")
_DEVICE_TYPES = {"device", "local", "standby", "md"}        # leaf controllers
_GROUP_TYPES = {"group", "system", "master", "mm"}          # containers / MM


def _node_row(line: str) -> tuple[str | None, str | None]:
    """Parse one node-hierarchy line -> (md_path, type_token) or (None, None).

    Tolerates a tabular 'Config Node  Type' layout, a leading '*' active-node
    marker or CLI-prompt prefix, quotes, and trailing '/'. Header/banner lines
    are skipped. The path must be the row's first real token (so a /md path
    embedded mid-sentence is not mistaken for a node row)."""
    s = line.strip()
    low = s.lower()
    if not s or set(s) <= set("-= ") or any(low.startswith(h) for h in _NODE_HEADER):
        return None, None
    toks = s.split()
    if toks and (toks[0] == "*" or re.fullmatch(r"\S*[#>]", toks[0])):
        toks = toks[1:]  # strip active-node marker / prompt prefix
    if not toks:
        return None, None
    path = toks[0].strip('"').rstrip("/")
    if not _MD_PATH_RE.fullmatch(path):
        return None, None
    typ = next((t.lower() for t in toks[1:] if t.lower() in _DEVICE_TYPES | _GROUP_TYPES), None)
    return path, typ


def _segments_after_md(path: str) -> int:
    return len(path.split("/")) - 2  # '/md' -> 0, '/md/grp/dev' -> 2


def _pick_devices(rows: list[tuple[str, str | None]]) -> list[str]:
    paths = [p for p, _ in rows]
    have_type = any(t for _, t in rows)
    out: list[str] = []
    for p, t in rows:
        if _segments_after_md(p) < 1:
            continue
        if have_type:
            is_dev = t in _DEVICE_TYPES
        else:  # no Type column: a managed device is a LEAF at depth >= 2
            is_leaf = not any(o != p and o.startswith(p + "/") for o in paths)
            is_dev = is_leaf and _segments_after_md(p) >= 2
        if is_dev:
            out.append(p)
    return out


def _devices_from_switches(switches_text: str) -> list[str]:
    """Fallback: pull /md device node paths from a 'show switches' table column."""
    paths: list[str] = []
    for line in switches_text.splitlines():
        for tok in line.split():
            tt = tok.strip('"').rstrip("/")
            if re.fullmatch(r"/md(?:/[^/\s]+){2,}", tt):
                paths.append(tt)
    return [p for p in paths if not any(o != p and o.startswith(p + "/") for o in paths)]


def enumerate_nodes(node_hierarchy_text: str = "", switches_text: str = "") -> list["NodeTarget"]:
    """Return managed-device config nodes (/md/<group>/<device>[/...]) on a
    Mobility Master, from 'show configuration node-hierarchy' (falling back to
    'show switches'). Excludes container groups, /md, and /mm. Returns [] for a
    standalone / Master-Local controller."""
    from ..model.evidence import NodeTarget

    rows = []
    for line in (node_hierarchy_text or "").splitlines():
        p, t = _node_row(line)
        if p:
            rows.append((p, t))
    devices = _pick_devices(rows)
    if not devices and switches_text:
        devices = _devices_from_switches(switches_text)

    out: list[NodeTarget] = []
    seen: set[str] = set()
    for p in devices:
        if p not in seen:
            seen.add(p)
            out.append(NodeTarget(node_path=p, role=NodeRole.MANAGED))
    return out


def detect_identity(host: str, version_text: str = "", switchinfo_text: str = "") -> ControllerIdentity:
    fields = parse_show_version(version_text)
    role = detect_role(version_text, switchinfo_text)
    return ControllerIdentity(
        host=host,
        model=fields.get("model"),
        platform_family=platform_family(fields.get("model")),
        aos_version=fields.get("aos_version"),
        serial=fields.get("serial"),
        role=role,
        detected_topology=role.value,
    )
