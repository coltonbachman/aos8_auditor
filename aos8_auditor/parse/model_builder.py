"""Build a queryable :class:`ControllerModel` from a ``CollectionResult``.

The model wraps the parsed running-config tree, gives evidence access by logical
key (mapping key -> command via the command catalog, preferring a usable result
and falling back through alternates), and carries a computed ``facts`` dict for
the cross-object / numeric checks the controls assert against.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..collection.command_catalog import COMMAND_CATALOG
from ..model.evidence import CollectionResult, CommandResult, ExitKind
from .config_tree import ConfigNode, parse_config
from .sanitizer import sanitize

# Logical evidence key -> ordered candidate commands (primary + alternates).
_KEY_COMMANDS: dict[str, list[str]] = {
    spec.key: [spec.command, *spec.alternates] for spec in COMMAND_CATALOG
}


@dataclass
class ControllerModel:
    collection: CollectionResult
    config_root: ConfigNode
    facts: dict = field(default_factory=dict)
    sanitize_notes: list[str] = field(default_factory=list)
    # Sanitized 'show running-config' text (banner bodies collapsed, prompts
    # stripped). All regex controls + facts read THIS, never the raw output, so
    # a login banner whose lines start with directive keywords cannot inject
    # false matches.
    sanitized_config_text: str = ""
    # The node this model represents ("/" for standalone/Master-Local; a
    # "/md/<group>/<device>" path on a Mobility Master). Evidence lookups prefer
    # this node, then global "/", so MM-global outputs (version, license) are
    # still seen while per-device config comes from the device's node.
    node_path: str = "/"
    identity_override: ControllerIdentity | None = None

    # -- evidence access ---------------------------------------------------
    @property
    def identity(self):
        return self.identity_override or self.collection.controller

    def _candidate_commands(self, key: str) -> list[str]:
        if key in _KEY_COMMANDS:
            return _KEY_COMMANDS[key]
        if key == "running_config":
            return ["show running-config"]
        return [key]  # treat the key itself as a literal command (control-supplied)

    def result_for_command(self, command: str) -> CommandResult | None:
        # Node preference: THIS node, then global "/". Never fall back to another
        # node — that would audit one managed device against a peer's config.
        cands = [r for r in self.collection.results if r.command == command]
        for np in (self.node_path, "/"):
            for r in cands:
                if r.node_path == np:
                    return r
        # Single-node bundles (or pre-node-tagging captures) use the lone result.
        if self.node_path == "/" and cands:
            return cands[0]
        return None

    def result_for_key(self, key: str) -> CommandResult | None:
        cmds = self._candidate_commands(key)
        for cmd in cmds:  # prefer a usable result
            r = self.result_for_command(cmd)
            if r and r.usable:
                return r
        for cmd in cmds:  # otherwise surface whatever ran (carries exit_kind)
            r = self.result_for_command(cmd)
            if r:
                return r
        return None

    def text_for(self, source: str) -> str:
        if source == "running_config":
            return self.running_config_text  # sanitized
        r = self.result_for_key(source)
        return r.redacted_output if r else ""

    @property
    def raw_config_text(self) -> str:
        r = self.result_for_command("show running-config")
        return r.redacted_output if r else ""

    def exit_kind_for(self, source: str) -> ExitKind | None:
        if source == "fact":
            return ExitKind.OK
        r = self.result_for_key(source)
        return r.exit_kind if r else None

    @property
    def running_config_text(self) -> str:
        # Sanitized (banner collapsed); falls back to raw if not yet built.
        return self.sanitized_config_text or self.raw_config_text


def build_controller_model(
    collection: CollectionResult,
    *,
    node_path: str = "/",
    identity: ControllerIdentity | None = None,
) -> ControllerModel:
    from . import facts as facts_mod  # local import avoids a module cycle

    model = ControllerModel(
        collection=collection,
        config_root=ConfigNode(),
        node_path=node_path,
        identity_override=identity,
    )
    # Pick the running-config for THIS node (prefer node, then global "/").
    rc_result = model.result_for_command("show running-config")
    rc = rc_result.redacted_output if rc_result else ""
    cleaned = sanitize(rc)
    model.config_root = parse_config(cleaned.text)
    model.sanitize_notes = cleaned.notes
    model.sanitized_config_text = cleaned.text
    model.facts = facts_mod.compute_facts(model)
    return model
