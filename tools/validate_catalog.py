"""Check every command line the catalog can emit against a controller's grammar.

Executes nothing. Every line is validated with '?' completion (see
cli_validator.py); the only things actually submitted are the sub-mode openers,
and only ones naming an object that already exists, so entering is a no-op.

    AOS_PW='...' python3 tools/validate_catalog.py \\
        --host <controller> --username <user> --password-env AOS_PW

    python3 tools/validate_catalog.py --snapshot     # no controller needed

Point it at a lab controller. Entering sub-modes leaves empty stanza headers in
the pending configuration of a staging controller — harmless, discarded by a
reload, and printed at the end so nobody has to wonder where they came from.
'write memory' is never sent.

Robustness is not incidental here. The first version of this sweep lost its
context part-way through, ran the rest of the catalog against the wrong prompt,
crashed, and skipped its own cleanup. So: the prompt is resynchronised before
every block, and one block that throws costs that block and not the run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.catalog_lines import (  # noqa: E402
    ABSENT,
    DEFAULT_TRAIN,
    GAP,
    OK,
    PLATFORM_ABSENT,
    SNAPSHOT,
    catalog_lines,
    emitted_rows,
    snapshot_records,
    write_snapshot,
)
from tools.cli_validator import CliGrammar  # noqa: E402

# A sub-mode opener as the catalog spells it -> the same stanza naming something
# that already exists on a controller, so entering it changes nothing.
OPENERS = {
    "firewall": "firewall",
    "firewall cp": "firewall cp",
    "control-plane-security": "control-plane-security",
    "web-server profile": "web-server profile",
    "lcd-menu": "lcd-menu",
    "aaa password-policy mgmt": "aaa password-policy mgmt",
    "aaa authentication mgmt": "aaa authentication mgmt",
    "aaa profile <p>": "aaa profile default",
    "aaa profile <name>": "aaa profile default",
    "aaa server-group <name>": "aaa server-group default",
    "aaa server-group <grp>": "aaa server-group default",
    "aaa authentication dot1x <prof>": "aaa authentication dot1x default",
    "wlan ssid-profile <p>": "wlan ssid-profile default",
    "wlan ssid-profile <name>": "wlan ssid-profile default",
    "wlan virtual-ap <p>": "wlan virtual-ap default",
    "wlan virtual-ap <name>": "wlan virtual-ap default",
    "ap system-profile <name>": "ap system-profile default",
    "user-role <name>": "user-role logon",
    "interface vlan 1": "interface vlan 1",
    "interface vlan <id>": "interface vlan 1",
    "interface vlan <mgmt-id>": "interface vlan 1",
    "interface gigabitethernet <port>": "interface gigabitethernet 0/0/0",
}

# Openers with no such stock object to borrow: every form names something the
# operator creates, and creating one is a configuration change on a controller
# that is not ours. The opener line itself is still checked -- only the body
# under it is reported unvalidated, which is a smaller lie than reporting it as
# checked. The value is the reason, printed so the gap is legible.
UNENTERABLE = {
    "aaa authentication-server radius <name>":
        "no RADIUS server exists on a stock controller to enter",
    "aaa authentication-server ldap <name>":
        "no LDAP server exists on a stock controller to enter",
    "aaa authentication-server tacacs <name>":
        "no TACACS+ server exists on a stock controller to enter",
    "crypto isakmp policy 20":
        "entering IKE policy 20 would create it",
    "crypto dynamic-map default-ikev2-dynamicmap 10000":
        "entering this dynamic-map entry would create it",
    "vrrp <id>":
        "entering a VRRP instance would create it",
    "ip access-list session <admin-policy>":
        "'ip access-list session ?' offers only <accname>, never the names that "
        "already exist, so no borrowed name can be shown to be a no-op first",
}

# Lines that run at (config) and are followed by another (config) line without
# opening anything. This set exists so the tool never has to *guess* whether a
# line changed the mode: an unlisted line with something after it is reported
# as an unclassified block shape rather than checked at a level that may be
# wrong. 'ssh disable-ciphers aes-cbc' was the line that made this necessary --
# the previous heuristic read it as an opener it could not enter and reported
# the SSH cipher fix, the whole reason this tool exists, as unvalidated.
FLAT = {
    "ssh disable-ciphers aes-cbc", "no ssh disable-ciphers",
    "no crypto isakmp policy 10001",
    "ntp server <ip> key <id>", "ntp authenticate",
    "ntp authentication-key <id> md5 <secret>",
    "no ntp server <ip>", "no ntp authenticate",
    "no telnet cli", "telnet cli",
}

# A line starting with one of these puts the rest of its block into text entry:
# what follows is the message being stored, terminated by a delimiter, and the
# parser is not reading it as commands. Checking those lines against the grammar
# would be a category error -- and '?' inside a banner is a literal '?'.
TEXT_OPENERS = ("banner ",)

# Lines that are mode plumbing rather than configuration. They are how a block
# gets where it is going; the grammar has nothing to say about them.
PLUMBING = {"configure terminal", "end", "exit"}


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Validate catalog command lines against a controller's grammar.")
    p.add_argument("--snapshot", action="store_true",
                   help="regenerate tests/data/validated_command_lines.txt and exit "
                        "(no controller). Run the live check FIRST.")
    p.add_argument("--from-report", type=Path, metavar="JSON",
                   help="take each line's verdict from this sweep's report. "
                        "Without it, --snapshot can only carry forward verdicts "
                        "already recorded, and fails on any new line.")
    p.add_argument("--train", default=DEFAULT_TRAIN,
                   help="what --snapshot records as the release that was checked")
    p.add_argument("--host")
    p.add_argument("--username")
    p.add_argument("--password-env", metavar="VAR",
                   help="environment variable holding the password; never pass it "
                        "on the command line")
    p.add_argument("--key-file")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--report", type=Path, default=Path("catalog_validation.json"))
    return p.parse_args(argv)


class Sweep:
    """One pass over the catalog, holding the connection and the prompt state."""

    def __init__(self, conn):
        self.conn = conn
        self.grammar = CliGrammar(conn)
        self.conn.send("configure terminal")
        self.config_prompt = conn._conn.find_prompt()
        self.results: list[dict] = []

    def resync(self) -> bool:
        """Back out to the (config) prompt from wherever the last block left us."""
        for _ in range(6):
            if self.conn._conn.find_prompt() == self.config_prompt:
                return True
            self.conn.send("exit")
        return self.conn._conn.find_prompt() == self.config_prompt

    def record(self, cid, kind, line, ok, why, context):
        self.results.append({"control_id": cid, "kind": kind, "line": line,
                             "ok": ok, "why": why, "context": context})
        if ok is False:
            print(f"  REJECTED  {cid} [{kind}] in {context}\n"
                  f"            {line!r}\n            {why}", flush=True)
        elif ok is None:
            print(f"  unchecked {cid} [{kind}] {line!r}\n"
                  f"            {why}", flush=True)

    def run_block(self, cid: str, kind: str, lines: list[str]) -> None:
        """Walk one block, checking each line where it would actually run.

        Context is tracked rather than inferred. A line is only checked once the
        tool knows which mode it lands in; when it cannot get into that mode, the
        line is reported unvalidated with the reason, and when it cannot even
        tell which mode a line lands in, it says that too. The one thing it will
        not do is check a line at (config) and call it valid when the catalog
        sends it three levels down.
        """
        if not self.resync():
            raise RuntimeError("cannot get back to a config prompt")
        context, depth = "(config)", 0
        blocked: str | None = None   # why the rest of this block cannot be checked
        text = False                 # the parser is reading a message, not commands

        for i, line in enumerate(lines):
            if text:
                self.record(cid, kind, line, None,
                            "message text, not a command: the parser is storing "
                            "these bytes, not reading them", f"{context} (text)")
                continue
            if line in PLUMBING:
                if line != "exit":
                    continue
                if depth:
                    # The one line in the catalog this sweep genuinely runs: it
                    # is how the sweep leaves a stanza, so if the controller did
                    # not accept it the run would lose its prompt and say so.
                    self.conn.send("exit")
                    self.record(cid, kind, line, True,
                                "sent, not probed: leaving the stanza is how the "
                                "sweep itself gets back to (config)", context)
                    depth -= 1
                else:
                    self.record(cid, kind, line, None,
                                "not reached: the sweep was already at (config)",
                                context)
                if not depth:
                    context, blocked = "(config)", None
                continue
            if blocked:
                self.record(cid, kind, line, None, blocked, "unvalidated")
                continue

            # check() returns None when it could not reach a verdict. Recording
            # that as checked inflates the coverage number this tool prints,
            # which is the number a reader uses to decide how much to trust the
            # snapshot.
            ok, why = self.grammar.check(line)
            self.record(cid, kind, line, ok, why, context)

            if line.startswith(TEXT_OPENERS):
                text = True
            elif depth == 0 and self._more_after(lines, i):
                # Only at (config). Inside a stanza the catalog's lines are that
                # stanza's body -- 'dot1x-default-role <role>' does not change
                # the mode, and demanding it be classified reported every
                # multi-line profile block as an unknown shape. A body line that
                # opened a nested mode would be checked correctly itself and
                # only mislead about its own body; the catalog has none.
                blocked = self._descend(line)
                if blocked is None and line in OPENERS:
                    depth, context = depth + 1, OPENERS[line]

    @staticmethod
    def _more_after(lines: list[str], i: int) -> bool:
        """Is there another real command after this one? The last line of a
        block never needs classifying: nothing follows it into the wrong mode."""
        return any(ln not in PLUMBING for ln in lines[i + 1:])

    def _descend(self, line: str) -> str | None:
        """Enter the stanza ``line`` opens. ``None`` if the next line is fine
        where it is; otherwise the reason the rest of the block is unvalidated.

        Note that failing to enter is *reported*, not retried. On this hardware
        'lcd-menu' is refused outright -- an MC-VA has no LCD -- and the honest
        answer for 'disable menu' underneath it is that this controller could not
        be asked, not that it passed.
        """
        if line in UNENTERABLE:
            return (f"runs inside {line!r}, which this tool will not enter: "
                    f"{UNENTERABLE[line]}")
        if line in FLAT:
            return None
        if line not in OPENERS:
            return (f"unclassified block shape: {line!r} is not a known (config) "
                    "command or stanza opener, so the mode the next line lands "
                    "in is unknown. Add it to FLAT, OPENERS or UNENTERABLE in "
                    f"{Path(__file__).name}.")
        reply = self.conn.send(OPENERS[line])
        if self.conn._conn.find_prompt() == self.config_prompt:
            # Quote the refusal. 'aaa server-group default' fails here with
            # "Cannot modify existing server-group from different node in config
            # path" -- a node-hierarchy restriction, not a grammar problem, and
            # a reader who only sees "could not enter" has no way to know that.
            said = " ".join(reply.split())[:200]
            return (f"the controller did not enter {OPENERS[line]!r}, so the "
                    "rest of this block could not be checked in context"
                    + (f" -- it said: {said}" if said else ""))
        return None


def live_check(args) -> int:
    from aos8_auditor.transport.connection import Connection, SSHConfig

    password = os.environ.get(args.password_env) if args.password_env else None
    if args.password_env and not password:
        print(f"error: ${args.password_env} is empty", file=sys.stderr)
        return 2

    blocks: dict[tuple[str, str], list[str]] = defaultdict(list)
    for cid, kind, _i, line in catalog_lines():
        blocks[(cid, kind)].append(line)

    conn = Connection(SSHConfig(host=args.host, username=args.username,
                                password=password, key_file=args.key_file,
                                port=args.port, default_read_timeout=30))
    conn.open()
    print(f"connected to {args.host}; checking {sum(len(v) for v in blocks.values())} "
          f"lines across {len(blocks)} blocks. Nothing will be executed.\n")
    sweep = Sweep(conn)
    try:
        for (cid, kind), lines in sorted(blocks.items()):
            try:
                sweep.run_block(cid, kind, lines)
            except Exception as e:
                # One block's mess is not the run's. This is the failure the
                # first version of this sweep died of.
                print(f"  !! {cid} [{kind}] raised {type(e).__name__}: {e}",
                      flush=True)
                try:
                    conn.cancel()
                except Exception:
                    pass
        sweep.resync()
        pending = conn.send("show configuration pending", read_timeout=120)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    args.report.write_text(json.dumps(sweep.results, indent=1))

    def key(r):
        return (r["control_id"], r["kind"], r["line"])

    rejected = [r for r in sweep.results
                if r["ok"] is False and key(r) not in PLATFORM_ABSENT]
    absent = [r for r in sweep.results
              if r["ok"] is False and key(r) in PLATFORM_ABSENT]
    unchecked = [r for r in sweep.results if r["ok"] is None]
    checked = len(sweep.results) - len(unchecked) - len(absent)
    # An exemption that a controller has stopped needing is worse than no
    # exemption: it reads as "checked, elsewhere" forever.
    stale = [r for r in sweep.results
             if r["ok"] is True and key(r) in PLATFORM_ABSENT]

    print(f"\n{len(rejected)} line(s) rejected out of {checked} checked; "
          f"{len(unchecked)} unvalidated, {len(absent)} absent from this "
          f"platform. Report: {args.report}")
    if absent:
        print("\nNot in this platform's grammar (expected; see PLATFORM_ABSENT):")
        for r in absent:
            print(f"  {r['control_id']} [{r['kind']}] {r['line']!r}\n"
                  f"      {PLATFORM_ABSENT[key(r)]}")
    if stale:
        print("\nThis controller HAS these, but they are listed in "
              "PLATFORM_ABSENT. Remove the exemption and record the real answer:")
        for r in stale:
            print(f"  {r['control_id']} [{r['kind']}] {r['line']!r}")
    if pending.strip():
        print("\nPending configuration on the controller now:\n"
              "(entering a stanza writes its header even when nothing inside it\n"
              " changed. A reload discards all of it. Read this before anyone\n"
              " runs 'write memory'.)\n")
        print(pending)
    if rejected:
        print("\nFix the rejected lines before re-snapshotting. Do not run\n"
              "--snapshot to make this go away: that records 'a human checked\n"
              "these' about lines a controller just refused.")
    return 1 if rejected else 0


def verdicts_from_report(path: Path) -> dict[str, tuple[str, str]]:
    """``identity -> (status, reason)`` from a sweep's JSON report.

    A rejection is not a verdict this function will record. Either the line is a
    known platform gap, spelled out in PLATFORM_ABSENT with what would settle it,
    or the line is wrong and the answer is to fix it. Letting a rejection through
    as a status would turn the snapshot from evidence into a list of excuses.
    """
    out: dict[str, tuple[str, str]] = {}
    unexplained = []
    for row in json.loads(path.read_text()):
        key = (row["control_id"], row["kind"], row["line"])
        identity = "\t".join(key)
        why = " ".join((row.get("why") or "").split())
        if row["ok"] is True:
            verdict = (OK, "")
        elif row["ok"] is None:
            verdict = (GAP, why or "not checked")
        elif key in PLATFORM_ABSENT:
            verdict = (ABSENT, PLATFORM_ABSENT[key])
        else:
            unexplained.append(f"{identity}\n      {why}")
            continue
        # One line can appear twice in a block -- 'exit' does -- and the two
        # occurrences can get different verdicts, since one may sit under a
        # stanza the sweep could not enter. The snapshot has a single row for
        # the line, so the weaker verdict wins: over-claiming here is the only
        # error this file cannot afford.
        if verdict[0] == OK and out.get(identity, (OK, ""))[0] != OK:
            continue
        out[identity] = verdict
    if unexplained:
        raise SystemExit(
            "refusing to snapshot: the controller rejected these lines and they "
            "are not recorded as platform gaps.\n\n    "
            + "\n    ".join(unexplained)
            + "\n\nFix the line, or -- if the keyword is simply not on the "
              "platform you swept -- add it to PLATFORM_ABSENT in "
              "tools/catalog_lines.py with what it would take to settle.")
    return out


def carried_verdicts() -> dict[str, tuple[str, str]]:
    """Verdicts from the existing snapshot, for lines that have not changed.

    A line the snapshot has never seen gets no verdict at all rather than a
    provisional one, so ``--snapshot`` on its own cannot promote a newly written
    command to checked. That is the whole forcing function.
    """
    return {f"{cid}\t{kind}\t{line}": (status, reason)
            for status, cid, kind, line, reason in snapshot_records()}


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.snapshot:
        if args.from_report:
            verdicts = verdicts_from_report(args.from_report)
        else:
            verdicts = carried_verdicts()
            missing = [r for r in emitted_rows() if r not in verdicts]
            if missing:
                print("error: these lines have no recorded verdict, so there is "
                      "nothing to carry forward:\n    "
                      + "\n    ".join(missing)
                      + "\n\nSweep a controller and snapshot from its report:\n"
                        "    python3 tools/validate_catalog.py --host ... "
                        "--report r.json\n"
                        "    python3 tools/validate_catalog.py --snapshot "
                        "--from-report r.json", file=sys.stderr)
                return 2
        count = write_snapshot(verdicts, train=args.train)
        print(f"wrote {count} lines to {SNAPSHOT.relative_to(Path.cwd())}"
              if SNAPSHOT.is_relative_to(Path.cwd()) else
              f"wrote {count} lines to {SNAPSHOT}")
        print(f"recorded as checked against: {args.train}")
        return 0
    if not (args.host and args.username):
        print("error: --host and --username are required (or use --snapshot)",
              file=sys.stderr)
        return 2
    return live_check(args)


if __name__ == "__main__":
    raise SystemExit(main())
