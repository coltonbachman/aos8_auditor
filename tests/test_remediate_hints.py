"""Hint parsing: the safety-critical step, checked against the whole catalog.

The failure costs are asymmetric. Prose emitted as a command means an operator
pastes English at a config prompt, which defeats the point of the artifact. A
command emitted as a note is commented out and harmless. So the parser is
conservative, and these tests assert that conservatism holds for every control —
not just the ones someone thought to write a case for.
"""

import re

from aos8_auditor.engine.loader import load_controls
from aos8_auditor.remediate.hints import (
    command_lines,
    is_actionable,
    is_destructive,
    is_partial,
    note_lines,
    parse_hint,
    prompts_for_confirmation,
    text_entry_delimiter,
    text_entry_regions,
    text_entry_spans,
)

CONTROLS = load_controls()

# Punctuation and shapes that never appear in an ArubaOS config line.
_PROSE_MARKERS = (",", ";", ":", "...", "…", "'", '"', "{", "}", "|")


def _all_command_lines():
    for c in CONTROLS:
        for line in command_lines(parse_hint(c.remediation_hint)):
            yield c.id, line


def test_no_command_line_contains_prose_punctuation():
    bad = [(cid, line) for cid, line in _all_command_lines()
           if any(m in line for m in _PROSE_MARKERS)]
    assert not bad, f"prose leaked into command lines: {bad}"


def test_no_command_line_starts_a_sentence():
    bad = [(cid, line) for cid, line in _all_command_lines() if line[:1].isupper()]
    assert not bad, f"sentences emitted as commands: {bad}"


def test_no_command_line_is_destructive():
    bad = [(cid, line) for cid, line in _all_command_lines() if is_destructive(line)]
    assert not bad, f"destructive commands must never be emitted: {bad}"


def test_no_command_line_is_mode_plumbing():
    """The emitter supplies configure terminal / end / write memory itself.

    A mid-block ``exit`` is NOT plumbing: several hints leave one sub-mode to
    enter a sibling, and dropping it would silently apply the next command in the
    wrong context.
    """
    plumbing = {"configure terminal", "configure", "end", "write memory"}
    bad = [(cid, line) for cid, line in _all_command_lines()
           if line.strip().lower() in plumbing]
    assert not bad, f"mode plumbing must not come from a hint: {bad}"


def test_no_block_ends_on_a_bare_exit():
    """A trailing exit is either a no-op or a sign the real command was dropped."""
    for c in CONTROLS:
        lines = command_lines(parse_hint(c.remediation_hint))
        if lines:
            assert lines[-1].strip().lower() != "exit", c.id


def test_command_lines_are_short():
    bad = [(cid, line) for cid, line in _all_command_lines() if len(line.split()) > 10]
    assert not bad, f"too long to be a real command: {bad}"


def test_a_useful_number_of_controls_are_actionable():
    """A guard against the parser silently going conservative to the point of
    uselessness — e.g. a regex change that demotes everything."""
    actionable = [c.id for c in CONTROLS if is_actionable(parse_hint(c.remediation_hint))]
    assert len(actionable) >= 55, f"only {len(actionable)} actionable controls"


def test_fips_drops_the_reload():
    segments = parse_hint("fips enable; reload")
    assert command_lines(segments) == ["fips enable"]
    assert any("destructive" in (s.reason or "") for s in segments if not s.is_command)


def test_exec_actions_are_notes_not_commands():
    segments = parse_hint("backup flash; copy flash: flash.tar scp: <host> <user> <path>")
    assert command_lines(segments) == []
    assert note_lines(segments)


def test_trailing_context_opener_is_dropped():
    """A hint that opens a sub-mode and then trails off in prose leaves an empty
    context, which would be a no-op at best and confusing at worst."""
    segments = parse_hint("web-server profile. Then set the session limit appropriately")
    assert command_lines(segments) == []


def test_alternatives_keep_only_the_first_branch():
    segments = parse_hint("no telnet cli OR telnet soe")
    assert command_lines(segments) == ["no telnet cli"]


def test_parenthetical_becomes_commentary():
    segments = parse_hint("firewall; prohibit-arp-spoofing (blocks gratuitous ARP; hot change)")
    assert command_lines(segments) == ["firewall", "prohibit-arp-spoofing"]
    assert any(s.reason == "commentary" for s in segments if not s.is_command)


def test_multi_line_hint_survives_a_sentence_break_after_a_placeholder():
    """Regression: the sentence splitter must anchor after '>' too, or the last
    command of a hint fuses with the prose that follows it."""
    segments = parse_hint("aaa authentication mgmt; server-group <grp>. Verify login first")
    assert command_lines(segments)[-1] == "server-group <grp>"


def test_partial_flags_a_hint_that_lost_something():
    segments = parse_hint("no spanning-tree. Confirm the upstream switch owns the "
                          "loop-prevention topology")
    assert is_actionable(segments)
    assert is_partial(segments)


def test_is_destructive_allows_the_negated_form():
    assert is_destructive("reload")
    assert is_destructive("write erase all")
    assert not is_destructive("no boot verify")
    assert not is_destructive("firewall")


def test_placeholders_stay_atomic():
    segments = parse_hint("banner motd <delim> <approved text> <delim>")
    line = command_lines(segments)[0]
    assert "<approved text>" in line
    assert len(re.findall(r"<[^>]+>", line)) == 3


# -- commands that are not commands ---------------------------------------

def test_a_command_that_asks_a_question_is_never_a_command_line():
    """The next line of a pasted block becomes the answer, so a confirmation
    prompt does not stall a run — it silently eats the command after it."""
    segments = parse_hint("controller-ip vlan <id>")
    assert command_lines(segments) == []
    assert any("confirmation" in (s.reason or "") for s in segments)


def test_prompts_for_confirmation_ignores_the_placeholder():
    assert prompts_for_confirmation("controller-ip vlan <id>")
    assert prompts_for_confirmation("controller-ip vlan 200")
    assert not prompts_for_confirmation("interface vlan 200")
    assert not prompts_for_confirmation("")


def test_no_control_in_the_catalog_emits_a_confirmation_prompt():
    bad = [(cid, line) for cid, line in _all_command_lines()
           if prompts_for_confirmation(line)]
    assert not bad, f"these would be answered by the line below them: {bad}"


# -- raw text entry --------------------------------------------------------

def test_a_banner_opener_is_recognised_filled_or_not():
    assert text_entry_delimiter("banner motd ^") == "^"
    assert text_entry_delimiter("banner motd <delim>") == "<delim>"
    assert text_entry_delimiter("  banner exec #  ") == "#"


def test_a_banner_with_its_text_on_the_same_line_is_not_an_opener():
    """The form that a controller rejects outright. Recognising it as text entry
    would be worse than not recognising it: the tool would then withhold the
    lines after it from the command checks on the strength of a command the
    device never accepted."""
    assert text_entry_delimiter("banner motd ^ Authorized use only ^") is None
    assert text_entry_delimiter("no banner motd") is None
    assert text_entry_delimiter("banner motd") is None


def test_the_text_of_a_banner_is_not_commands():
    lines = ["configure terminal", "banner motd ^", "Authorized use only.",
             "end", "^", "end"]
    assert text_entry_regions(lines) == [(1, 4)]
    # The 'end' at index 3 is inside the banner: a word, not a mode change.
    assert text_entry_spans(lines) == {2, 3, 4}


def test_an_unclosed_banner_runs_to_the_end_of_the_block():
    """Which is what the controller does with it, and why it is refused."""
    lines = ["banner motd ^", "Authorized use only.", "end"]
    assert text_entry_regions(lines) == [(0, None)]
    assert text_entry_spans(lines) == {1, 2}


def test_two_banners_in_one_block_are_two_regions():
    lines = ["banner motd ^", "first", "^", "aaa profile x",
             "banner exec #", "second", "#"]
    assert text_entry_regions(lines) == [(0, 2), (4, 6)]
    assert 3 not in text_entry_spans(lines)


# -- command forms checked against a real controller ------------------------
#
# Every assertion below was verified on ArubaOS 8.13.3.0 by asking the CLI's own
# '?' completion grammar, not by reading a PDF. Each one replaces a form the
# controller rejects, and the comments say what the rejection looked like —
# because two of these did not fail cleanly, and a command that fails dirtily is
# the reason this section exists.

def _recipe_rollback(control_id):
    from aos8_auditor.remediate.recipes import recipe_for
    return list(recipe_for(control_id).rollback or [])


def test_ssh_weak_algorithms_use_the_knob_that_owns_them():
    """hmac-sha1-96 is a MAC, and 'disable-ciphers' only accepts aes-cbc/aes-ctr.

    Sending it to the wrong knob does not print '% Invalid input': the parser
    falls through to the exec-mode SSH *client*, which prompts for a password.
    The command never returns, and the next line of the block is read as the
    password. That is why this is pinned rather than left to review.
    """
    lines = command_lines(parse_hint(
        next(c for c in CONTROLS if c.id == "AOS8-CRYPTO-SSH-CIPHERS-001"
             ).remediation_hint))
    assert "ssh disable-mac hmac-sha1-96" in lines
    assert "ssh disable-ciphers hmac-sha1-96" not in lines


def test_ssh_algorithm_knobs_negate_whole_not_per_algorithm():
    """'no ssh disable-ciphers aes-cbc' is one token too many and is rejected,
    so the rollback for this control could never have run."""
    assert _recipe_rollback("AOS8-CRYPTO-SSH-CIPHERS-001") == [
        "no ssh disable-ciphers", "no ssh disable-mac"]


def test_negations_that_take_no_argument_do_not_carry_one():
    """The same defect shape as the SSH rollback: a rollback written by putting
    'no ' in front of the apply line, where the negation is already complete."""
    assert "no mgmt-auth" in _recipe_rollback("AOS8-MGMT-WEBUI-CERTAUTH-001")
    assert "no server-group" in _recipe_rollback("AOS8-MGMT-CENTRALAUTH-001")
    for cid in ("AOS8-MGMT-WEBUI-CERTAUTH-001", "AOS8-MGMT-CENTRALAUTH-001"):
        for line in _recipe_rollback(cid):
            assert line not in ("no mgmt-auth certificate", "no server-group <grp>")


def test_control_plane_bandwidth_contracts_take_a_bare_rate():
    """The rate carries no unit keyword.

    This test used to assert the opposite, off a misreading of the help text:
    'cp-bandwidth-contract untrusted-ucast ?' answers '<1-65535> pps', which
    names the unit of the value rather than a token to type. An 8.13.3.0
    controller prints 'cp-bandwidth-contract untrusted-ucast 9765' in its own
    running config, answers '<cr>' to '... untrusted-ucast 20', and answers
    nothing at all to '... untrusted-ucast pps' -- the shape of a line that has
    stopped being a command.
    """
    lines = command_lines(parse_hint(
        next(c for c in CONTROLS if c.id == "AOS8-FW-CP-BWCONTRACT-001"
             ).remediation_hint))
    contracts = [ln for ln in lines if ln.startswith("cp-bandwidth-contract")]
    assert contracts, "the control stopped emitting bandwidth contracts"
    for line in contracts:
        assert " pps" not in line, line
        assert re.fullmatch(r"cp-bandwidth-contract \S+ \d+", line), line
