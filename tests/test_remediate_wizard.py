"""The wizard's front end: navigation, and knowing when you are finished.

The decisions live in Session and are tested next door. What is tested here is
the part an operator actually experiences — which key moves where, and whether
the screen ever says "you are done, here is the next command". A wizard that
walks you through twelve changes and then looks identical on the last one as on
the first has not finished the job it started.

_Curses is built without __init__ throughout: everything under test reads the
session, the view and the scroll offset, and none of it needs a terminal.
"""

from pathlib import Path

import pytest

from aos8_auditor.remediate.plan import ChangeState
from aos8_auditor.remediate.wizard import (_change_lines, _Curses, _next_steps,
                                           _overview_lines, _review_lines)
from test_remediate_session import _session

curses = pytest.importorskip("curses")


def _screen(session, view="change"):
    """A _Curses with no terminal behind it."""
    ui = object.__new__(_Curses)
    ui.session = session
    ui.view = view
    ui.scroll = 0
    ui.result = None
    ui.styles = {}
    ui.out_dir = Path("/tmp")
    ui.operator = None
    ui.suppressions_path = None
    ui.apply_hook = None
    ui.apply_on_export = False
    return ui


def _decide_everything(session):
    for change in session.queue:
        change.state = ChangeState.SKIPPED
        change.skip_reason = "not in this change window"


def _text(lines):
    return "\n".join(text for _, text in lines)


# -- navigation -----------------------------------------------------------
#
# Two axes, two pairs of arrows: left and right walk the changes, up and down
# walk what is inside the one you are on. Collapsing both onto up/down was the
# earlier design, and it left the only list on the page — the values you have to
# supply — reachable solely by tab.

ESC = 27
NO_FIELDS = "AOS8-GLOBAL-STP-001"
HAS_FIELDS = "AOS8-GLOBAL-NTP-001"


def test_the_right_arrow_moves_to_the_next_change():
    session = _session()
    ui = _screen(session)
    start = session.index

    ui._handle(curses.KEY_RIGHT)

    assert session.index == start + 1


def test_the_left_arrow_moves_back():
    session = _session()
    ui = _screen(session)
    session.goto(2)

    ui._handle(curses.KEY_LEFT)

    assert session.index == 1


def test_moving_to_another_change_starts_at_the_top_of_it():
    session = _session()
    ui = _screen(session)
    ui.scroll = 12

    ui._handle(curses.KEY_RIGHT)

    assert ui.scroll == 0


def test_the_down_arrow_moves_between_the_values_you_supply():
    """The fields are what the change page is a list of, and enter edits the one
    the arrows land on. Anything else makes the cursor on screen unreachable."""
    session = _session(HAS_FIELDS)
    ui = _screen(session)
    assert len(session.fields) > 1, "fixture no longer exercises multiple fields"

    ui._handle(curses.KEY_DOWN)

    assert session.field_index == 1
    assert session.index == 0, "moving between fields must not move between changes"


def test_the_up_arrow_moves_back_through_the_values():
    session = _session(HAS_FIELDS)
    ui = _screen(session)
    session.select_field(1)

    ui._handle(curses.KEY_UP)

    assert session.field_index == 0


def test_the_arrows_scroll_a_change_that_has_nothing_to_fill_in():
    """Some changes are pure commands. There the arrows have no list to walk,
    so they do the other useful thing rather than nothing at all."""
    session = _session(NO_FIELDS)
    ui = _screen(session)
    assert not session.fields, "fixture no longer exercises a field-less change"

    ui._handle(curses.KEY_DOWN)

    assert ui.scroll == 1


def test_the_arrows_still_scroll_where_there_is_nothing_to_step_through():
    """Help and review are prose, not a list. Moving the change cursor from
    behind them would silently change what 'e' is about to export."""
    session = _session()
    ui = _screen(session, view="help")
    start = session.index

    ui._handle(curses.KEY_DOWN)

    assert session.index == start
    assert ui.scroll == 1


def test_the_arrows_walk_the_change_list_on_the_overview():
    """The overview *is* a list of changes, so up and down mean there what they
    mean everywhere: move within the page you are looking at."""
    session = _session()
    ui = _screen(session, view="overview")

    ui._handle(curses.KEY_DOWN)

    assert session.index == 1


# -- escape ---------------------------------------------------------------

def test_escape_backs_out_of_the_keys_page():
    session = _session()
    ui = _screen(session, view="help")

    ui._handle(ESC)

    assert ui.view == "change"


def test_escape_backs_out_of_the_review_page():
    """Left and right also leave it, but they move you somewhere at the same
    time. Escape is the one that just undoes the key that got you here."""
    session = _session()
    ui = _screen(session, view="review")
    ui.scroll = 4

    ui._handle(ESC)

    assert (ui.view, ui.scroll) == ("change", 0)


def test_escape_never_quits_the_wizard():
    session = _session()
    ui = _screen(session, view="overview")

    assert ui._handle(ESC) is not False
    assert ui.view == "change"


def test_escape_says_nothing_on_its_way_out():
    """'cancelled' in the status bar is a reply to a keystroke that means
    cancel. The page coming back unchanged has already said it."""
    session = _session()
    ui = _screen(session, view="help")
    session.message = "something earlier"

    ui._handle(ESC)

    assert ui.session.message == ""


def test_the_overview_scrolls_to_keep_the_cursor_visible():
    """The overview is longer than a terminal on a real run, so an arrow that
    moved an off-screen cursor would look like an arrow that did nothing."""
    session = _session()
    ui = _screen(session, view="overview")
    body = [("", "line") for _ in range(40)]
    body[30] = ("sel", "> the change you are on")

    assert ui._follow_selection(body, room=10) == 21


def test_a_visible_cursor_does_not_move_the_page():
    ui = _screen(_session(), view="overview")
    body = [("", "a"), ("sel", "b"), ("", "c")]

    assert ui._follow_selection(body, room=10) == 0


# -- skipping -------------------------------------------------------------

def test_shift_s_skips_without_asking_for_anything():
    """Most skips have no story — 'not this window' is the whole thought. A
    prompt that insists on one gets twelve changes skipped with 'n/a'."""
    session = _session()
    ui = _screen(session)
    ui._prompt = lambda *a, **kw: pytest.fail("S must not ask for a reason")
    first = session.current

    ui._handle(ord("S"))

    assert first.state is ChangeState.SKIPPED
    assert first.skip_reason is None


def test_shift_s_moves_on_like_the_other_decisions_do():
    session = _session()
    ui = _screen(session)
    first = session.current

    ui._handle(ord("S"))

    assert session.current is not first


def test_lowercase_s_still_asks_for_a_reason():
    """The two keys are one shift apart, so the difference has to be real."""
    session = _session()
    ui = _screen(session)
    asked = []
    ui._prompt = lambda label, **kw: asked.append(label)
    ui._confirm = lambda _q: False

    ui._handle(ord("s"))

    assert asked and "reason" in asked[0]


def test_escaping_the_reason_leaves_the_change_undecided_and_says_nothing():
    session = _session()
    ui = _screen(session)
    ui._prompt = lambda *a, **kw: None

    ui._handle(ord("s"))

    assert session.current.state is ChangeState.PENDING
    assert session.message == ""


# -- knowing you are finished ---------------------------------------------

def test_deciding_the_last_change_lands_you_on_the_review_page():
    session = _session()
    ui = _screen(session)
    _decide_everything(session)

    ui._finished()

    assert ui.view == "review"
    assert "press e" in session.message


def test_nothing_jumps_while_changes_are_still_undecided():
    session = _session()
    ui = _screen(session)

    ui._finished()

    assert ui.view == "change"


def test_the_change_page_says_so_when_everything_is_decided():
    session = _session()
    _decide_everything(session)

    assert "Every change is decided" in _text(_change_lines(session, 78))


def test_the_overview_says_so_too():
    session = _session()
    _decide_everything(session)

    assert "Every change is decided" in _text(_overview_lines(session, 78))


def test_the_status_bar_offers_the_export_key_once_there_is_nothing_left():
    session = _session()
    ui = _screen(session)
    assert "DONE" not in ui._status()

    _decide_everything(session)
    session.message = ""

    assert "DONE" in ui._status()
    assert "e write the files" in ui._status()


def test_a_narrow_terminal_keeps_the_keys_and_drops_the_tally():
    """Truncation eats the right-hand end, and that is where '? keys' and
    'q quit' are — the two you need exactly when you are stuck."""
    session = _session()
    ui = _screen(session)

    assert "accepted" in ui._status(200)
    narrow = ui._status(60)
    assert "accepted ·" not in narrow
    assert "q quit" in narrow


def test_the_status_bar_names_both_pairs_of_arrows():
    session = _session()

    assert "←→ change · ↑↓ field" in _screen(session)._status()


def test_a_message_never_costs_the_operator_the_keys():
    """The two used to share a line, so filling in a field replaced the only
    list of keys on screen with a sentence about the field — and somebody who
    had just arrived had no way of knowing there was anywhere to go."""
    session = _session()
    ui = _screen(session)
    session.message = "not accepted — that VLAN id is out of range"

    assert ui._notice() == "not accepted — that VLAN id is out of range"
    assert "←→ change" in ui._status()


def test_a_value_that_was_taken_is_not_announced(monkeypatch):
    """It shows up in the change above, which is where the operator is already
    looking. A second sentence about it just sits there afterwards."""
    session = _session(HAS_FIELDS)
    ui = _screen(session)
    monkeypatch.setattr(ui, "_prompt", lambda *a, **k: "192.0.2.10")

    ui._edit_field()

    assert session.fields[session.field_index].value == "192.0.2.10"
    assert ui._notice() == ""


def test_a_value_that_was_refused_says_why():
    session = _session(HAS_FIELDS)
    ui = _screen(session)
    ui._prompt = lambda *a, **k: "not-an-address"

    ui._edit_field()

    assert "not accepted" in ui._notice()


def test_a_value_taken_with_a_caveat_still_speaks_up(monkeypatch):
    """'accepted' and 'accepted, and you should know something' are different
    answers. Only the second one is worth a line of the screen."""
    session = _session(HAS_FIELDS)
    ui = _screen(session)
    session.plan.context.own_ips = ["192.168.1.201"]
    monkeypatch.setattr(ui, "_prompt", lambda *a, **k: "192.168.1.201")

    ui._edit_field()

    assert "controller's own address" in ui._notice()


def test_e_exports_from_any_view_once_everything_is_decided(monkeypatch):
    """The status bar offers 'e' in that state, so it has to answer wherever
    the operator happens to be standing."""
    session = _session()
    ui = _screen(session, view="overview")
    _decide_everything(session)
    exported = []
    ui._export = lambda: exported.append(True)

    assert ui._handle(ord("e")) is False
    assert exported == [True]


def test_e_with_work_left_shows_the_review_instead_of_exporting():
    session = _session()
    ui = _screen(session, view="change")
    ui._export = lambda: pytest.fail("should not export with changes undecided")

    ui._handle(ord("e"))

    assert ui.view == "review"
    assert "still undecided" in session.message


# -- what to do with the files --------------------------------------------

def test_the_export_prints_the_command_that_applies_it():
    """'I accepted twelve changes' reads as 'twelve changes happened'. It has to
    say plainly that nothing was sent, and what to run if that is what you meant."""
    session = _session()

    steps = "\n".join(_next_steps(session, Path("/tmp/aos8-lab/lab-01")))

    assert "NOT APPLIED" in steps
    assert "--remediate-apply /tmp/aos8-lab/lab-01" in steps
    assert "--remediate-dry-run" in steps
    assert "10.0.0.1" in steps          # the host it was audited against


def test_the_apply_command_is_still_printable_without_a_host():
    session = _session()
    session.plan.context.host = None

    assert "<controller>" in "\n".join(_next_steps(session, Path("/tmp/x")))


def test_the_review_page_does_not_claim_pasting_is_the_only_way():
    session = _session()

    text = _text(_review_lines(session, 78))

    assert "Press e to write the files." in text
    assert "Nothing is sent to the controller here" in text


# -- ^A, the apply key ----------------------------------------------------

def _appliable(session, view="change"):
    """A screen with a controller behind it. The hook records what it was given."""
    ui = _screen(session, view=view)
    ui.sent = []
    ui.apply_hook = lambda out_dir: ui.sent.append(out_dir) or 0
    ui._export = lambda **kw: ui.sent.append(("export", kw))
    return ui


def test_ctrl_a_asks_before_it_sends_anything():
    session = _session()
    session.queue[0].state = ChangeState.ACCEPTED
    ui = _appliable(session)
    asked = []
    ui._confirm = lambda q: asked.append(q) or False

    ui._handle(1)                                   # ^A

    assert "apply them to" in asked[0]
    assert ui.sent == []


def test_declining_the_confirmation_writes_nothing_either():
    """The files and the push are one action here, so a no has to undo both —
    a directory left behind would be applied later by someone reading it as
    reviewed."""
    session = _session()
    session.queue[0].state = ChangeState.ACCEPTED
    ui = _appliable(session)
    ui._confirm = lambda _q: False

    ui._handle(1)

    assert ui.sent == []
    assert "nothing written, nothing sent" in session.message


def test_escaping_the_apply_question_says_nothing_at_all():
    """Saying no to the key that reaches a controller earns an answer. Escaping
    out of the question is not saying no to anything."""
    session = _session()
    session.queue[0].state = ChangeState.ACCEPTED
    ui = _appliable(session)
    ui._confirm = lambda _q: None

    ui._handle(1)

    assert ui.sent == []
    assert session.message == ""


def test_ctrl_a_exports_before_it_applies():
    """The applier verifies the directory against its own hash pin, so the files
    have to exist first — and nothing can be sent that was not also written."""
    session = _session()
    session.queue[0].state = ChangeState.ACCEPTED
    ui = _appliable(session)
    ui._confirm = lambda _q: True

    assert ui._handle(1) is False                    # the wizard ends
    assert ui.sent == [("export", {"then_apply": True})]


def test_ctrl_a_with_nothing_accepted_does_not_ask():
    session = _session()
    ui = _appliable(session)
    ui._confirm = lambda _q: pytest.fail("should not ask with nothing to send")

    ui._handle(1)

    assert "nothing accepted" in session.message
    assert ui.sent == []


def test_ctrl_a_without_a_controller_says_which_flags_are_missing():
    session = _session()
    session.queue[0].state = ChangeState.ACCEPTED
    ui = _screen(session)

    ui._handle(1)

    assert "--host" in session.message


def test_the_apply_key_is_only_offered_when_there_is_something_to_apply():
    session = _session()
    ui = _screen(session)
    assert "^A" not in ui._status()

    ui.apply_hook = lambda _d: 0
    assert "^A apply" in ui._status()


def test_the_review_page_offers_the_apply_key_and_names_the_host():
    session = _session()

    text = _text(_review_lines(session, 78, apply_key="^A"))

    assert "Press ^A to write them and apply them to 10.0.0.1" in text
    assert "never runs 'write memory'" in text
