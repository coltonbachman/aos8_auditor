"""The grammar oracle's reading of ArubaOS help output, pinned to real output.

This parser decides whether a command line is reported as valid or rejected, so
a mistake in it does not produce a small inaccuracy -- it produces an argument
for editing a command that was already correct. That happened: names are padded
into a fixed column, a name long enough to fill the column is followed by a
single space, and requiring two spaces hid every one of them. The catalog's
'deny-inter-user-traffic' was reported as refused by a controller that offers
it, and the next step would have been to rewrite a working remediation.

Every sample below is verbatim from an ArubaOS 8.13.3.0 MC-VA.
"""

from tools.cli_validator import CliGrammar

parse = CliGrammar._parse_completions


FIREWALL_STANZA = """\

attack-rate             Configure rate of attacks
deny-inter-user-bridg.. Disallow forwarding non-IP frames between untrusted users
deny-inter-user-traffic Disallow forwarding any frames between untrusted users
local-valid-users       Only allow local subnets in user table
no                      Delete Command
prohibit-arp-spoofing   Prohibit ARP spoofing

(ArubaMC-VA_7F_57_17) [mynode] (config-submode)#
"""


def test_a_name_that_fills_the_column_is_still_a_completion():
    """23 characters wide, one space before the description. The catalog line
    this hid was correct all along."""
    offered = parse(FIREWALL_STANZA)
    assert "deny-inter-user-traffic" in offered
    assert "deny-inter-user-bridg.." in offered
    assert "prohibit-arp-spoofing" in offered
    assert "local-valid-users" in offered


def test_the_echoed_input_line_is_not_read_as_a_completion():
    """'?' echoes what was typed. Splitting that on whitespace would offer 'no'
    as a valid token wherever the probe happened to start with it."""
    raw = ("no ip access-group \n"
           "in                      Apply access-list to interface's inbound traffic\n"
           "out                     Apply access-list to interface's outbound traffic\n"
           "session                 Apply session access-list to interface\n"
           "\n(ArubaMC-VA_7F_57_17) [mynode] (config-submode)#no ip access-group \n")
    assert sorted(parse(raw)) == ["in", "out", "session"]


def test_cr_is_not_offered_as_a_token():
    """'<cr>' says the line is already complete. Returning it as a completion
    would make the value-slot test treat the position as free-form and wave any
    argument through -- a false clear, which is the failure that reaches a
    controller rather than a human."""
    raw = ("no cipher-suite \n<cr>\n\n"
           "(ArubaMC-VA_7F_57_17) [mynode] (Web Server Configuration) #no cipher-suite \n")
    assert parse(raw) == []


def test_bare_names_with_no_description_are_completions():
    """Existing object names are listed without help text, unlike keywords."""
    raw = ("aaa server-group \n"
           "default\n"
           "internal\n"
           "<sg_name>               Name of server group\n"
           "\n(ArubaMC-VA_7F_57_17) [mynode] (config) #aaa server-group \n")
    assert sorted(parse(raw)) == ["<sg_name>", "default", "internal"]


def test_a_value_slot_holding_spaces_and_a_minus_survives():
    """'<-23 - 23>' is one slot, not three tokens. Anchoring on an alphanumeric
    first character dropped it and reported 'clock timezone <IANA-zone>
    <utc-offset>' as broken when it is fine."""
    raw = ("clock timezone PST \n"
           "<-23 - 23>              Hours offset from UTC\n"
           "\n(ArubaMC-VA_7F_57_17) [mynode] (config) #clock timezone PST \n")
    assert parse(raw) == ["<-23 - 23>"]


def test_wrapped_descriptions_do_not_become_completions():
    """A description too long for the line continues indented underneath."""
    raw = ("web-server profile \n"
           "session-timeout         Configure user's WebUI session timeout <30-3600>\n"
           "                        (seconds)\n"
           "switch-cert             Server Certificate for Management WebUI\n"
           "\n(ArubaMC-VA_7F_57_17) [mynode] (Web Server Configuration) #\n")
    assert sorted(parse(raw)) == ["session-timeout", "switch-cert"]


PPS = ("cp-bandwidth-contract untrusted-ucast \n"
       "<1-65535> pps           Rate in packets per-second (Applied as a multiple of 32\n"
       "                        in datapath)\n"
       "\n(ArubaMC-VA_7F_57_17) [mynode] (config-submode)#"
       "cp-bandwidth-contract untrusted-ucast \n")


def test_a_name_column_holding_two_words_is_still_one_completion():
    """'<1-65535> pps' is a number carrying its unit, not a keyword to type:
    the controller's own config prints 'cp-bandwidth-contract untrusted-ucast
    9765'. Reading this row as nothing at all is what let the catalog keep
    'cp-bandwidth-contract <queue> pps <n>', which the parser refuses."""
    assert parse(PPS) == ["<1-65535> pps"]


def test_a_lone_completion_row_is_not_mistaken_for_silence():
    """Silence from the parser is a verdict -- 'this prefix is not a command'.
    A row the parser printed but the tool failed to read looks identical to it,
    so a row that goes missing here turns into a rejection of a working line."""
    assert CliGrammar._parse_rows(PPS) != []


def test_a_one_word_echo_is_not_read_as_a_completion():
    """Bare rows are how existing object names are listed, and how a one-word
    echo comes back. The prompt line repeats what was typed, so it settles which
    is which."""
    raw = ("no \n"
           "aaa                     Authentication, Authorization and Accounting\n"
           "firewall                Configure firewall policies\n"
           "\n(ArubaMC-VA_7F_57_17) [mynode] (config) #no \n")
    assert sorted(parse(raw)) == ["aaa", "firewall"]
