# tools/

Development tools. **Not part of the shipped package** — nothing under
`aos8_auditor/` imports them, and they are not installed by `pip install .`.

They exist because of one failure mode that no amount of code review catches.

## The problem

A remediation line can be wrong in a way that looks right. The line that
prompted these tools was:

```
ssh disable-ciphers hmac-sha1-96
```

`hmac-sha1-96` is a MAC, not a cipher; `disable-ciphers` accepts only `aes-cbc`
and `aes-ctr`. On ArubaOS 8.13.3.0 that does **not** produce `% Invalid input`.
The parser falls through to the exec-mode SSH *client*, which prints
`Password:` and waits. The apply run then sat there until its read timeout,
reported the controller as unresponsive, and would have sent the next line of the
block in as the password.

Five more lines were wrong in quieter ways. Four of them were rollbacks written
by prefixing `no ` to the apply line, where the ArubaOS negation is already a
complete command and rejects the argument (`no ssh disable-ciphers aes-cbc`,
`no mgmt-auth certificate`, `no server-group <grp>`). Those would only ever have
failed at the moment they were needed.

None of this is knowable from the repository. It is a property of ArubaOS.

## The tools

### `validate_catalog.py`

Checks every command line the catalog can emit against a real controller's own
grammar, and **executes nothing**.

```bash
AOS_PW='...' python3 tools/validate_catalog.py \
    --host <controller> --username <user> --password-env AOS_PW
```

Use a lab controller. It enters configuration sub-modes to check the lines that
only exist inside them, which leaves empty stanza headers in the pending
configuration on a staging controller — harmless, discarded by a reload, and
reported at the end so you know they are there. It never sends `write memory`.

Re-pin the snapshot after you have read the report and fixed what it found:

```bash
python3 tools/validate_catalog.py --snapshot --from-report catalog_validation.json
```

The snapshot records a verdict per line — `ok`, `gap`, or `absent` — taken from
the run, not asserted about the catalog as a whole. `--snapshot` without
`--from-report` can only carry forward verdicts already recorded and fails on any
line it has not seen, so a newly written command cannot be promoted to "checked"
without a controller having answered for it.

`--from-report` refuses outright to record a rejection. Either the line is wrong
and the answer is to fix it, or the keyword is not on the platform you swept and
it belongs in `PLATFORM_ABSENT` with what it would take to settle.

### Placeholders

The catalog is full of `<site-ip>`, `<id>`, `<secret>`. A placeholder is not a
value, so the parser has nothing to say after one — and a token-by-token walk
that treats silence as "nothing to check here" stops examining the line at the
first placeholder while still reporting it walked. Nine lines were being cleared
that way, and one of them was wrong four tokens in.

So the walk resolves each placeholder to a concrete stand-in and *tries it*,
keeping the first the controller accepts, rather than guessing. What that
bought:

```
before   161 checked, 36 unvalidated
after    174 checked, 27 unvalidated
```

and the line it found:

```
cp-bandwidth-contract untrusted-ucast pps 20     # refused
cp-bandwidth-contract untrusted-ucast 20         # what the controller wants
```

`cp-bandwidth-contract untrusted-ucast ?` answers `<1-65535> pps`. That names the
unit of the value; it is not a token to type. A controller's own running config
prints `cp-bandwidth-contract untrusted-ucast 9765`. Both this repository's
remediation *and the test asserting it was right* had made the same misreading.

### `cli_validator.py`

The grammar oracle the above is built on. Typing `?` makes the ArubaOS parser
answer immediately, on the *unsubmitted* line: it prints the completions for what
you have typed so far and leaves your text in the input buffer. So the validator
writes `<line> ?` with no newline, reads the answer, and sends ctrl-U to wipe the
line. Nothing reaches the parser as a command.

One thing worth knowing before you trust it: **appending `?` to a whole line does
not report a bad argument.** The parser answers the part it liked and ignores the
rest, so `ssh disable-ciphers hmac-sha1-96 ?` looks perfectly healthy. Validation
has to walk the line token by token, asking at each boundary whether the next
token is one the grammar offers there. That is what `CliGrammar.check` does, and
it is the difference between the sweep that found six defects and the first one,
which found none.

Two properties of the reader are worth stating, because both were wrong once and
both failed *toward* declaring a line valid:

- **Help output is column-padded, not gap-delimited.** A completion name long
  enough to fill its 24-character column is followed by a single space, and a
  name can itself contain one (`<1-65535> pps`). Splitting on two-or-more spaces
  made those rows invisible, which read as "the parser offered nothing".
- **Silence from the parser is a verdict, not a gap.** Every prefix of a real
  command answers with completions, or `<cr>`, or both; a prefix it cannot parse
  answers with nothing. Treating that as "unchecked" is what let a wrong argument
  sit at a position the grammar left open, since only the *next* probe reveals
  that the line has stopped being a command.

## What this cannot tell you

The oracle proves the parser accepts the *shape* of a line. It does not prove the
line does anything:

- `no crypto isakmp policy 20` is accepted and then reports
  "Config deletion will not take effect: configuration is inherited."
- A placeholder is resolved to a stand-in the parser accepts, which proves the
  *shape* of the argument and nothing about the operator's actual value.
  `logging <syslog-server-ip>` is checked with an address; whether the real one
  is reachable is not a grammar question. The runtime side of that gap is covered
  by `Connection.send_line`, which detects a command that opened a prompt and
  cancels it rather than feeding the next line in as the answer.
- One controller answers for one platform on one release — and the platform is
  load-bearing. `fips enable` and `lcd-menu` are not "valid but refused at
  execution" on the lab MC-VA; the keywords are absent from its grammar
  entirely, so it has no opinion to give. Those four lines are recorded as
  `absent` rather than checked, and settling them needs a FIPS image and a
  controller with a front panel respectively.
