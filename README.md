# aos8-auditor

A **read-only** security-hardening auditor for ArubaOS 8 controllers. It logs in
as a read-only admin over SSHv2, runs `show` commands, and reports which of its
**149 controls** from the two HPE ArubaOS 8 hardening guides are in place — each
classified `pass` / `fail` / `warn` / `manual` / `not_applicable` / `error`,
scored by severity, and backed by preserved, **redacted** raw evidence.

The controls are drawn from *both* published guides, which are complementary
document lineages rather than two editions of one document — every finding cites
which guide backs it:

| Document | Strong on |
|---|---|
| *ArubaOS Hardening Guide* (Federal Technology Guide, AOS 8.2, v1.0, Jan 2020) — `a00105293en_us` | FIPS/JITC posture, physical & TEL handling, licensing, VRRP, initial setup |
| *ArubaOS 8 Controller Hardening Guide* (rev 10, Jan 2023) — `a00107216en_us` | cryptography configuration, firewall & control-plane defense, console lockdown, open ports, scanner false positives |

Where the two disagree, the stricter federal value is kept but reported as
`warn`, and the finding says so.

**Auditing never mutates controller state.** Only `show ...`, the session-scoped
`no paging` toggle, and read-only `cd <node>` navigation are ever transmitted —
enforced by a command allowlist *and* a verb denylist at the transport boundary.
The one code path that can send configuration is reached by a separate opt-in flag
(§13), takes a reviewed, hash-pinned file as its input, and cannot be reached from
any audit command.

It also handles Mobility Master hierarchies (per-node audit + aggregate),
crosswalks to PCI / HIPAA / SOC 2 / HITRUST / NIST 800-53 / CMMC L2, checks
configuration workarounds from published HPE Aruba Networking PSIRT advisories,
and diffs run-over-run so you can gate CI on posture drift.

When you're ready to fix what it found, `--remediate` walks you through the
changes and writes the config — `remediation.cfg`, plus a rollback and a
hash-stamped record. That step still sends nothing: you review the file and paste
it yourself.

If you'd rather not paste it, `--remediate-apply` will send that reviewed file for
you, block by block, checking after each one (§13). It is strictly opt-in, it will
only send bytes that still hash to what you reviewed, and it never saves to flash
— so a change that goes wrong is one power cycle from undone. **Auditing stays
read-only whether or not you ever use it.**

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install .
aos8-audit --version
```

For a working copy you intend to edit (and to run the test suite):

```bash
pip install -e ".[dev]"
pytest
```

Requires Python 3.11+. All runtime deps — `pydantic`, `netmiko`, `ruamel.yaml`,
`pyyaml` — are declared in `pyproject.toml`. `netmiko` is imported lazily, so the
package and test suite import cleanly with no device present.

### What you need on the controller

A dedicated **read-only** admin account (`mgmt-user <name> read-only`) reachable
over SSHv2. Commands the read-only role cannot see are recorded as `denied` and
degrade to manual review — they are never scored as failures.

## Usage

`aos8-audit` runs in one of three modes:

- **collect** (default) — SSH to a controller as a read-only admin, run the
  safelisted `show` catalog, redact, write a replayable evidence bundle to
  `runs/<run_id>/`, then audit it.
- **replay** (`--from-evidence <dir>`) — re-audit a saved bundle with **zero
  device access** (this is also how control/rule edits are regression-tested).
- **apply** (`--remediate-apply <dir>`, opt-in) — send a *reviewed export* to the
  controller, block by block (§13). Its input is an export directory rather than
  an evidence bundle, so it runs instead of the two modes above, not after them.

`aos8-audit --help` prints the full flag reference with these examples inline.

### Orient yourself (no device or credentials)

```bash
aos8-audit --version           # aos8-audit 1.0.0
aos8-audit --list-compliance   # cmmc_l2  hipaa  hitrust  nist_800_53  pci_dss  soc2
aos8-audit --help              # full reference + worked use-case examples
```

### Use cases at a glance

| Goal | Command |
|---|---|
| Audit one controller now | `aos8-audit --host wlc1 --username audit-ro --key-file ~/.ssh/k` |
| Audit a whole Mobility Master | *(same command — topology is auto-detected)* |
| Re-analyze a saved capture offline | `aos8-audit --from-evidence runs/<id>` |
| Capture evidence, score later | `aos8-audit --host … --no-audit` |
| Check CVE exposure (PSIRT advisories) | `aos8-audit --from-evidence runs/<id> --checks both` |
| Crosswalk to PCI / HIPAA / … | `aos8-audit --from-evidence runs/<id> --compliance pci_dss` |
| Gate CI on posture drift | `aos8-audit --from-evidence runs/new --diff runs/baseline` |
| Cut false positives | `… --org-profile org.yaml --attestations att.yaml --profile high_security` |
| Accept a known risk | `… --suppressions suppressions.yaml` |
| Triage a vulnerability-scanner report | `aos8-audit --from-evidence runs/<id> --scanner-findings scan.txt` |
| Generate the fix config (you paste it) | `aos8-audit --from-evidence runs/<id> --remediate` |
| Apply that config for you (opt-in, §13) | `aos8-audit --remediate-apply runs/<id> --host wlc1 --username admin` |

The recipes below expand each one.

### 1 · Audit a single controller (live)

The first thing most people run. Use a dedicated **read-only** admin account;
key-based auth is preferred, with an env-var password as a fallback:

```bash
aos8-audit --host wlc1.example.gov --username audit-ro --key-file ~/.ssh/audit_ed25519
# password fallback — put the secret in an env var (never on the command line):
export AOS_PW='…'
aos8-audit --host wlc1 --username audit-ro --password-env AOS_PW --operator "$(whoami)"
```

This collects evidence **and** audits it, writing everything under
`runs/<run_id>/` (see [What gets written](#what-gets-written)). The collection
summary and the `AUDIT … score=…/100` block print to **stdout**; progress lines
(`evidence bundle written to …`, `report written to …`) go to **stderr**.

### 2 · Audit a Mobility Master deployment

No extra flags — the **same command** works. On a Mobility Master the tool
detects the topology, enumerates the managed device nodes (`/md/<group>/<device>`,
navigation is restricted to the `/mm` and `/md` subtrees), and audits **each node
against its own effective config** (group inheritance resolved on-box; MM-global
outputs like licensing are collected once):

```bash
aos8-audit --host mm1.example.gov --username audit-ro --key-file ~/.ssh/audit_ed25519
```

Output layout differs from a standalone run:

- **Standalone / Master-Local** → `report.json` / `report.md` / `report.html`
  directly in `runs/<run_id>/`.
- **Mobility Master** → one full report per node under
  `runs/<run_id>/nodes/<slug>/` (including `report.html`), plus a top-level
  **aggregate** `report.md` (a posture table ranking each node + the union of
  controls failing on one or more nodes) and an aggregate `report.json`
  (`{mode, nodes:[{node_path, slug, model, posture_score, counts}]}` — there is
  no top-level `report.html`, and the deployment-wide detail lives in the
  aggregate `report.md`). Compliance crosswalks run per node.

### 3 · Collect once, analyze anywhere (offline / air-gapped)

Device access and analysis can be separated — useful on change-controlled or
air-gapped networks, and for iterating on controls/profiles without touching the
controller again. Collect on the sensitive side (optionally skipping the audit),
copy the bundle out, then replay it anywhere:

```bash
# On the sensitive network — capture only, no scoring:
aos8-audit --host wlc1 --username audit-ro --key-file ~/.ssh/k --no-audit

# Inspect what was actually captured (which commands were denied to the read-only
# role / unsupported on this train / empty) — prints JSON to stdout:
aos8-audit --from-evidence runs/<run_id> --no-audit --summary-json > coverage.json

# Anywhere, later — re-audit the saved bundle with no device access:
aos8-audit --from-evidence runs/<run_id> --profile high_security --org-profile org_profile.yaml
```

Replay reuses the bundle's own `run_id` and rewrites `report.*` in place; the raw
evidence (`raw/`, `collection_result.json`, `manifest.json`) is not re-collected.

### 4 · Cut false positives (intent + attestations + profile)

Some controls depend on site intent the box can't reveal (e.g. "is IPv6 in use
here?"), and some can't be proven from a read-only account at all. Declare intent
in an `org_profile.yaml` and answer the manual controls in `attestations.yaml` so
they resolve cleanly instead of guessing. Starter files ship with the package:

```bash
cp aos8_auditor/org_profile.example.yaml   org_profile.yaml      # edit for your site
cp aos8_auditor/attestations.example.yaml  attestations.yaml     # edit for your site
aos8-audit --from-evidence runs/<run_id> --profile high_security \
           --org-profile org_profile.yaml --attestations attestations.yaml
```

**Profiles** (`baseline` / `high_security` / `fips`) are overlays that escalate
"recommended" hardening to "required" as the posture tightens. Each finding is
scored by severity into a 0–100 posture score; `manual` / `not_applicable` /
`error` are excluded from the denominator so attestation-only controls don't skew
it. The active profile is chosen by precedence: `--profile` → the org-profile's
`deployment_profile` → the first `--compliance` pack's profile → `high_security`.

### 5 · Check CVE exposure — PSIRT advisory workarounds

Separate from the hardening guide, the auditor can check **configuration
workarounds from published HPE Aruba Networking security advisories**, framing
each as *what enabling it prevents*. This is off by default — opt in with
`--checks`:

```bash
aos8-audit --from-evidence runs/<run_id> --checks advisories   # advisories only
aos8-audit --from-evidence runs/<run_id> --checks both         # hardening + advisories
```

The corpus (`aos8_auditor/advisories/aos8_workarounds.csv`, one row per CVE — 157 CVEs across
18 advisories, 2021–2026) is clustered into workaround **families** by mitigation
intent; many CVEs share one action (dozens of PAPI bugs map to "restrict UDP/8211
to APs/peer controllers"). Counts come straight from the corpus; severity is a
labeled **heuristic** from each vulnerability title (the source carries no CVSS),
and CVEs with no config workaround are listed honestly as patch/upgrade-only.
Each item reads as a justification for action:

```
### Workarounds not yet applied (actionable)
- [FAIL] ADV-PAPI-8211 — Restrict PAPI (UDP/8211) to trusted devices (APs / peer controllers)
  - Applying this prevents exploitation of 18 CVE(s) (14 critical, 4 medium — severity heuristic) across 2 advisories 2021–2024.
  - remediation: Block UDP/8211 (PAPI) from untrusted networks (permit only APs/peer controllers), or enable CPSec.
  - change impact: medium (AP reboot) — firewall/ACL change on the control plane; over-broad block severs the AP↔controller channel.
  - CVEs: CVE-2023-22747, CVE-2024-26304, … advisories: 2023-002, 2024-004
```

Advisory findings never enter the hardening posture score; they carry their own
coverage rollup (exposed / already-mitigated / needs-verify / patch-only). Match
patterns are deliberately port- and interface-specific so a UDP/8211 workaround is
never miscounted under the UDP/8444 family (this clustering was adversarially
red-teamed twice). Override the packaged corpus with `--advisory-data <csv>`.

### 6 · Compliance crosswalks

Map the hardening controls to a compliance framework and get a per-requirement
report (each requirement → MET / GAP / PARTIAL / REVIEW / ACCEPTED-RISK / N/A,
plus a coverage %). `--compliance` is repeatable. Packs live in
`aos8_auditor/compliance/<framework>.yaml`:

```bash
aos8-audit --list-compliance                                        # available frameworks
aos8-audit --from-evidence runs/<run_id> --compliance pci_dss       # one crosswalk
aos8-audit --from-evidence runs/<run_id> \
           --compliance hipaa --compliance soc2                     # several at once
```

> **Crosswalks score the *hardening* findings.** Pair `--compliance` with the
> default (or `--checks both`); a `--checks advisories`-only run has no hardening
> results and will report ~0 % coverage. Also note that `REVIEW` (manual)
> requirements sit in the coverage denominator, so coverage rises as you supply
> `--attestations`.

A pack maps a framework's requirements to the control IDs that evidence them, and
may seed the run: the **first** named pack supplies the deployment `profile`
(only if you didn't pass `--profile`), all packs' deployment-intent defaults are
merged (your `--org-profile` wins), and any pack `suppressions` are *added to*
your `--suppressions`. The crosswalk is written as
`compliance_<framework>.{md,html,json}` next to the run's `report.*` (per node on
a Mobility Master).

> **These crosswalks are advisory** — they cover only the WLAN-controller
> configuration slice of each requirement, are not a certification, and a
> requirement shown MET may still need network/host/process evidence. Every pack
> carries a disclaimer; validate with a qualified assessor. To add your own
> framework or adjust a mapping, drop/edit a YAML pack in `compliance/`.

### 7 · Track drift / gate CI

`--diff` compares this run's `report.json` against a prior run's and prints what
changed. It **exits 3 if anything regressed** — i.e. a control moved to a
less-healthy status (e.g. pass → warn, warn → fail, pass → error) — so CI can fail
the build on backsliding:

```bash
aos8-audit --from-evidence runs/2026-06-01 --diff runs/2026-05-01   # compare two captures
aos8-audit --host wlc1 --username audit-ro --key-file ~/.ssh/k \
           --diff runs/baseline                                     # fresh capture vs baseline
```

`--diff` is **single-node only**; on a Mobility Master multi-node run it prints a
note and exits 0.

### 8 · Accept known risks (suppressions)

When a finding is a known, accepted risk, suppress it with an **expiry and
justification** so it's excluded from the score but stays auditable. A starter
file ships with the package:

```bash
cp aos8_auditor/suppressions.example.yaml suppressions.yaml         # edit for your site
aos8-audit --from-evidence runs/<run_id> --suppressions suppressions.yaml
```

Suppressed findings move out of the actionable fail/warn list; an **expired** or
**stale** (matched-nothing) suppression is surfaced as a `suppression warning:`
on stderr and in the report so accepted risk doesn't silently rot.

### 9 · Triage a vulnerability-scanner report

The 2023 Controller Hardening Guide's *Common False Positives* table (p.15–18) is
the single most-asked-about page in either guide: *my scanner flagged the
controller for CVE-XXXX — is it real?* It ships as
`data/scanner_false_positives.yaml` — 10 service rows, 52 CVEs, each with the
vendor's own wording — and is printed in every report whether or not you have a
scan to check.

```bash
# One CVE id or finding title per line; '#' comments and blank lines ignored.
printf 'CVE-2011-3389\nSSL Certificate Name Mismatch\nCVE-2099-0001\n' > scan.txt
aos8-audit --from-evidence runs/<run_id> --scanner-findings scan.txt
```

```
SCANNER TRIAGE  3 finding(s) submitted  action_required=1  unknown=1  false_positive=1
  2 need(s) your attention (real, or not covered by the guide's table) — see report.md
```

Each match reports one of four verdicts — `false_positive` (does not apply to
ArubaOS), `action_required` (**real; you must fix it**), `accepted_risk`
(unfixable, vendor judged the risk low), `by_design` (an intentional tradeoff or
a Common Criteria mandate) — plus the live status of any control that closes or
fixes it, so "the guide calls this a false positive" lands next to "and the
control that would remove it from your scan is currently failing."

> **Two rails, both deliberate.** The default-certificate warnings
> (`securelogin.arubanetworks.com`) are **not** a false positive — the guide is
> explicit — so that row is `action_required` and routes to `AOS8-MGMT-CERT-001`.
> And a finding the corpus doesn't recognize is reported as `unknown`, never
> silently dropped. Nothing in this section is scored and nothing suppresses a
> control: the vendor's position is about ArubaOS as shipped, and your version,
> licensed features and configuration still matter.

### 10 · Open-port and control-plane reference

Every report also carries the guide's documented open ports (43 controller, 4 AP)
and 46 control-plane protocols, joined against what this controller actually has
configured, so a port reads *"UDP/53 — the DNS responder is on, and the guide says
it's blockable without loss of service"* rather than sitting in a flat list of 43.

**No port is ever probed** — the auditor only runs `show` commands and never
scans. "Not needed here" means the *configuration* shows the service behind the
port is unused, which resolves the guide's conditional "may be blocked if X is
not in use". Ports whose state can't be determined stay `unknown` rather than
being guessed, and rows where the controller is the server for its own APs
(UDP/123 NTP, UDP/514 syslog) carry no fact at all, because the only facts
visible from the config describe the opposite direction.

Two ports get real scored controls, because the guide gives them a remedy *on the
controller* rather than on an upstream firewall: `AOS8-PORTS-DNS-RESPONDER-001`
(`no ip domain lookup`) and `AOS8-PORTS-CAPTIVE-PORTAL-001` (control-plane denies
for 8080–8083/8088 when captive portal is unused).

### 11 · Custom controls, provenance & connection tweaks

```bash
# Run an edited/local control set instead of the packaged one:
aos8-audit --from-evidence runs/<run_id> --controls-dir ./controls.local

# Record who/what/where (metadata + output location):
aos8-audit --host wlc1 --username audit-ro --key-file ~/.ssh/k \
           --operator "jane.doe" --run-id 2026-06-02-wlc1 --out /secure/audits

# Non-default SSH port / netmiko driver:
aos8-audit --host wlc1 --username audit-ro --key-file ~/.ssh/k \
           --port 2222 --device-type aruba_os_ssh
```

`--no-redact` exists for debugging only and is a loud, dangerous opt-in — it
leaves plaintext secrets in the bundle. **Caveat:** the report header and
`collection_result.json` still say *"Redaction: on"* (the flag only changes
whether secrets are scrubbed, not the recorded flag); the honest signal that a
bundle is unredacted is `redactions=0` in the collection summary.

### 12 · Turn the findings into a config (guided remediation)

An audit ends with a list of things to fix and a hint for each one. `--remediate`
walks you through those fixes **one change per screen** and writes the config you
would have typed:

```bash
aos8-audit --from-evidence runs/<run_id> --remediate
```

Each page shows the finding, what was observed, the exact commands the change will
produce, and its disruption rating. Values you have to supply — a syslog server, a
VLAN id, a shared secret — are asked for as fields and **validated as you type**
(a VLAN of 9000 is refused, an address that is the controller's own is flagged, and
a value that names something the audited config doesn't contain — an ACL, a role, a
profile, an interface — is warned about rather than left to be discovered mid-apply),
so the file that comes out is one you can paste rather than one you have to correct
at the prompt. Those warnings never block, since you may be about to create the
thing; they're repeated on the review page so a value you scrolled past doesn't
reach the artifact unnoticed. Keys: `←`/`→` move between changes (`n`/`p` too) · `↑`/`↓` move between
the fields of the change on screen · `PgUp`/`PgDn` scroll a long page · `y` accept ·
`s` skip (with a reason) · `S` skip with none · `Tab`/`Enter` fill a field · `^E`
edit the commands by hand · `a` accept everything hot (the changes rated `none`) ·
`o` overview · `r` review · `e` write the files · `^A` write them **and apply
them** · `esc` back out of a page or cancel what you are typing · `q` quit · `?`
help. Once nothing is undecided it says so,
drops you on the review page, and the status bar offers `e`. Nothing is installed
for this — it's stdlib `curses`, and on a limited terminal, over a serial console,
or with `--remediate-plain` the same walkthrough runs as plain prompts (`a` there
is the apply key).

Three files come out, all mode `0600`:

| File | What it is |
|---|---|
| `remediation.cfg` | The change, in self-contained blocks — each opens its own `configure terminal` (and `cd <node>` on a Mobility Master) and closes with `end`, so you can paste one block, verify, and continue. Every block carries the finding, the observed value, the guide citation and its disruption rating as comments; blocks that reboot an AP or the controller carry a full-width **STOP** banner. The header states the posture score the run would have if every block lands, and findings with no command form are appended as a *MANUAL* section so nothing silently drops off the list. |
| `rollback.cfg` | The reverse, in reverse order, for the blocks where a reverse exists. Where one doesn't, it records the observed value as a comment instead of guessing — a half-applied rollback is worse than none. |
| `remediation.json` | The record: what was accepted, what was skipped and why, who generated it, and the sha256 of both `.cfg` files. |

#### Blocks that are not a list of commands

One change doesn't fit the "line, line, line" shape: a banner. `banner motd ^`
doesn't take the text as an argument — it hands the CLI over to raw text entry,
and everything after it is stored verbatim until the delimiter reappears alone on
a line. The one-line form reads well and is rejected outright (`% Invalid input
detected at '^' marker.`), so the wizard, the file and the applier all treat those
lines as **text, not commands**: they are exempt from the destructive-verb and
mode-plumbing checks (an `end` in your message is a word; "Reload requests go to
the service desk" is a sentence), they keep their leading `!`, blank lines and
indentation, and the region has to close inside its own block — one that doesn't
is refused at build time rather than swallowing the rest of the file.

That also creates the one error two individually-valid answers can make together:
a delimiter that occurs in your banner text ends the banner early, and from that
point the CLI is back at a config prompt, so the rest of your message runs as
configuration. The wizard refuses the pair and says which value to change.

**`--remediate` applies nothing on its own.** It writes files. `write memory` is
never emitted, only mentioned in a closing comment. Review the file, then either
paste it yourself or hand it to `--remediate-apply` (§13) — the wizard prints that
command, filled in for this run, as the last thing it does.

If you'd rather not leave the wizard, **`^A` writes the files and applies them**,
asking `Apply changes to <host>? [Y/n]` first. `--apply-remediations` makes an
ordinary export do the same thing, so one command can audit, walk you through the
fixes and push what you accepted:

```bash
export AOS_PW='…'
aos8-audit --host wlc1 --username admin --password-env AOS_PW \
           --remediate --apply-remediations
```

Both routes export first and then apply that export, so what reaches the
controller is bytes that were written down and still hash to the file — the same
verification `--remediate-apply` performs, and the same per-block gates: the
lockout-risky changes are still confirmed one at a time, the run still stops at
the first rejection, and `write memory` is still never sent.

Skipping a change can write a suppression entry for you — with a mandatory
justification and expiry — so the same finding is accepted risk on the next run
instead of noise (see §8).

**Secrets are asked about, never assumed.** Nothing writes a password to disk
unless you say so at export time; by default the secret-bearing lines are emitted
commented out and marked `! FILL IN`, which is deliberately *not* a placeholder
that pastes cleanly. `remediation.json` masks them either way.

#### Non-interactive (pipelines, or re-generating after a re-audit)

```bash
# 1. Ask what the questions are — writes a template, no config:
aos8-audit --from-evidence runs/<run_id> --remediate-template

# 2. Edit it: set `accept: true` per control, fill `values:`, or record a skip.
#    Secrets are NOT in this file — it names an env var to read instead.

# 3. Generate the same three artifacts, with the same validation:
export VRRP_PW='…'
aos8-audit --from-evidence runs/<run_id> \
           --remediate-from runs/<run_id>/remediation_values.yaml
```

The template defaults every control to `accept: false`, so round-tripping it
unedited is a no-op rather than a silent yes to everything. A bad value fails the
run with the same message it would have shown on screen (exit `1`, no `.cfg`
written); a control that has since been fixed is a note on stderr, not a failure.

On a Mobility Master each managed node gets its own artifacts under
`nodes/<slug>/`, and the values file records the node it was gathered for — feed
it back and it applies to that node and skips the siblings, because answers
reviewed against one node's config describe a change set the others don't have.

`--remediate-out DIR` moves the artifacts elsewhere (per-node subdirectories are
kept apart under it).

### 13 · Apply an export (opt-in)

Everything above is read-only. This is the part that isn't, and it exists because
the alternative people actually reach for — pasting a 200-line block into a
terminal at 1am — has no gate on it at all.

Two flags reach it, and the difference between them is *distance*:

| | Gate |
|---|---|
| `--apply-remediations` / `^A` in the wizard — the change set you just built and read on screen | `Apply changes to <host>? [Y/n]` |
| `--remediate-apply <dir>` — an export from another session, another operator, or last Tuesday | type the word `apply` |

Everything past that gate is identical, including the per-block confirmations.

```bash
# Rehearse first. Prints every line that would be sent; opens no connection.
aos8-audit --remediate-apply runs/<run_id> --host wlc1 --username admin \
           --remediate-dry-run

# Apply. You will be asked to type 'apply', and asked again before each change
# that can cut off your own access.
export AOS_PW='…'
aos8-audit --remediate-apply runs/<run_id> \
           --host wlc1 --username admin --password-env AOS_PW
```

**The artifact is the allowlist.** There is no list of permitted commands, because
"the right change" and "the change that locks you out" are spelled with the same
verbs. What the applier will send is: the blocks of the directory you named, whose
bytes still hash to what `remediation.json` recorded. Nothing else — not a command
you pass it, not a block appended to the file afterwards, not a line edited in
place. The read-only half of the session goes through the auditor's own allowlist,
so every byte that leaves is either a verified block or a `show`.

Two shapes are refused even when they are in a verified block, because sending
them line-by-line means something other than what the block says. A command that
stops and asks a question — `controller-ip vlan <id>` answers
`This configuration change requires a reboot. Do you want to continue[y/n]:` —
doesn't stall the run, it eats the line below it as the answer; the generator
never writes one and the applier refuses it if one appears. A banner region is the
opposite case: it is one interaction rather than N commands, so the opener goes
out first and the text is only written **after** the controller confirms it
entered text entry. If the opener is rejected, not a byte of the message follows
it to a live config prompt.

Before the first block it re-audits the controller, read-only, and stops if:

- the serial, model or AOS train doesn't match the run this export came from
  (a patch bump or a different address is a warning, not a refusal),
- the running-config couldn't be read completely — a check that couldn't run must
  never read as a check that passed,
- or the export was already applied in full, which is recorded in the directory.

Anything a *different* admin already fixed is dropped rather than re-sent, which
is also what makes a stopped run resumable: re-run it and the blocks that landed
are detected and skipped.

Then, block by block:

| Step | Why |
|---|---|
| Send one block, stop at the first line the controller rejects | AOS 8 rejects a line and cheerfully accepts the next one. Pushing more config on top of a rejection is how a reviewed sequence gets applied as something else. |
| Reverse the block if it half-landed | `configure terminal` landing and the command after it failing leaves a state no file describes. Only the failed block is reversed; the ones that succeeded stand. |
| Run a heartbeat — after **every** block | Not just the ones flagged lockout-risky. The flag decides how loudly you're warned beforehand; it must not decide whether the safety net exists, or the net is only as good as a curated YAML file. |
| Re-read the controller and re-check that control | "Accepted" is what the CLI says to a command that *parsed*. A block whose commands all succeeded and whose control still fails is reported as exactly that. |

**`write memory` is never sent, and there is no flag for it.** Everything lands in
the running configuration only. That is the escape hatch: if a change cuts off your
access, the controller is one power cycle from the last saved configuration. Saving
on your behalf would trade that away to spare you one command.

#### Controllers that stage configuration

Some AOS 8 controllers — the ones carrying the Mobility-Master configuration
hierarchy, including standalones with a `/mm/mynode` of their own — don't apply
what you type in config mode at all. It goes into a pending buffer and takes
effect on `write memory`. On those boxes "nothing is saved" stops meaning *your
change is one reboot from gone* and starts meaning *your change hasn't happened
yet*, and a run where every command is accepted and every control still fails is
the expected reading rather than a broken change.

The applier asks the controller (`show configuration pending`) before the first
block and again at the end, and only claims the change is staged if it can see
this run's own commands sitting in the buffer. When it can, the outcome is
`staged` rather than `applied`, the exit code is `6`, the per-control note says
so instead of sending you to debug a command that was fine, and the next steps
lead with what makes the change happen. It still doesn't run `write memory` for
you — on that platform, the uncommitted state is the way back.

Pending configuration that was *already there* when the run started is reported
too, before anything is added to it: a `write memory` would commit somebody
else's uncommitted work along with yours.

If a staged run *stops* — a rejected command, a reversal that didn't take — none
of that advice holds, and it isn't given. What's in the buffer is then part of a
plan rather than all of one, so the outcome stays `stopped` (exit `5`), and the
warnings and next steps say to read the buffer before committing anything and
that a reload is the clean way back. A failed rollback on one of these boxes is
also not the emergency it is elsewhere: neither the change nor its reversal is in
effect, so the message says that instead of sending you to firefight a controller
that is still running exactly what it was running before.

Two more files appear in the export directory (mode `0600`): `apply_result.json`
— what was sent, what the controller said, what each control reports now — and
`apply_transcript.txt`, a plain-text record for the change ticket. Secrets reach
the controller and appear in neither. `apply_result.json` is also the interlock: a
second full apply of the same export is refused, because that change set was
planned against a configuration the controller no longer has.

#### Editing the export first

If you edit `remediation.cfg`, apply refuses it — the bytes no longer match the
pin. Re-approve it, offline:

```bash
$EDITOR runs/<run_id>/remediation.cfg
aos8-audit --remediate-approve runs/<run_id> --operator you --remediate-note CHG-1234
```

That writes `approval.json`, which records the hash it approved *and* the hash it
supersedes, plus the commands as approved. It is a separate file on purpose: a
record that rewrites its own pin to match whatever the file currently holds is not
a pin. An approval only supersedes the hash — it can't bless a block that is
incomplete or that carries a destructive verb, and the re-approval fails without
writing anything if you try.

#### Non-interactive

`--remediate-yes` answers every confirmation, including the lockout-risk ones.
Without a terminal and without that flag, the run refuses rather than assuming.
Use it only where a console fallback is actually in place.

### What gets written

A run directory (`runs/<run_id>/`, or under `--out`) contains:

| File | What it is |
|---|---|
| `report.md` / `report.html` | Human-readable report: posture score, a severity × status matrix, the **Remediation change impact** rollup, then findings split into *Actionable (fail/warn)* and *Manual / not-applicable / informational*. Each finding shows reason / observed / remediation / `change impact:` / the evidence commands (with a `(redacted)` marker). |
| `report.json` | The same findings as structured data (stable key order) — the source of truth for `--diff` and any scripting. |
| `collection_result.json` | The replayable evidence bundle (`--from-evidence` reads this). |
| `manifest.json` | Per-command exit-kind + sha256 index. |
| `raw/<command>.txt` | The redacted raw `show` output, mode `0600`, with a provenance header. |
| `compliance_<fw>.{md,html,json}` | One per `--compliance` framework (when requested). |
| `remediation.cfg` / `rollback.cfg` / `remediation.json` | The guided-remediation artifacts, mode `0600` (only with `--remediate*` — see §12). Writing them applies nothing. |
| `approval.json` | Only if you edited `remediation.cfg` and re-approved it (§13): the hash approved, the hash superseded, and the commands as approved. |
| `apply_result.json` / `apply_transcript.txt` | Only after `--remediate-apply` (§13): what was sent, what came back, and what each control reports now. `apply_result.json` is also what refuses a second apply of the same export. A run that sent nothing writes `apply_attempt.json` instead. |

The whole `runs/` tree is **git-ignored** — even redacted, it can carry sensitive
topology and hashes.

### Exit codes

For scripting and CI:

| Code | Meaning |
|---|---|
| `0` | Success — including `--list-compliance`, `--no-audit`, and a clean `--diff`. |
| `1` | Error — collection failed, or a controls / advisory-data / suppressions / compliance pack failed to load. |
| `2` | Usage — a mode that needs a connection was invoked without both `--host` and `--username`, or `--password-env` named a variable that isn't set in this shell. |
| `3` | `--diff` found a posture regression (use this to gate CI). |
| `4` | `--remediate-apply` refused before sending anything — failed verification, wrong controller, or you declined at the prompt. The controller was not changed. |
| `5` | `--remediate-apply` started and stopped part-way. Read `apply_result.json` before re-running. |
| `6` | The apply completed, and the controller stages configuration: every command was accepted and **none of it is in effect** until someone runs `write memory`. Deliberately not `0` — nothing failed, and nothing changed either. |

### Remediation change impact

The audit is read-only and never disruptive — but *fixing* a finding can be.
Every control carries a remediation disruption rating (`data/remediation_impact.yaml`):
`none` (hot) / `low` (management-plane only) / `medium` (wireless clients reauth
or specific AP(s) reboot) / `high` (controller reboot / outage). Each fail/warn
finding shows a `change impact:` line, and the report leads with a rollup so
operators can plan change windows:

```
Remediation change impact (applying fixes for the N fail/warn findings):
  high=2  medium=4  low=12  none=4
  - ⚠ controller reboot / outage required: AOS8-GLOBAL-FIPS-001, AOS8-INIT-STARTUP-001
  - wireless clients reauthenticate: AOS8-WLAN-001, AOS8-DOT1X-001, ...
  - AP reboot(s): AOS8-AP-GROUP-001, ...
```

Self-lockout risks (disabling local auth, applying an admin ACL, enforcing
cert/pubkey-only auth) are called out in the finding's `change impact` detail.

## Layout

```
aos8_auditor/
  transport/   connection (only layer that imports netmiko), the read-only
               Session, the opt-in ApplySession, topology detect
  collection/  command_catalog (safelist), redaction, classify, collector
  parse/       running-config tree + per-object parsers
  model/       evidence/collection shapes, ControllerFacts, version comparator
  engine/      ControlDef/Finding/Report contract + evaluator
  remediate/   guided remediation: hint parsing, field typing/validation, plan,
               wizard, .cfg emitters; then the opt-in apply path — approve
               (hash pin), preflight (right controller? still needed?), apply
  reporting/   JSON / Markdown / HTML reports, diffing, crosswalk output
  controls/    declarative control definitions as YAML (149 controls + profiles)
  compliance/  framework crosswalk packs as YAML
  advisories/  PSIRT corpus (CSV) + workaround families (YAML)
  data/        remediation change-impact + error-signature tables, open-port
               reference, scanner false-positive corpus
fixtures/      captured/sample outputs for offline tests
tests/         pytest suite (redaction, safelist, classify, version, replay)
tools/         dev-only, not installed: checks every command line the catalog
               can emit against a real controller's grammar. See tools/README.md
```

The `*.example.yaml` files at the top of `aos8_auditor/` (`org_profile`,
`attestations`, `suppressions`) are the starter files referenced above — copy
them out and edit for your site.

## Safety model

- **Two independent gates** (allowlist of `show`/`no paging`/`cd` forms + a
  leading-verb denylist + pipe-modifier validation + chaining/redirection block)
  mean even a buggy caller physically cannot emit a state-changing command from
  the audit path. The applier's read-only half goes through those same gates —
  shared code, not a relaxed copy.
- **Redaction is mandatory** and runs before anything touches disk; it preserves
  directive structure (so controls can still assert *presence*) and **fails
  closed** on unrecognized hash-like tokens. `--no-redact` is an explicit,
  loudly-warned opt-in.
- **`denied` / `unsupported` / `empty` are distinct from `fail`** — a command the
  read-only role cannot see degrades to manual review, never a false negative.
- **Generating a remediation writes files and nothing else.** Destructive verbs
  (`reload`, `write erase`, `delete`, …) are refused at the point the artifact is
  *built*, so a hand-edited command or an out-of-tree recipe can't smuggle one
  into the file — and refused again at the point it would be sent. So are
  commands that stop and ask for confirmation, which consume the line under them
  as the answer, and banner text regions that never close, which would swallow
  every line after them.
- **Applying is opt-in and its permission model is the artifact itself** —
  `--remediate-apply` (and `--apply-remediations`, which exports and then calls
  it) sends only blocks whose bytes still hash to what a human reviewed, one
  block at a time, with a heartbeat after each and a stop at the first refusal.
  It re-audits the controller before the first block and skips what is already
  fixed. It never runs `write memory`, so nothing it does survives a reboot until
  you decide it should. The shortcut flags change which question you are asked,
  never which bytes are eligible to be sent.
- **A remediation line can be wrong in a way that looks right**, and on ArubaOS
  the failure is not an error message. `ssh disable-ciphers hmac-sha1-96` passed
  review and every unit test; `hmac-sha1-96` is a MAC, `disable-ciphers` takes
  only `aes-cbc`/`aes-ctr`, and the bad argument dropped the parser through to
  the exec-mode SSH *client*, which printed `Password:` and waited — with the
  next line of the block queued up behind it. Three things now stand between that
  and a controller:
  - **At runtime**, a reply that stops at a question instead of the prompt is
    detected as `ExitKind.INTERACTIVE`: the prompt is cancelled, nothing further
    is sent, and the operator is told it is a bad command rather than a bad
    device. This needs no advance knowledge, so it also covers values an operator
    supplied.
  - **In CI**, `tests/test_command_lines_pinned.py` compares every line the
    catalog can emit against `tests/data/validated_command_lines.txt`, which
    records what a controller actually said about each one. A new or edited
    remediation fails the suite until someone has run it past a device.
  - **On demand**, `tools/validate_catalog.py` is that sweep. It asks the
    controller's own parser, token by token, and executes nothing. It has found
    seven defects in shipped remediations so far, two of them in *detection* —
    checks looking for a command ArubaOS cannot accept, which would have told an
    operator to re-apply a fix that was already in place, on every run.
- Audit run output (`runs/`) is **git-ignored** — even redacted, it may carry
  sensitive topology/hashes.

## License and support status

Copyright 2026 Colton Bachman. Licensed under the **Apache License, Version
2.0** — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

> **This is an independent, unofficial tool.** It is not affiliated with,
> endorsed by, or sponsored by HPE Aruba Networking. It is provided **"AS IS",
> without warranty or condition of any kind**, express or implied, with no
> service-level commitment, and it is **not serviced through any vendor's
> support channels** — use this project's issue tracker.

Findings are advisory and do not constitute a vendor security assessment or
certification. You are responsible for validating them against your own
environment and policies: a passing control is evidence, not a guarantee, and the
compliance crosswalks are a configuration-slice mapping rather than a
certification (see §6).

The control definitions restate technical recommendations from the two
*ArubaOS* hardening guides named at the top of this README, `data/open_ports.yaml`
and `data/scanner_false_positives.yaml` transcribe their reference tables, and
`advisories/aos8_workarounds.csv` is a **point-in-time
snapshot** of published HPE Aruba Networking advisories — it is not updated
automatically. Those source documents are the authoritative reference; for
current advisory text always consult the
[HPE Aruba Networking security bulletins](https://www.arubanetworks.com/support-services/security-bulletins/).

"ArubaOS", "Aruba", "HPE", and "Mobility Master" are trademarks of their
respective owners, used here solely to identify the systems this tool audits.
