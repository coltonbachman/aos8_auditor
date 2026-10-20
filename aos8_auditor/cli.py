"""Command-line entrypoint for the ArubaOS 8 hardening auditor.

Modes:
  * **collect** (default): open a read-only SSH session, run the safelisted
    command catalog, redact, write a replayable evidence bundle under
    ``runs/<run_id>/``, then audit it and write report.json / report.md.
  * **replay** (``--from-evidence <dir>``): reload a prior bundle and audit it
    with zero device access (also how rule/control changes are tested).
  * **apply** (``--remediate-apply <dir>``): the opt-in write path. Its input is
    a reviewed export directory rather than an evidence bundle, so it runs
    instead of the two modes above, not after them. Everything else in this file
    is read-only and stays that way.

Use ``--no-audit`` to only collect/replay the evidence without classifying.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

from . import __version__
from .collection.collector import Collector
from .reporting.json_report import collection_summary


_DESCRIPTION = """\
ArubaOS 8 controller security auditor: read-only auditing, opt-in remediation.

Auditing logs in as a read-only admin over SSHv2, runs `show` commands (never
anything that mutates state), redacts secrets, and reports which hardening-guide
controls are in place — each pass/fail/warn/manual/not_applicable/error, scored by
severity, with preserved redacted evidence. Can also crosswalk to compliance
frameworks and check configuration workarounds from published PSIRT advisories.

Remediation is opt-in: it generates a config for you to review and can push it to
the controller, but never runs 'write memory' — saving is left to you.
"""

_EPILOG = """\
modes:
  collect (default)         SSH in, run the read-only command catalog, redact, write a
                            replayable bundle to runs/<run_id>/, then audit it.
  replay  --from-evidence   re-audit a saved runs/<id> bundle with NO device access.

common use cases:
  # Orient yourself (no device, no credentials needed)
  aos8-audit --version
  aos8-audit --list-compliance

  # Audit one controller now (key auth preferred; password via env var fallback)
  aos8-audit --host wlc1 --username audit-ro --key-file ~/.ssh/id_ed25519
  export AOS_PW=secret; aos8-audit --host wlc1 --username audit-ro --password-env AOS_PW

  # Audit a whole Mobility Master (SAME command — topology is auto-detected; you get
  # one report per managed node plus a top-level aggregate)
  aos8-audit --host mm1 --username audit-ro --key-file ~/.ssh/id_ed25519

  # Capture evidence now, score it later (e.g. on an air-gapped / change-controlled net)
  aos8-audit --host wlc1 --username audit-ro --key-file ~/.ssh/k --no-audit
  aos8-audit --from-evidence runs/<run_id> --summary-json    # collection coverage as JSON

  # Re-analyze a saved capture offline (no device access; also how rule edits are tested)
  aos8-audit --from-evidence runs/<run_id>

  # Cut false positives: declare deployment intent + answer the manual controls
  aos8-audit --from-evidence runs/<run_id> --profile high_security \\
             --org-profile org_profile.yaml --attestations attestations.yaml

  # CVE exposure (PSIRT advisory workarounds; default runs hardening only)
  aos8-audit --from-evidence runs/<run_id> --checks both

  # Compliance crosswalk (repeatable). NOTE: crosswalks score the HARDENING findings,
  # so use --checks both/hardening (the default), NOT advisories-only.
  aos8-audit --from-evidence runs/<run_id> --compliance pci_dss --compliance hipaa

  # Triage a scanner report against the guide's Common False Positives table
  aos8-audit --from-evidence runs/<run_id> --scanner-findings nessus_cves.txt

  # Accept known risks with an expiry + justification trail
  aos8-audit --from-evidence runs/<run_id> --suppressions suppressions.yaml

  # Turn the findings into a config you can paste (EXPORT ONLY — nothing is sent)
  aos8-audit --from-evidence runs/<run_id> --remediate

  # Same thing without a terminal: answer by file, then generate
  aos8-audit --from-evidence runs/<run_id> --remediate-template
  $EDITOR runs/<run_id>/remediation_values.yaml      # set accept: true, fill values
  export VRRP_PW=...; aos8-audit --from-evidence runs/<run_id> \\
             --remediate-from runs/<run_id>/remediation_values.yaml

  # Gate CI on posture drift (single-node only; exits 3 if anything regressed)
  aos8-audit --from-evidence runs/new --diff runs/baseline

applying an export (OPT-IN — every command above is read-only):
  # 1. Rehearse. Prints every line that would be sent; contacts nothing.
  aos8-audit --remediate-apply runs/<run_id> --host wlc1 --username admin \\
             --remediate-dry-run

  # 2. Apply it. Verifies the files against their own hash, checks it is the same
  #    controller, skips anything already fixed, and stops at the first refusal.
  export AOS_PW=secret; aos8-audit --remediate-apply runs/<run_id> \\
             --host wlc1 --username admin --password-env AOS_PW

  # If you edited remediation.cfg, re-approve it first (offline) or apply refuses
  $EDITOR runs/<run_id>/remediation.cfg
  aos8-audit --remediate-approve runs/<run_id> --operator you

  # Or do the whole thing in one pass: audit, walk the wizard, push what you accept.
  # Asks 'Apply changes to <host>?' before sending, and again per lockout-risky block.
  export AOS_PW=secret; aos8-audit --host wlc1 --username admin \\
             --password-env AOS_PW --remediate --apply-remediations
  # (^A in the wizard does the same thing on demand, with or without the flag.)

exit codes:
  0  success / diff clean / --list-compliance / --no-audit / apply completed
  1  error (collection, or loading controls/advisory-data/suppressions/compliance pack)
  2  usage: a mode that needs a connection was invoked without --host/--username,
     or --password-env named a variable that is not set in this shell
  3  --diff found a posture regression (for CI gating)
  4  apply refused before sending anything (failed verification, wrong controller,
     or you declined at the prompt) — the controller was not changed
  5  apply started and stopped part-way; read apply_result.json before re-running
  6  apply completed, and this controller stages configuration: every command was
     accepted and none of it is in effect until someone runs 'write memory'

notes:
  * Evidence is redacted before it ever touches disk; --no-redact opts out (loudly).
  * --host/--username are validated at runtime, not by argparse.
  * Frameworks available to --compliance come from --list-compliance.
  * Outputs land in runs/<run_id>/ (or --out): report.json/.md/.html, the replayable
    collection_result.json, manifest.json, and redacted raw/<command>.txt (mode 0600).
  * Auditing is read-only, always. --remediate on its own only writes files (0600).
    --remediate-apply and --apply-remediations are the two opt-in flags that can send
    configuration, and all either can send is blocks that were written to a file and
    still hash to it. Neither is reachable from an audit-only command.
  * Nothing here ever runs 'write memory'. The changes stay in the running
    configuration until you save them, which is what makes a reboot the way out.
  * Secrets are never written to a values file — it names an environment variable to
    read instead, and remediation.cfg leaves secret lines commented out unless you
    say otherwise at export time.
  * On a Mobility Master each managed node gets its own artifacts, and a values file
    records the node it was gathered for so it cannot be applied to a sibling.
"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aos8-audit",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"aos8-audit {__version__}")

    conn = p.add_argument_group("connection (collect mode)")
    conn.add_argument("--host", help="controller hostname/IP")
    conn.add_argument("--username", help="read-only admin username")
    conn.add_argument("--key-file", help="SSH private key path (preferred)")
    conn.add_argument("--password-env", help="env var holding the SSH password (fallback to key auth)")
    conn.add_argument("--port", type=int, default=22, help="SSH TCP port (default: 22)")
    conn.add_argument("--device-type", default="aruba_os",
                      help="netmiko device_type for the controller SSH driver "
                           "(default: aruba_os; try aruba_os_ssh if prompt/paging handling misbehaves)")

    out = p.add_argument_group("output")
    out.add_argument("--out", default="runs", help="output root directory (default: runs/)")
    out.add_argument("--run-id", help="override the generated run id")
    out.add_argument("--operator", help="who is running the audit (recorded in metadata)")
    out.add_argument("--no-redact", action="store_true", help="DANGER: do not redact secrets in evidence")

    aud = p.add_argument_group("audit")
    aud.add_argument("--profile", choices=["baseline", "high_security", "fips"],
                     help="deployment profile (overrides org-profile's deployment_profile)")
    aud.add_argument("--org-profile", metavar="YAML", help="operator-declared intent (org_profile.yaml)")
    aud.add_argument("--attestations", metavar="YAML", help="operator answers for manual controls")
    aud.add_argument("--suppressions", metavar="YAML", help="accepted-risk suppressions (expiry + justification)")
    aud.add_argument("--controls-dir", metavar="DIR", help="control YAML directory (default: packaged)")
    aud.add_argument("--checks", choices=["hardening", "advisories", "both"], default="hardening",
                     help="which checks to run: hardening-guide controls, PSIRT advisory workarounds, "
                          "or both (default: hardening)")
    aud.add_argument("--advisory-data", metavar="CSV",
                     help="override the packaged advisory corpus CSV (advisory/cve/workaround rows)")
    aud.add_argument("--scanner-findings", metavar="FILE",
                     help="triage a vulnerability scanner's output against the hardening guide's "
                          "Common False Positives table: one CVE id or finding title per line "
                          "('#' comments and blank lines ignored). The corpus is reported either "
                          "way; this only adds the per-finding verdicts")
    aud.add_argument("--no-audit", action="store_true", help="collect/replay only; skip classification")
    aud.add_argument("--diff", metavar="RUN_DIR",
                     help="diff this run's report against a prior run's report.json; "
                          "exits 3 on a posture regression (single-node runs only)")
    aud.add_argument("--compliance", metavar="FRAMEWORK", action="append", default=[],
                     help="emit a compliance crosswalk for a packaged framework (repeatable); "
                          "the first pack's profile/intent/suppressions seed the run")
    p.add_argument("--list-compliance", action="store_true", help="list available compliance frameworks and exit")

    p.add_argument("--from-evidence", metavar="RUN_DIR",
                   help="replay a prior runs/<id> bundle and audit it with no device access")
    p.add_argument("--summary-json", action="store_true",
                   help="print the collection coverage summary as JSON to stdout (instead of text)")

    rem = p.add_argument_group("remediation export (writes files; never touches a controller)")
    rem.add_argument("--remediate", action="store_true",
                     help="after the audit, walk through the recommended fixes one change at a "
                          "time and write remediation.cfg / rollback.cfg / remediation.json. "
                          "EXPORT ONLY: nothing is sent to the controller — a human reviews the "
                          "file and pastes it")
    rem.add_argument("--remediate-from", metavar="YAML",
                     help="non-interactive remediation: take the answers from a values file "
                          "instead of prompting (see --remediate-template)")
    rem.add_argument("--remediate-template", action="store_true",
                     help="write a values-file template for this run's findings and exit "
                          "(pairs with --remediate-from)")
    rem.add_argument("--remediate-out", metavar="DIR",
                     help="where to write the remediation artifacts (default: alongside the report)")
    rem.add_argument("--remediate-plain", action="store_true",
                     help="use the prompt-driven wizard even on a full terminal")

    # Opt-in, and separate from every group above on purpose: everything else in
    # this tool reads. These two flags are the only way to reach a code path that
    # can send a configuration command, and you have to name a reviewed directory
    # to get there — there is no --fix-everything.
    app = p.add_argument_group(
        "remediation apply (OPT-IN: the only flags that write to a controller)")
    app.add_argument("--remediate-apply", metavar="DIR",
                     help="apply a reviewed export directory to the controller named by "
                          "--host, one block at a time, checking after each. Verifies the "
                          "files against their own hash first and refuses if they were "
                          "edited without --remediate-approve. Never runs 'write memory'")
    app.add_argument("--remediate-approve", metavar="DIR",
                     help="re-approve an export you edited by hand: re-reads the directory, "
                          "checks it is still coherent, and writes approval.json. Offline — "
                          "no controller is contacted")
    app.add_argument("--remediate-dry-run", action="store_true",
                     help="rehearse --remediate-apply: print every command that would be "
                          "sent, contact nothing")
    app.add_argument("--remediate-yes", action="store_true",
                     help="answer yes to the confirmations --remediate-apply would ask, "
                          "including the ones for changes that can cut off your own access. "
                          "For change automation with a console fallback in place")
    app.add_argument("--apply-remediations", action="store_true",
                     help="with --remediate/--remediate-from: send the export to the "
                          "controller as soon as it is written, instead of stopping at "
                          "the files. Asks 'Apply changes to <host>?' first, still asks "
                          "again before each change that can cut off your access, and "
                          "still never runs 'write memory'")
    app.add_argument("--remediate-note", metavar="TEXT",
                     help="change-ticket reference or reason, recorded in approval.json / "
                          "apply_result.json")
    return p


def _load_yaml(path: str | None) -> dict:
    if not path:
        return {}
    return yaml.safe_load(Path(path).read_text()) or {}


def _env_password(name: str | None, *, key_file: str | None) -> tuple[str | None, str | None]:
    """Read the SSH password out of the environment. Returns (password, error).

    An unset or empty variable is refused rather than quietly falling through to
    key auth. Netmiko reports the result as "No authentication methods available"
    from somewhere inside paramiko, which reads like a device or account problem
    and sends people to look at the controller — when what actually happened is
    that the export never made it into the shell that ran the command.
    """
    if not name:
        return None, None
    value = os.environ.get(name)
    if value:
        return value, None
    state = "set but empty" if name in os.environ else "not set"
    if key_file:
        # Key auth can still carry the session, so this is a note, not a stop.
        print(f"warning: --password-env {name} is {state}; continuing with {key_file}",
              file=sys.stderr)
        return None, None
    return None, (f"error: --password-env {name} is {state} in this shell, and no "
                  "--key-file was given, so there is nothing to authenticate with. "
                  f"Export {name} in the same shell that runs this command.")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.list_compliance:
        from .engine.compliance import list_packs
        for name in list_packs():
            print(name)
        return 0

    # 0. The apply path. Its input is a reviewed export directory, not an evidence
    #    bundle, so it short-circuits everything below: there is no audit to run
    #    and nothing to collect. Keeping it here rather than folding it into the
    #    remediation section is deliberate — it is the one branch that writes.
    if args.remediate_approve:
        return _run_approve(args)
    if args.remediate_apply:
        return _run_apply(args)

    # 1. Obtain a CollectionResult + the directory to write the report into.
    if args.from_evidence:
        result = Collector.from_evidence(args.from_evidence)
        run_dir = Path(args.from_evidence)
    else:
        if not (args.host and args.username):
            print("error: --host and --username are required for collection "
                  "(or use --from-evidence to replay)", file=sys.stderr)
            return 2
        if args.no_redact:
            print("WARNING: --no-redact set — evidence will contain unredacted secrets.", file=sys.stderr)
        try:
            from .transport.ssh_session import SSHConfig, Session
        except Exception as e:  # pragma: no cover
            print(f"error: transport unavailable: {e}", file=sys.stderr)
            return 1
        password, problem = _env_password(args.password_env, key_file=args.key_file)
        if problem:
            print(problem, file=sys.stderr)
            return 2
        config = SSHConfig(host=args.host, username=args.username, key_file=args.key_file,
                           password=password, port=args.port, device_type=args.device_type)
        collector = Collector(None, out_root=args.out, run_id=args.run_id)
        try:
            with Session(config) as session:
                collector.runner = _RedactToggle(session, redact_output=not args.no_redact)
                result = collector.collect_topology(host=args.host)
        except Exception as e:
            print(f"error: collection failed: {e}", file=sys.stderr)
            return 1
        run_dir = collector.write_bundle(result)
        print(f"evidence bundle written to {run_dir}", file=sys.stderr)

    _print_collection_summary(result, as_json=args.summary_json)

    if args.no_audit:
        return 0

    # 2. Audit the collected evidence (per node on a Mobility Master).
    from .engine import audit_topology, build_advisory_controls, load_controls

    run_hardening = args.checks in ("hardening", "both")
    run_advisory = args.checks in ("advisories", "both")

    try:
        controls = load_controls(args.controls_dir)
    except Exception as e:
        print(f"error: could not load controls: {e}", file=sys.stderr)
        return 1
    if run_hardening and not controls:
        print("no controls found; skipping audit (use --no-audit to silence)", file=sys.stderr)
        return 0

    advisory_controls: list = []
    advisory_prevents: dict = {}
    advisory_version = None
    if run_advisory:
        try:
            advisory_controls, advisory_prevents, adv_meta = build_advisory_controls(args.advisory_data)
            advisory_version = adv_meta.get("version")
            print(f"advisories: {adv_meta['total_cves']} CVEs across {adv_meta['advisories']} advisories "
                  f"({adv_meta['year_min']}-{adv_meta['year_max']}); {adv_meta['config_mitigable_cves']} "
                  f"config-mitigable, {adv_meta['patch_only_cves']} patch-only", file=sys.stderr)
        except Exception as e:
            print(f"error: could not load advisory data: {e}", file=sys.stderr)
            return 1

    effective_controls = controls if run_hardening else []

    org_profile = _load_yaml(args.org_profile)
    attestations = _load_yaml(args.attestations)

    # Compliance packs seed the run: the first pack's profile/intent/suppressions
    # are applied (user flags still win), and every pack gets a crosswalk report.
    from .engine.compliance import evaluate_compliance, load_pack, validate_pack_controls
    from .engine.suppressions import load_suppressions, suppressions_from_items

    packs = []
    for name in args.compliance:
        try:
            packs.append(load_pack(name))
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    pack_org_defaults: dict = {}
    pack_suppression_items: list = []
    pack_profile = None
    for pk in packs:
        for k, v in (pk.org_profile_defaults or {}).items():
            pack_org_defaults.setdefault(k, v)
        pack_suppression_items.extend(pk.suppressions or [])
        if pack_profile is None and pk.profile:
            pack_profile = pk.profile
    # Precedence: explicit --org-profile values win over pack defaults.
    merged_org = {**pack_org_defaults, **org_profile}
    active_profile = args.profile or org_profile.get("deployment_profile") or pack_profile or "high_security"

    try:
        suppressions = load_suppressions(args.suppressions) + suppressions_from_items(pack_suppression_items)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Surface any dangling control references in the packs.
    valid_ids = {c.id for c in controls}
    for pk in packs:
        dangling = validate_pack_controls(pk, valid_ids)
        if dangling:
            print(f"warning: compliance pack '{pk.name}' references unknown control id(s): "
                  + ", ".join(dangling), file=sys.stderr)

    scanner_findings = None
    if args.scanner_findings:
        from .engine.scanner_fp import load_findings
        try:
            scanner_findings = load_findings(args.scanner_findings)
        except OSError as e:
            print(f"error: --scanner-findings: {e}", file=sys.stderr)
            return 1

    org_profile = merged_org
    node_reports = audit_topology(
        result, effective_controls,
        tool_version=__version__,
        active_profile=active_profile,
        org_profile=org_profile,
        attestations=attestations,
        suppressions=suppressions,
        operator=args.operator,
        advisory_controls=advisory_controls,
        advisory_prevents=advisory_prevents,
        advisory_catalog_version=advisory_version,
        scanner_findings=scanner_findings,
    )

    from .reporting.topology_report import write_topology
    written = write_topology(node_reports, run_dir)

    if written["mode"] == "single":
        rep = node_reports[0].report
        print(f"report written to {run_dir} (report.json / report.md / report.html)", file=sys.stderr)
        _print_audit_summary(rep)
        for w in rep.run_metadata.suppression_warnings:
            print(f"  suppression warning: {w}", file=sys.stderr)
    else:
        from .reporting.report import advisory_rollup
        print(f"\nMOBILITY MASTER — {len(node_reports)} managed node(s); aggregate: {written['paths']['markdown']}")
        for nr in node_reports:
            s = nr.report.summary
            line = (f"  {nr.node_path}  score={s.posture_score}/100  "
                    f"fail={s.counts.get('fail', 0)} warn={s.counts.get('warn', 0)}")
            if nr.report.advisory_results:
                line += f"  advisory-exposed={advisory_rollup(nr.report.advisory_results)['exposed']}"
            print(line)

    # 3. Compliance crosswalk report(s) — per node on a Mobility Master.
    if packs:
        from .reporting.compliance_report import write_compliance_report
        for nr in node_reports:
            cdir = written["node_dirs"].get(nr.node_path, run_dir)
            for pk in packs:
                cr = evaluate_compliance(pk, nr.report.results)
                write_compliance_report(cr, nr.report, cdir)
                label = "" if written["mode"] == "single" else f" [{nr.node_path}]"
                print(f"COMPLIANCE {pk.framework}{label}  coverage={cr.coverage_pct}%  "
                      + "  ".join(f"{k}={v}" for k, v in sorted(cr.counts.items())))

    # 4. Guided remediation. Export only — see aos8_auditor/remediate/__init__.py.
    if args.remediate or args.remediate_from or args.remediate_template:
        rc = _run_remediation(args, result, node_reports, written, run_dir)
        if rc:
            return rc

    # 5. Run-over-run diff (single-node only).
    if args.diff:
        if written["mode"] != "single":
            print("note: --diff is not supported for Mobility Master multi-node runs (skipped)", file=sys.stderr)
            return 0
        from .reporting.diff import diff_reports, load_report, render_diff_text
        try:
            prior = load_report(args.diff)
        except FileNotFoundError as e:
            print(f"error: --diff: {e}", file=sys.stderr)
            return 1
        d = diff_reports(prior, node_reports[0].report)
        print("\n" + render_diff_text(d))
        if d.has_regressions:
            return 3  # non-zero so CI can gate on regressions
    return 0


def _run_remediation(args, collection, node_reports, written, run_dir: Path) -> int:
    """Drive the guided remediation wizard for every audited node.

    Nothing here opens a session. The wizard reads the report that was just
    written and produces files; applying them stays a human action.
    """
    from .parse.model_builder import build_controller_model
    from .remediate import ExportOptions, build_plan, context_from_model, write_artifacts
    from .remediate.values import apply_values, load_values, template_for
    from .remediate.wizard import run as run_wizard
    # Same slug the report writer uses, so nodes/<slug>/ and the remediation
    # directory for that node carry the same name and can be matched by eye.
    from .reporting.topology_report import _slug

    matched_a_node = False
    apply_codes: list[int] = []  # exit codes from any apply the operator triggered
    for nr in node_reports:
        report = nr.report
        if not report.results and not report.advisory_results:
            continue
        node_dir = written["node_dirs"].get(nr.node_path, run_dir)
        out_dir = Path(args.remediate_out) if args.remediate_out else node_dir
        if args.remediate_out and len(node_reports) > 1:
            out_dir = out_dir / _slug(nr.node_path)

        model = build_controller_model(collection, node_path=nr.node_path)
        plan = build_plan(report, context_from_model(model, host=args.host))
        label = "" if written["mode"] == "single" else f" [{nr.node_path}]"

        if args.remediate_template:
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / "remediation_values.yaml"
            path.write_text(template_for(plan), encoding="utf-8")
            print(f"remediation values template{label}: {path}")
            continue

        if args.remediate_from:
            try:
                data = load_values(args.remediate_from)
            except (OSError, ValueError) as e:
                print(f"error: --remediate-from: {e}", file=sys.stderr)
                return 1
            applied = apply_values(plan, data)
            if applied.node_mismatch:
                print(f"  note{label}: values file was gathered for "
                      f"{applied.node_mismatch}; skipping this node", file=sys.stderr)
                continue
            matched_a_node = True
            for w in applied.warnings:
                print(f"  warning{label}: {w}", file=sys.stderr)
            for c in applied.unknown_controls:
                print(f"  note{label}: {c} is not a finding in this run (already fixed?)",
                      file=sys.stderr)
            if not applied.ok:
                for e in applied.errors:
                    print(f"error{label}: {e}", file=sys.stderr)
                return 1
            if not applied.accepted:
                print(f"remediation{label}: nothing accepted in the values file; "
                      "no artifacts written")
                continue
            res = write_artifacts(plan, out_dir, ExportOptions(operator=args.operator))
            print(f"remediation{label}: {len(applied.accepted)} change(s) -> "
                  f"{res.remediation_cfg}")
            print(f"  rollback: {res.rollback_cfg}   record: {res.remediation_json}")
            if not args.apply_remediations:
                print("  NOT APPLIED. Review the file, then paste it yourself.")
                continue
            _apply_hook(args, apply_codes)(out_dir)
            continue

        # The hook goes in whether or not --apply-remediations was passed: the
        # flag decides whether exporting applies on its own, but the apply key is
        # always on the keyboard, and a wizard that hides it until you restart
        # the whole audit with another flag is a wizard people paste around.
        run_wizard(plan, out_dir, operator=args.operator,
                   suppressions_path=args.suppressions,
                   force_plain=args.remediate_plain,
                   apply_hook=_apply_hook(args, apply_codes),
                   apply_on_export=args.apply_remediations)

    if args.remediate_from and not matched_a_node:
        # Silently doing nothing here would read as "no changes needed".
        print("error: --remediate-from: the values file names a node that was not "
              "audited in this run; nothing was written", file=sys.stderr)
        return 1
    # A refused or half-finished apply has to reach the caller. Worst code wins:
    # on a Mobility Master one node landing cleanly says nothing about the next.
    return _worst_apply_code(apply_codes) if apply_codes else 0


# Which node's outcome the caller hears about when several were applied to.
# Spelled out rather than max(), because the codes are identifiers and not a
# scale: 6 is a run that completed and needs a commit, while 5 is the one
# somebody has to go and look at, and the larger number is the smaller problem.
_APPLY_SEVERITY = (5, 1, 2, 4, 6, 0)


def _worst_apply_code(codes: list[int]) -> int:
    return next((c for c in _APPLY_SEVERITY if c in codes), max(codes))


def _apply_hook(args, outcome: list[int]):
    """Build the callback the wizard uses to push what it just wrote.

    The wizard has no idea how to reach a controller and should not learn: it
    hands back a directory, and this turns that into the same apply run
    --remediate-apply performs, against the same verification.
    """
    def hook(out_dir) -> int:
        rc = _run_apply(args, out_dir, gate="confirm")
        outcome.append(rc)
        return rc
    return hook


# --------------------------------------------------------------------------
# the opt-in write path
# --------------------------------------------------------------------------

def _load_and_verify(directory: str):
    """Load an export directory and check it against its own pin.

    Returns ``(artifact, report)``, or ``(None, None)`` after printing why the
    directory could not be read at all.
    """
    from .remediate.approve import ArtifactError, load_artifact, verify
    try:
        artifact = load_artifact(directory)
    except ArtifactError as e:
        print(f"error: {e}", file=sys.stderr)
        return None, None
    return artifact, verify(artifact)


def _run_approve(args) -> int:
    """Re-approve an export that was edited by hand. Contacts nothing."""
    from .remediate.approve import approval_document, verify, write_approval

    artifact, report = _load_and_verify(args.remediate_approve)
    if artifact is None:
        return 1

    # Build the approval and try it on before writing it. An approval only
    # supersedes the hash pin — it is not a way to sign off on a block that is
    # incomplete or that carries a destructive command, and finding that out
    # after the file is on disk would leave a directory that looks approved.
    document = approval_document(artifact, operator=args.operator,
                                 note=args.remediate_note)
    artifact.approval = document
    trial = verify(artifact)
    if not trial.ok:
        print("error: this export cannot be approved as it stands:", file=sys.stderr)
        for e in trial.errors:
            print(f"  - {e}", file=sys.stderr)
        return 4

    path = write_approval(artifact, document)
    for w in trial.warnings:
        print(f"warning: {w}", file=sys.stderr)
    print(f"approved {len(artifact.blocks)} change(s) in {artifact.directory}")
    print(f"  {path}")
    print("  The pin now follows the edited file. Re-read it before applying.")
    return 0


def _apply_summary(artifact, report) -> None:
    from .engine.impact import impact_for

    source = artifact.record.get("source_run") or {}
    target = artifact.target
    print(f"export    : {artifact.directory}")
    print(f"node      : {artifact.node_path}")
    print(f"from run  : {source.get('run_id') or 'unknown'}"
          f"  ({target.get('model') or '?'} {target.get('aos_version') or '?'})")
    print(f"pinned by : {report.pinned_by}")
    print(f"changes   : {len(artifact.blocks)}")
    for block in artifact.blocks:
        impact = impact_for(block.control_id)
        flag = "  ** can cut off your own access **" if impact.lockout_risk else ""
        print(f"  - {block.control_id}{flag}")
    for w in report.warnings:
        print(f"warning: {w}", file=sys.stderr)


def _run_apply(args, directory: str | Path | None = None, *,
               gate: str = "typed") -> int:
    """Apply a reviewed export. The only path in this tool that writes.

    ``gate`` is how the operator is asked. ``"typed"`` makes them type the word
    ``apply``; ``"confirm"`` is a plain [Y/n]. The difference is distance: an
    export handed over from another session, another operator or last Tuesday
    gets the deliberate one, while a change set the operator just built and
    approved on screen in this run gets the ordinary one. Both send exactly the
    same bytes and both keep every per-block warning.
    """
    from .remediate.apply import ApplyOptions, apply_artifact
    from .transport.apply_session import ApplyRefused, ApplySession
    from .transport.connection import SSHConfig, TransportError

    directory = directory or args.remediate_apply
    artifact, report = _load_and_verify(directory)
    if artifact is None:
        return 1
    if not report.ok:
        print("refusing to apply this export:", file=sys.stderr)
        for e in report.errors:
            print(f"  - {e}", file=sys.stderr)
        print("\nIf you edited the file on purpose, re-approve it:\n"
              f"  aos8-audit --remediate-approve {directory}", file=sys.stderr)
        return 4

    if not (args.host and args.username):
        print("error: applying needs --host and --username (the same credentials "
              "the audit used, or a write-capable account)", file=sys.stderr)
        return 2

    # Before the summary and the prompt, not after: asking someone to type 'apply'
    # and then failing on a shell variable wastes the one decision that matters.
    # A dry run opens no socket, so it needs no credentials to rehearse.
    password, problem = (None, None) if args.remediate_dry_run else _env_password(
        args.password_env, key_file=args.key_file)
    if problem:
        print(problem, file=sys.stderr)
        return 2

    print()
    _apply_summary(artifact, report)
    print()

    if args.remediate_dry_run:
        print("DRY RUN — nothing will be sent, and nothing will be asked.\n")
    elif args.remediate_yes:
        print("--remediate-yes: every confirmation is answered yes.\n")
    elif not sys.stdin.isatty():
        print("error: this would change a controller and there is no terminal to "
              "confirm on. Re-run with --remediate-dry-run to rehearse, or "
              "--remediate-yes if you have accepted the risk elsewhere.",
              file=sys.stderr)
        return 4
    elif not _confirm_apply(args.host, len(artifact.blocks), gate=gate):
        print("nothing was sent.")
        return 4

    config = SSHConfig(host=args.host, username=args.username, key_file=args.key_file,
                       password=password, port=args.port, device_type=args.device_type)

    # Progress goes to stderr and is unbuffered; the plan above went to stdout and
    # is not, when this is piped into a change record. Flushing here keeps the two
    # in the order they happened.
    sys.stdout.flush()

    prompting = not (args.remediate_yes or args.remediate_dry_run)
    options = ApplyOptions(
        operator=args.operator,
        confirm=_confirm_block if prompting else None,
        progress=lambda msg: print(f"  {msg}", file=sys.stderr),
    )
    try:
        session = ApplySession(config, artifact, dry_run=args.remediate_dry_run)
    except ApplyRefused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 4
    try:
        with session:
            for w in session.connect_warnings:
                print(f"warning: {w}", file=sys.stderr)
            result = apply_artifact(session, artifact, options=options)
    except TransportError as e:
        print(f"error: could not reach {args.host}: {e}", file=sys.stderr)
        return 1

    return _report_apply(artifact, result, args)


def _confirm_apply(host: str, count: int, *, gate: str = "typed") -> bool:
    """The last question before anything is sent.

    The typed form is not a y/n anyone can hit by reflex, which is what an export
    from somewhere else deserves. The [Y/n] form is for the operator who just
    walked the wizard and pressed the apply key: they have read every block on
    screen already, and asking them to spell a word to confirm what they just
    asked for twice is ceremony rather than safety.
    """
    print(f"This will send {count} change(s) to {host}.")
    print("Nothing is saved to flash, so a reboot undoes everything if it goes "
          "wrong — but you may need console access to get there.")
    try:
        if gate == "confirm":
            answer = input(f"Apply changes to {host}? [Y/n] ").strip().lower()
            return answer in ("", "y", "yes")
        return input("Type 'apply' to continue: ").strip() == "apply"
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _confirm_block(block, detail: str) -> bool:
    print(f"\n  {block.control_id} can cut off your own access.", file=sys.stderr)
    if detail:
        print(f"  {detail}", file=sys.stderr)
    for line in block.lines:
        print(f"    {line}", file=sys.stderr)
    try:
        return input("  Apply it? [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _report_apply(artifact, result, args) -> int:
    from .remediate.apply import (
        APPLIED, DRY_RUN, NOTHING_TO_DO, REFUSED, STAGED, next_steps)

    print()
    for block in result.blocks:
        mark = "ok    " if block.ok else "FAILED"
        state = block.confirmed.value if block.confirmed else "not checked"
        print(f"  {mark}  {block.control_id}  (control now: {state})")
        for note in block.notes:
            print(f"          {note}")
    for control_id, why in result.skipped:
        print(f"  skip    {control_id}  ({why})")

    # Warnings go to stderr and the block list above went to stdout, which is
    # block-buffered the moment either is redirected. Without this, a captured
    # run reads with every warning above the results it refers to.
    sys.stdout.flush()
    for w in result.warnings:
        print(f"warning: {w}", file=sys.stderr)
    for e in result.errors:
        print(f"error: {e}", file=sys.stderr)

    paths = write_result_safely(artifact, result, args)
    print(f"\noutcome: {result.outcome}")
    for path in paths:
        print(f"  {path}")
    for step in next_steps(result):
        print(f"  next: {step}")

    if result.outcome in (APPLIED, NOTHING_TO_DO, DRY_RUN):
        return 0
    if result.outcome == REFUSED:
        return 4
    if result.outcome == STAGED:
        # Not 0. Nothing failed, and nothing is in effect either — anything
        # reading the exit code to decide whether the controller is hardened
        # would get the wrong answer from a success.
        return 6
    return 5  # stopped part-way; a human has to look


def write_result_safely(artifact, result, args) -> list:
    """A crash while writing the record must not hide what already landed."""
    from .remediate.apply import write_result
    try:
        return write_result(artifact, result, operator=args.operator)
    except OSError as e:
        print(f"error: could not write the apply record: {e}", file=sys.stderr)
        return []


class _RedactToggle:
    """Wrap a Session so the collector can honor --no-redact uniformly."""

    def __init__(self, session, *, redact_output: bool):
        self._session = session
        self._redact = redact_output

    def run(self, command: str, *, timeout_s: int | None = None):
        return self._session.run(command, timeout_s=timeout_s, redact_output=self._redact)


def _print_collection_summary(result, *, as_json: bool) -> None:
    summary = collection_summary(result)
    if as_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return
    print(f"run {summary['run_id']}  host={summary['host']}  "
          f"model={summary['model']}  version={summary['aos_version']}  role={summary['role']}")
    print(f"commands: {summary['commands_total']}  exit_kinds={summary['exit_kind_counts']}  "
          f"redactions={summary['redactions_applied']}")
    if summary["commands_denied_to_role"]:
        print(f"  denied to read-only role: {summary['commands_denied_to_role']}")
    if summary["commands_unsupported"]:
        print(f"  unsupported on this train: {summary['commands_unsupported']}")
    for w in summary["warnings"]:
        print(f"  warning: {w}")


def _print_audit_summary(report) -> None:
    s = report.summary
    c = s.counts
    from .reporting.report import advisory_rollup, impact_rollup
    if report.results:  # an advisories-only run has no hardening posture to print
        print(f"\nAUDIT  profile={report.run_metadata.profile}  "
              f"score={s.posture_score}/100  worst_failed={s.worst_severity_failed.value if s.worst_severity_failed else 'none'}")
        print("  " + "  ".join(f"{k}={c.get(k, 0)}" for k in
                               ("fail", "warn", "pass", "manual", "not_applicable", "error")))
        if s.fips_gate:
            print(f"  FIPS gate: {'FAILED' if s.fips_gate_failed else 'passed'}")
        roll = impact_rollup(report.results)
        if roll["actionable"]:
            msg = f"  change impact (to fix {roll['actionable']} findings): " + \
                "  ".join(f"{k}={v}" for k, v in sorted(roll["by_level"].items()))
            if roll["reboot_required"]:
                msg += f"  | reboot/outage: {len(roll['reboot_required'])}"
            other_high = [c for c in roll["high_impact"] if c not in roll["reboot_required"]]
            if other_high:
                msg += f"  | high-disruption: {len(other_high)}"
            if roll["client_impact"]:
                msg += f"  | client-reauth: {len(roll['client_impact'])}"
            print(msg)
    st = report.scanner_triage
    if st and st.items:
        c = st.counts
        real = c.get("action_required", 0) + c.get("unknown", 0)
        print(f"\nSCANNER TRIAGE  {c.get('submitted', 0)} finding(s) submitted  "
              + "  ".join(f"{k}={c[k]}" for k in
                          ("action_required", "unknown", "accepted_risk", "by_design",
                           "false_positive") if k in c))
        if real:
            print(f"  {real} need(s) your attention (real, or not covered by the guide's table) "
                  "— see report.md")
    if report.advisory_results:
        a = advisory_rollup(report.advisory_results)
        print(f"\nADVISORY  {a['total_cves']} CVEs in scope  "
              f"(config-mitigable={a['config_mitigable']}  patch-only={a['patch_only']})")
        print(f"  exposed={a['exposed']}  mitigated={a['mitigated']}  needs-verify={a['needs_verify']}  "
              "(apply the listed workarounds to prevent exploitation — see report.md)")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
