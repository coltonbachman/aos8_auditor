"""Collector must persist a bundle that --from-evidence reloads byte-for-byte,
and must degrade to a partial result (never crash) on transport failure."""

from pathlib import Path

from aos8_auditor.collection.classify import classify_exit_kind
from aos8_auditor.collection.collector import Collector
from aos8_auditor.collection.command_catalog import CommandSpec
from aos8_auditor.collection.redaction import redact
from aos8_auditor.model.evidence import CommandResult, ExitKind


class FakeRunner:
    """Mimics Session.run (safelist + redact + classify) without a device."""

    def __init__(self, outputs: dict[str, str], fail_on: str | None = None):
        self.outputs = outputs
        self.fail_on = fail_on
        self.calls: list[str] = []

    def run(self, command: str, *, timeout_s=None) -> CommandResult:
        self.calls.append(command)
        if self.fail_on and command == self.fail_on:
            raise RuntimeError("simulated transport failure")
        raw = self.outputs.get(command, "")
        rr = redact(raw)
        kind, sig = classify_exit_kind(raw, echoed_command=command)
        r = CommandResult(
            command=command,
            redacted_output=rr.text,
            exit_kind=kind,
            error_signature=sig,
            redaction_count=rr.count,
            redaction_kinds=rr.kinds,
            started_at="2026-05-29T00:00:00+00:00",
            duration_ms=1,
        )
        r.sha256 = r.compute_sha256()
        return r


VERSION_OUT = "ArubaOS (MODEL: Aruba7240), Version 8.6.0.4"
OUTPUTS = {
    "show version": VERSION_OUT,
    "show fips": "FIPS Settings:\n--------------\nMode    Enabled\n",
    "show running-config": "version 8.6.0.4\nhostname \"JITC7240\"\nkey SuperSecretRadiusKey\n",
}


def test_collect_parses_identity():
    c = Collector(FakeRunner(OUTPUTS), run_id="testrun-1")
    result = c.collect(host="10.0.0.9")
    assert result.controller.host == "10.0.0.9"
    assert result.controller.model == "7240"
    assert result.controller.aos_version == "8.6.0.4"
    assert result.controller.platform_family == "7200"


def test_collected_running_config_is_redacted():
    c = Collector(FakeRunner(OUTPUTS), run_id="testrun-2")
    result = c.collect(host="10.0.0.9")
    rc = result.by_command("show running-config")
    assert rc is not None
    assert "SuperSecretRadiusKey" not in rc.redacted_output
    assert rc.redaction_count >= 1


def test_write_bundle_and_replay_roundtrip(tmp_path: Path):
    c = Collector(FakeRunner(OUTPUTS), out_root=tmp_path, run_id="testrun-3")
    result = c.collect(host="10.0.0.9")
    run_dir = c.write_bundle(result)

    assert (run_dir / "collection_result.json").exists()
    assert (run_dir / "manifest.json").exists()
    assert (run_dir / "raw" / "show-version.txt").exists()

    reloaded = Collector.from_evidence(run_dir)
    assert reloaded.model_dump(mode="json") == result.model_dump(mode="json")


def test_partial_collection_on_transport_failure():
    specs = [
        CommandSpec("show_version", "show version"),
        CommandSpec("running_config", "show running-config"),
        CommandSpec("show_fips", "show fips"),
    ]
    runner = FakeRunner(OUTPUTS, fail_on="show running-config")
    c = Collector(runner, run_id="testrun-4")
    result = c.collect(specs=specs, host="10.0.0.9")

    # First command succeeded; the failing one and everything after are SKIPPED.
    assert result.by_command("show version").exit_kind == ExitKind.OK
    assert result.by_command("show running-config").exit_kind == ExitKind.SKIPPED
    assert result.by_command("show fips").exit_kind == ExitKind.SKIPPED
    assert any("transport failed" in w for w in result.collection_warnings)
    # The runner was never asked to run 'show fips' after the failure.
    assert "show fips" not in runner.calls


def test_denied_primary_falls_back_to_alternate():
    # A primary command DENIED to the read-only role must try its alternate
    # (regression: fallback previously only fired on UNSUPPORTED).
    outputs = {
        "show banner": "You do not have permission to run this command",
        "show banner-fallback": "banner motd is configured",
    }
    runner = FakeRunner(outputs)
    specs = [CommandSpec("banner", "show banner", alternates=("show banner-fallback",))]
    c = Collector(runner, run_id="testrun-5")
    result = c.collect(specs=specs, host="10.0.0.9")

    assert result.by_command("show banner").exit_kind == ExitKind.DENIED
    assert "show banner-fallback" in runner.calls
    assert result.by_command("show banner-fallback").exit_kind == ExitKind.OK
