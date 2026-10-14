"""Topology/identity parsing must prefer the AOS line, handle legacy versions,
and never guess STANDALONE without positive evidence (red-team regressions)."""

from aos8_auditor.model.evidence import NodeRole
from aos8_auditor.transport.topology import detect_role, parse_show_version, platform_family


def test_rom_bootstrap_line_not_picked_as_aos_version():
    text = "ROM: System Bootstrap, Version 1.0.0.0\nArubaOS (MODEL: Aruba7210), Version 8.6.0.4"
    assert parse_show_version(text)["aos_version"] == "8.6.0.4"


def test_legacy_three_component_version_parsed():
    assert parse_show_version("ArubaOS (MODEL: Aruba7005), Version 6.5.4")["aos_version"] == "6.5.4"


def test_model_leading_hyphen_stripped():
    assert parse_show_version("MODEL: Aruba-7210")["model"] == "7210"
    assert parse_show_version("ArubaOS (MODEL: Aruba7240), Version 8.6.0.4")["model"] == "7240"


def test_platform_family():
    assert platform_family("7240") == "7200"
    assert platform_family("7005") == "7000"


def test_role_unknown_without_evidence():
    # No role evidence (incl. denied/empty source) -> UNKNOWN, never STANDALONE.
    assert detect_role("", "") == NodeRole.UNKNOWN
    assert detect_role("ArubaOS (MODEL: Aruba7240), Version 8.6.0.4", "") == NodeRole.UNKNOWN


def test_role_mm_marker_detected():
    assert detect_role("This is a Mobility Master", "") == NodeRole.MM


def test_role_explicit_switch_role():
    assert detect_role("Switch Role: master", "") == NodeRole.MASTER
    assert detect_role("switch role = standalone", "") == NodeRole.STANDALONE
