"""AOS versions are not plain semver; the comparator must handle real strings."""

import pytest

from aos8_auditor.model.version import parse_aos_version, version_in_range


def test_parse_basic():
    v = parse_aos_version("8.6.0.4")
    assert v is not None
    assert v.components == (8, 6, 0, 4)
    assert v.train == "8.6"
    assert v.base == "8.6.0.4"


def test_parse_from_show_version_line():
    v = parse_aos_version("ArubaOS (MODEL: Aruba7240), Version 8.6.0.4")
    assert v is not None
    assert v.base == "8.6.0.4"


def test_parse_with_build_suffix():
    v = parse_aos_version("8.10.0.7_87826")
    assert v is not None
    assert v.components == (8, 10, 0, 7)
    assert v.suffix == "87826"


def test_parse_with_dash_suffix():
    v = parse_aos_version("8.6.0.4-FIPS")
    assert v is not None
    assert v.components == (8, 6, 0, 4)
    assert v.suffix == "FIPS"


def test_numeric_compare_not_lexical():
    # 8.10 must be greater than 8.6 (10 > 6), not less (string '1' < '6').
    assert parse_aos_version("8.10.0.0") > parse_aos_version("8.6.0.0")
    assert parse_aos_version("8.6.0.10") > parse_aos_version("8.6.0.9")


def test_unparseable_returns_none():
    assert parse_aos_version("no version here") is None
    assert parse_aos_version("") is None


@pytest.mark.parametrize("ver,spec,expected", [
    ("8.6.0.4", ">=8.6.0.0,<8.6.0.10", True),
    ("8.6.0.4", "<8.6.0.4", False),
    ("8.6.0.4", "==8.6.0.4", True),
    ("8.10.0.0", ">=8.6.0.0", True),
    ("8.5.0.0", ">=8.6.0.0", False),
])
def test_version_in_range(ver, spec, expected):
    assert version_in_range(ver, spec) is expected


def test_version_in_range_unknown_version_is_none():
    # An unparseable version must never silently read as in/out of range.
    assert version_in_range("garbage", ">=8.6.0.0") is None


def test_bad_constraint_raises():
    with pytest.raises(ValueError):
        version_in_range("8.6.0.4", ">=not-a-version")


# --- Regression: must not grab an IP/uptime before the version (red-team) ---
def test_anchored_parse_skips_ip_before_version():
    text = "Switch IP Address is 10.20.30.40\nArubaOS (MODEL: Aruba7210), Version 8.6.0.4\nuptime 5 days"
    v = parse_aos_version(text)
    assert v is not None and v.base == "8.6.0.4"
    assert version_in_range(v, ">=8.6.0.0,<8.6.0.10") is True


def test_seven_components_not_truncated():
    v = parse_aos_version("1.2.3.4.5.6.7")
    assert v is not None and v.components == (1, 2, 3, 4, 5, 6, 7)
