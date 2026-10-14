"""The closed predicate DSL: text and fact predicates."""

import pytest

from aos8_auditor.engine.predicates import Ctx, PredicateError, evaluate

TEXT = "fips enable\nno spanning-tree\nloginsession timeout 5\nsnmp-server community public\n"
FACTS = {
    "fips_enabled": True,
    "snmp_v1v2c_present": True,
    "ntp_server_count": 0,
    "syslog_server_count": 2,
    "lcd_menu_disabled": None,
    "aps_in_default": 1,
}


def _ctx():
    return Ctx(source_text=lambda name: TEXT, facts=FACTS)


def test_regex_and_absent():
    ok, m = evaluate({"source": "running_config", "predicate": "regex", "arg": r"fips\s+enable"}, _ctx())
    assert ok and m
    ok2, _ = evaluate({"source": "running_config", "predicate": "regex_absent", "arg": r"telnet"}, _ctx())
    assert ok2


def test_no_form_present():
    ok, m = evaluate({"source": "running_config", "predicate": "no_form_present", "arg": "spanning-tree"}, _ctx())
    assert ok and "no spanning-tree" in m[0]
    # mere absence is not a 'no' form
    ok2, _ = evaluate({"source": "running_config", "predicate": "no_form_present", "arg": "mgmt-user localauth"}, _ctx())
    assert not ok2


def test_fact_true_false_unknown():
    assert evaluate({"source": "fact", "predicate": "fact_true", "arg": "fips_enabled"}, _ctx())[0] is True
    assert evaluate({"source": "fact", "predicate": "fact_false", "arg": "fips_enabled"}, _ctx())[0] is False
    # unknown (None) is distinct from true/false
    assert evaluate({"source": "fact", "predicate": "fact_unknown", "arg": "lcd_menu_disabled"}, _ctx())[0] is True
    assert evaluate({"source": "fact", "predicate": "fact_true", "arg": "lcd_menu_disabled"}, _ctx())[0] is False


def test_fact_equals_gte_lte():
    assert evaluate({"source": "fact", "predicate": "fact_equals", "arg": {"path": "ntp_server_count", "value": 0}}, _ctx())[0]
    assert evaluate({"source": "fact", "predicate": "fact_gte", "arg": {"path": "syslog_server_count", "value": 1}}, _ctx())[0]
    assert not evaluate({"source": "fact", "predicate": "fact_gte", "arg": {"path": "ntp_server_count", "value": 1}}, _ctx())[0]


def test_unknown_predicate_raises():
    with pytest.raises(PredicateError):
        evaluate({"source": "fact", "predicate": "nope", "arg": "x"}, _ctx())
