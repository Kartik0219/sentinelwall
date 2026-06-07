"""Unit tests for the YAML-driven risk-matrix rules engine."""
from app.engine.rules import RulesEngine
from app.schemas import Severity


def test_brute_force_high_severity_triggers_block():
    engine = RulesEngine.from_yaml_file("alert_policies.yaml")
    decision = engine.evaluate("Brute Force Attack Detected", Severity.HIGH)
    assert decision.action == "BLOCK_IP"
    assert decision.ttl_seconds == 3600


def test_malicious_ip_communication_low_severity_still_blocks():
    engine = RulesEngine.from_yaml_file("alert_policies.yaml")
    decision = engine.evaluate("Malicious IP Communication observed", Severity.LOW)
    assert decision.action == "BLOCK_IP"
    assert decision.ttl_seconds == 86400


def test_unmatched_alert_yields_no_action():
    engine = RulesEngine.from_yaml_file("alert_policies.yaml")
    decision = engine.evaluate("Resource tagging policy violation", Severity.HIGH)
    assert decision.action == "NONE"


def test_match_is_case_insensitive():
    engine = RulesEngine.from_yaml_file("alert_policies.yaml")
    decision = engine.evaluate("brute FORCE login spree", Severity.HIGH)
    assert decision.action == "BLOCK_IP"
