"""Risk-matrix rules engine: loads alert_policies.yaml and evaluates alerts against it."""
import logging
from dataclasses import dataclass

import yaml

from app.schemas import Severity, severity_at_least

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Rule:
    match_substring: str
    min_severity: Severity
    action: str
    ttl_seconds: int

    def matches(self, alert_name: str, severity: Severity) -> bool:
        return (
            self.match_substring.lower() in alert_name.lower()
            and severity_at_least(severity, self.min_severity)
        )


@dataclass(frozen=True)
class Decision:
    action: str
    ttl_seconds: int
    matched_rule: str


NO_ACTION = Decision(action="NONE", ttl_seconds=0, matched_rule="-")


class RulesEngine:
    """Loads policy rules from YAML and evaluates them in declaration order (first match wins)."""

    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules

    @classmethod
    def from_yaml_file(cls, path: str) -> "RulesEngine":
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

        rules: list[Rule] = []
        for entry in raw.get("rules", []):
            rules.append(
                Rule(
                    match_substring=str(entry["match"]),
                    min_severity=Severity(entry["min_severity"]),
                    action=str(entry["action"]),
                    ttl_seconds=int(entry["ttl_seconds"]),
                )
            )
        logger.info(
            "loaded rules engine policies",
            extra={"component": "engine.rules", "action": "load", "status": "success", "target_ip": "-"},
        )
        return cls(rules)

    def evaluate(self, alert_name: str, severity: Severity) -> Decision:
        for rule in self._rules:
            if rule.matches(alert_name, severity):
                return Decision(action=rule.action, ttl_seconds=rule.ttl_seconds, matched_rule=rule.match_substring)
        return NO_ACTION
