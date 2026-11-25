from __future__ import annotations

from collections.abc import Iterable

from watchlog.detection.base import DetectionRule
from watchlog.models import Alert, SecurityEvent


class DetectionEngine:
    def __init__(self, rules: Iterable[DetectionRule] = ()) -> None:
        self._rules: list[DetectionRule] = list(rules)

    def add_rule(self, rule: DetectionRule) -> None:
        self._rules.append(rule)

    @property
    def rules(self) -> tuple[DetectionRule, ...]:
        return tuple(self._rules)

    def process(self, event: SecurityEvent) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self._rules:
            alerts.extend(rule.evaluate(event))
        return alerts
