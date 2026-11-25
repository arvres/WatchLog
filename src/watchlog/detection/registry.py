"""Registro de regras: para criar uma regra nova basta implementá-la e registrar aqui."""

from __future__ import annotations

from collections.abc import Callable

from watchlog.config import Config, RuleSettings
from watchlog.detection.base import DetectionRule
from watchlog.detection.brute_force import BruteForceRule
from watchlog.detection.engine import DetectionEngine
from watchlog.detection.login_after_failures import LoginAfterFailuresRule
from watchlog.detection.password_spray import PasswordSprayRule

RuleFactory = Callable[[RuleSettings], DetectionRule]


def _factory(cls: type[DetectionRule]) -> RuleFactory:
    if cls is LoginAfterFailuresRule:
        return lambda s: cls(
            threshold=s.threshold,
            window_seconds=s.window_seconds,
        )
    return lambda s: cls(  # type: ignore[call-arg]
        threshold=s.threshold,
        window_seconds=s.window_seconds,
        cooldown_seconds=s.cooldown_seconds,
    )


RULE_FACTORIES: dict[str, RuleFactory] = {
    cls.name: _factory(cls) for cls in (BruteForceRule, PasswordSprayRule, LoginAfterFailuresRule)
}


def create_engine(config: Config | None = None) -> DetectionEngine:
    config = config or Config()
    engine = DetectionEngine()
    for name, settings in config.rules.items():
        if settings.enabled:
            engine.add_rule(RULE_FACTORIES[name](settings))
    return engine
