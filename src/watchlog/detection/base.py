from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from watchlog.models import Alert, SecurityEvent

MAX_USERNAMES_IN_ALERT = 20


class DetectionRule(ABC):
    """Regra com estado: recebe eventos em ordem cronológica e devolve zero ou mais alertas."""

    name: ClassVar[str]

    @abstractmethod
    def evaluate(self, event: SecurityEvent) -> list[Alert]: ...


def validate_params(threshold: int, window_seconds: int) -> None:
    if threshold < 1:
        raise ValueError("threshold deve ser >= 1")
    if window_seconds < 1:
        raise ValueError("window_seconds deve ser >= 1")


def cap_usernames(usernames: set[str]) -> tuple[str, ...]:
    """Lista ordenada e limitada, para um spray gigante não gerar um alerta gigante."""
    return tuple(sorted(usernames)[:MAX_USERNAMES_IN_ALERT])
