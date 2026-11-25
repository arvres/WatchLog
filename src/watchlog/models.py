"""Modelos de domínio. Imutáveis e sem dependência de qualquer outra camada."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import Any


class EventType(enum.StrEnum):
    AUTH_FAILURE = "authentication_failure"
    AUTH_SUCCESS = "authentication_success"
    INVALID_USER = "invalid_user"


class Severity(enum.IntEnum):
    """Severidade de um *alerta* (eventos brutos não têm severidade: isso é decisão de detecção)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, text: str) -> Severity:
        try:
            return cls[text.strip().upper()]
        except KeyError:
            valid = ", ".join(s.label for s in cls)
            raise ValueError(f"severidade inválida: {text!r} (válidas: {valid})") from None


class AlertType(enum.StrEnum):
    SSH_BRUTE_FORCE = "ssh_brute_force"
    SSH_PASSWORD_SPRAY = "ssh_password_spray"
    SSH_LOGIN_AFTER_FAILURES = "ssh_login_after_failures"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    timestamp: datetime
    hostname: str
    source: str
    event_type: EventType
    source_ip: str | None = None
    username: str | None = None
    source_port: int | None = None
    auth_method: str | None = None
    invalid_user: bool = False

    @property
    def epoch(self) -> float:
        """Segundos desde a época; comparável mesmo se houver datetimes naive e aware."""
        return self.timestamp.timestamp()

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "hostname": self.hostname,
            "source": self.source,
            "event_type": self.event_type.value,
            "source_ip": self.source_ip,
            "username": self.username,
            "source_port": self.source_port,
            "auth_method": self.auth_method,
            "invalid_user": self.invalid_user,
        }


@dataclass(frozen=True, slots=True)
class Alert:
    type: AlertType
    severity: Severity
    message: str
    source_ip: str
    timestamp: datetime  # instante do evento que disparou o alerta
    event_count: int
    usernames: tuple[str, ...] = ()
    window_seconds: int | None = None
    rule: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "type": self.type.value,
            "severity": self.severity.label,
            "rule": self.rule,
            "message": self.message,
            "source_ip": self.source_ip,
            "event_count": self.event_count,
            "usernames": list(self.usernames),
            "window_seconds": self.window_seconds,
        }
