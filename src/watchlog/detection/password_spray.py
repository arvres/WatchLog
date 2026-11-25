from __future__ import annotations

from watchlog.detection.base import DetectionRule, cap_usernames, validate_params
from watchlog.detection.state import Cooldown, KeyedWindows
from watchlog.models import Alert, AlertType, EventType, SecurityEvent, Severity

_RELEVANT = {EventType.AUTH_FAILURE, EventType.INVALID_USER}


class PasswordSprayRule(DetectionRule):
    """
    `threshold` usuários **distintos** atacados pelo mesmo IP dentro de `window_seconds`.

    O sshd registra tanto "Invalid user X" quanto "Failed password for invalid user X" para a
    mesma tentativa; como contamos usuários *distintos*, não há contagem dupla.
    """

    name = "password_spray"

    def __init__(
        self, threshold: int = 5, window_seconds: int = 300, cooldown_seconds: int | None = None
    ) -> None:
        validate_params(threshold, window_seconds)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._windows = KeyedWindows(window_seconds)
        self._cooldown = Cooldown(window_seconds if cooldown_seconds is None else cooldown_seconds)

    def evaluate(self, event: SecurityEvent) -> list[Alert]:
        if event.event_type not in _RELEVANT or not event.source_ip or not event.username:
            return []

        ip = event.source_ip
        window = self._windows.add(ip, event.epoch, event.username)
        distinct = window.distinct
        if distinct < self.threshold or not self._cooldown.try_acquire(ip, event.epoch):
            return []

        return [
            Alert(
                type=AlertType.SSH_PASSWORD_SPRAY,
                severity=Severity.HIGH,
                message=(
                    f"{distinct} usuários distintos atacados a partir de {ip} "
                    f"em até {self.window_seconds}s"
                ),
                source_ip=ip,
                timestamp=event.timestamp,
                event_count=distinct,
                usernames=cap_usernames(window.values()),
                window_seconds=self.window_seconds,
                rule=self.name,
            )
        ]
