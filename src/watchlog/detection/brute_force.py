from __future__ import annotations

from watchlog.detection.base import DetectionRule, cap_usernames, validate_params
from watchlog.detection.state import Cooldown, KeyedWindows
from watchlog.models import Alert, AlertType, EventType, SecurityEvent, Severity


class BruteForceRule(DetectionRule):
    """
    `threshold` falhas de autenticação **contra o mesmo usuário**, vindas do **mesmo IP**,
    dentro de `window_seconds`. (Muitos usuários diferentes = password spray, outra regra.)
    """

    name = "brute_force"

    def __init__(
        self, threshold: int = 5, window_seconds: int = 300, cooldown_seconds: int | None = None
    ) -> None:
        validate_params(threshold, window_seconds)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._windows = KeyedWindows(window_seconds)
        self._cooldown = Cooldown(window_seconds if cooldown_seconds is None else cooldown_seconds)

    def evaluate(self, event: SecurityEvent) -> list[Alert]:
        if event.event_type is not EventType.AUTH_FAILURE or not event.source_ip:
            return []

        ip = event.source_ip
        user = event.username or "<desconhecido>"
        key = (ip, user)

        window = self._windows.add(key, event.epoch, user)
        count = len(window)
        if count < self.threshold or not self._cooldown.try_acquire(key, event.epoch):
            return []

        return [
            Alert(
                type=AlertType.SSH_BRUTE_FORCE,
                severity=Severity.HIGH,
                message=(
                    f"{count} falhas de login SSH para o usuário '{user}' "
                    f"a partir de {ip} em até {self.window_seconds}s"
                ),
                source_ip=ip,
                timestamp=event.timestamp,
                event_count=count,
                usernames=cap_usernames({user}),
                window_seconds=self.window_seconds,
                rule=self.name,
            )
        ]
