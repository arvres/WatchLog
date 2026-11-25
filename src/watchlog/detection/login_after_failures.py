from __future__ import annotations

from watchlog.detection.base import DetectionRule, validate_params
from watchlog.detection.state import KeyedWindows
from watchlog.models import Alert, AlertType, EventType, SecurityEvent, Severity


class LoginAfterFailuresRule(DetectionRule):
    """
    Login **bem-sucedido** de um IP que acabou de acumular `threshold` falhas na janela.
    É o sinal mais importante do conjunto: indica que o ataque provavelmente funcionou.
    (O original não tinha essa regra, apesar de o auth.log de exemplo terminar exatamente assim.)
    """

    name = "login_after_failures"

    def __init__(
        self, threshold: int = 5, window_seconds: int = 300, _cooldown_seconds: int | None = None
    ) -> None:
        validate_params(threshold, window_seconds)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._failures = KeyedWindows(window_seconds)
        # _cooldown_seconds aceito por uniformidade com outras regras, mas não usado:
        # histórico de falhas é descartado ao alertar, evitando duplicatas.

    def evaluate(self, event: SecurityEvent) -> list[Alert]:
        ip = event.source_ip
        if not ip:
            return []

        if event.event_type is EventType.AUTH_FAILURE:
            self._failures.add(ip, event.epoch, event.username or "<desconhecido>")
            return []
        if event.event_type is not EventType.AUTH_SUCCESS:
            return []

        window = self._failures.get(ip, event.epoch)
        if window is None or len(window) < self.threshold:
            return []

        failures = len(window)
        self._failures.discard(ip)
        user = event.username or "<desconhecido>"
        return [
            Alert(
                type=AlertType.SSH_LOGIN_AFTER_FAILURES,
                severity=Severity.CRITICAL,
                message=(
                    f"login bem-sucedido de '{user}' a partir de {ip} após {failures} "
                    f"falhas em até {self.window_seconds}s — possível comprometimento"
                ),
                source_ip=ip,
                timestamp=event.timestamp,
                event_count=failures,
                usernames=(user,),
                window_seconds=self.window_seconds,
                rule=self.name,
            )
        ]
