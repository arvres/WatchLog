from __future__ import annotations

import logging
from collections.abc import Iterable

from watchlog.alerting.sinks import AlertSink
from watchlog.models import Alert, Severity

log = logging.getLogger(__name__)


class AlertManager:
    """Filtra por severidade mínima e entrega aos sinks; a falha de um não afeta os outros."""

    def __init__(self, sinks: Iterable[AlertSink], min_severity: Severity = Severity.INFO) -> None:
        self._sinks = list(sinks)
        self._min_severity = min_severity

    def handle(self, alert: Alert) -> bool:
        if alert.severity < self._min_severity:
            return False
        for sink in self._sinks:
            try:
                sink.emit(alert)
            except Exception:  # um sink com defeito não pode derrubar o pipeline
                log.exception("falha ao enviar alerta para %s", type(sink).__name__)
        return True
