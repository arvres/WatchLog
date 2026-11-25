"""Destinos de alerta. Acrescentar e-mail/webhook/syslog = implementar `emit`."""

from __future__ import annotations

import json
from typing import Protocol, TextIO

from watchlog.models import Alert


class AlertSink(Protocol):
    def emit(self, alert: Alert) -> None: ...


def format_alert_text(alert: Alert) -> str:
    users = f" users={','.join(alert.usernames)}" if alert.usernames else ""
    return (
        f"{alert.timestamp.isoformat()} [{alert.severity.name}] {alert.type.value} "
        f"ip={alert.source_ip} count={alert.event_count}{users} :: {alert.message}"
    )


class TextSink:
    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def emit(self, alert: Alert) -> None:
        self._stream.write(format_alert_text(alert) + "\n")
        self._stream.flush()  # essencial no modo --follow


class JsonLinesSink:
    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def emit(self, alert: Alert) -> None:
        self._stream.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")
        self._stream.flush()
