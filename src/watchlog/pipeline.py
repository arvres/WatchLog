"""Orquestra parser -> engine -> alertas, independente de CLI e de origem das linhas."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass

from watchlog.alerting.manager import AlertManager
from watchlog.detection.engine import DetectionEngine
from watchlog.models import Alert
from watchlog.parsers.base import LogParser

log = logging.getLogger(__name__)


@dataclass(slots=True)
class PipelineStats:
    lines_read: int = 0
    events_parsed: int = 0
    alerts_raised: int = 0


class Pipeline:
    def __init__(self, parser: LogParser, engine: DetectionEngine, alerts: AlertManager) -> None:
        self._parser = parser
        self._engine = engine
        self._alerts = alerts
        self.stats = PipelineStats()

    def process_line(self, line: str) -> list[Alert]:
        self.stats.lines_read += 1
        if not line.strip() or line.lstrip().startswith("#"):
            return []

        event = self._parser.parse(line)
        if event is None:
            return []
        self.stats.events_parsed += 1
        log.debug("evento: %s", event)

        alerts = self._engine.process(event)
        for alert in alerts:
            self.stats.alerts_raised += 1
            self._alerts.handle(alert)
        return alerts

    def run(self, lines: Iterable[str]) -> PipelineStats:
        for line in lines:
            self.process_line(line)
        return self.stats
