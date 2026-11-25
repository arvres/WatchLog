from __future__ import annotations

from abc import ABC, abstractmethod

from watchlog.models import SecurityEvent


class LogParser(ABC):
    """Converte uma linha de log em um evento normalizado (ou None se não for relevante)."""

    @abstractmethod
    def parse(self, line: str) -> SecurityEvent | None: ...
