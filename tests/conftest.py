from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from watchlog.models import EventType, SecurityEvent

BASE = datetime(2026, 8, 17, 10, 0, 0)


@pytest.fixture
def make_event():
    def _make(
        event_type: EventType = EventType.AUTH_FAILURE,
        ip: str | None = "192.168.1.50",
        user: str | None = "admin",
        at: float = 0,
        **kwargs,
    ) -> SecurityEvent:
        """`at` = segundos após BASE."""
        return SecurityEvent(
            timestamp=BASE + timedelta(seconds=at),
            hostname="server",
            source="sshd",
            event_type=event_type,
            source_ip=ip,
            username=user,
            **kwargs,
        )

    return _make
