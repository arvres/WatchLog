"""Parser de mensagens do sshd (auth.log / secure / journald exportado como texto)."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime, timedelta

from watchlog.models import EventType, SecurityEvent
from watchlog.parsers.base import LogParser

# Cabeçalho: "<timestamp> <host> sshd[pid]: <mensagem>".
#  - timestamp clássico do syslog ("Aug 17 10:31:01", SEM ano) ou ISO-8601 (rsyslog moderno);
#  - processo "sshd" ou "sshd-session" (OpenSSH >= 9.8 separou o processo de sessão);
#  - pid é opcional.
_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)"
    r"\s+(?P<host>\S+)"
    r"\s+(?P<proc>sshd(?:-session)?)(?:\[\d+\])?:"
    r"\s+(?P<msg>.*)$"
)
_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2})$")

_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.+?)"
    r" from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>.+?) from (?P<ip>\S+) port (?P<port>\d+)"
)
_INVALID_USER = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?")

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}


class SSHParser(LogParser):
    def __init__(
        self,
        *,
        year: int | None = None,
        now: Callable[[], datetime] = datetime.now,
    ) -> None:
        """
        O formato syslog clássico não traz o ano. Estratégia:
          * `year` explícito, se informado; senão
          * ano de `now()`, recuando um ano se a data resultante ficar no futuro
            (ex.: lendo em janeiro um log com linhas de dezembro).
        `now` deve devolver um datetime *naive* (injetável para testes).
        """
        self._year = year
        self._now = now

    def parse(self, line: str) -> SecurityEvent | None:
        header = _HEADER.match(line.strip())
        if header is None:
            return None

        message = header["msg"]
        if message.startswith("Failed "):
            return self._build(header, _FAILED.match(message), EventType.AUTH_FAILURE)
        if message.startswith("Accepted "):
            return self._build(header, _ACCEPTED.match(message), EventType.AUTH_SUCCESS)
        if message.startswith("Invalid user "):
            return self._build(header, _INVALID_USER.match(message), EventType.INVALID_USER)
        return None

    # ------------------------------------------------------------------ internals
    def _build(
        self, header: re.Match[str], match: re.Match[str] | None, event_type: EventType
    ) -> SecurityEvent | None:
        if match is None:
            return None
        timestamp = self._parse_timestamp(header["ts"])
        if timestamp is None:
            return None

        groups = match.groupdict()
        port = groups.get("port")
        return SecurityEvent(
            timestamp=timestamp,
            hostname=header["host"],
            source=header["proc"],
            event_type=event_type,
            source_ip=groups["ip"],
            username=groups["user"],
            source_port=int(port) if port else None,
            auth_method=groups.get("method"),
            invalid_user=event_type is EventType.INVALID_USER or bool(groups.get("invalid")),
        )

    def _parse_timestamp(self, text: str) -> datetime | None:
        if text[0].isdigit():
            try:
                return datetime.fromisoformat(text)
            except ValueError:
                return None

        m = _SYSLOG_TS.match(" ".join(text.split()))
        if m is None or m[1] not in _MONTHS:
            return None
        month = _MONTHS[m[1]]
        day, hour, minute, second = (int(g) for g in m.groups()[1:])
        try:
            if self._year is not None:
                return datetime(self._year, month, day, hour, minute, second)
            ref = self._now()
            candidate = datetime(ref.year, month, day, hour, minute, second)
            if candidate > ref + timedelta(days=1):
                candidate = datetime(ref.year - 1, month, day, hour, minute, second)
            return candidate
        except ValueError:  # ex.: 29 de fevereiro em ano não bissexto
            return None
