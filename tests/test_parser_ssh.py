from datetime import datetime

import pytest

from watchlog.models import EventType
from watchlog.parsers import SSHParser

NOW = datetime(2026, 8, 20, 12, 0, 0)


@pytest.fixture
def parser():
    return SSHParser(now=lambda: NOW)


def test_failed_password(parser):
    e = parser.parse(
        "Aug 17 10:31:01 server sshd[1234]: Failed password for admin from 192.168.1.50 port 42131 ssh2"
    )
    assert e.event_type is EventType.AUTH_FAILURE
    assert (e.username, e.source_ip, e.source_port) == ("admin", "192.168.1.50", 42131)
    assert (e.hostname, e.source, e.auth_method) == ("server", "sshd", "password")
    assert e.timestamp == datetime(2026, 8, 17, 10, 31, 1)
    assert e.invalid_user is False


def test_failed_password_invalid_user_keeps_real_username(parser):
    e = parser.parse(
        "Aug 17 10:31:01 server sshd[1]: Failed password for invalid user oracle from 10.0.0.1 port 22 ssh2"
    )
    assert e.username == "oracle"  # o original engolia o "invalid user" e perdia a informação
    assert e.invalid_user is True


def test_failed_publickey_is_also_a_failure(parser):
    e = parser.parse(
        "Aug 17 10:31:01 s sshd[1]: Failed publickey for root from 10.0.0.1 port 22 ssh2"
    )
    assert e.event_type is EventType.AUTH_FAILURE and e.auth_method == "publickey"


def test_invalid_user_line(parser):
    e = parser.parse("Aug 17 10:31:01 s sshd[1]: Invalid user test from 10.0.0.1 port 5555")
    assert e.event_type is EventType.INVALID_USER
    assert (e.username, e.source_ip, e.source_port) == ("test", "10.0.0.1", 5555)


def test_invalid_user_line_without_port(parser):
    e = parser.parse("Aug 17 10:31:01 s sshd[1]: Invalid user test from 10.0.0.1")
    assert e.source_port is None


@pytest.mark.parametrize("method", ["password", "publickey", "keyboard-interactive/pam"])
def test_accepted(parser, method):
    e = parser.parse(
        f"Aug 17 10:31:12 s sshd[1]: Accepted {method} for admin from 10.0.0.1 port 42142 ssh2"
    )
    assert e.event_type is EventType.AUTH_SUCCESS and e.auth_method == method


def test_sshd_session_process_name_openssh_98(parser):
    e = parser.parse(
        "Aug 17 10:31:01 s sshd-session[99]: Failed password for root from 10.0.0.1 port 22 ssh2"
    )
    assert e is not None and e.source == "sshd-session"


def test_pid_is_optional(parser):
    assert parser.parse(
        "Aug 17 10:31:01 s sshd: Failed password for root from 10.0.0.1 port 22 ssh2"
    )


def test_ipv6_address(parser):
    e = parser.parse(
        "Aug 17 10:31:01 s sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2"
    )
    assert e.source_ip == "2001:db8::1"


def test_iso8601_timestamp(parser):
    e = parser.parse(
        "2026-08-17T10:31:01.123456-03:00 host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2"
    )
    assert e.timestamp.year == 2026 and e.timestamp.tzinfo is not None
    assert e.hostname == "host"


def test_single_digit_day_with_double_space(parser):
    e = parser.parse(
        "Aug  7 10:31:01 s sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2"
    )
    assert e.timestamp.day == 7


def test_year_rolls_back_when_date_is_in_the_future():
    p = SSHParser(now=lambda: datetime(2026, 1, 2))
    e = p.parse("Dec 31 23:59:59 s sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2")
    assert e.timestamp.year == 2025


def test_explicit_year_wins():
    p = SSHParser(year=2020)
    e = p.parse("Aug 17 10:31:01 s sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2")
    assert e.timestamp.year == 2020


def test_feb_29_invalid_year_is_skipped():
    p = SSHParser(year=2025)
    assert (
        p.parse("Feb 29 10:00:00 s sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2")
        is None
    )


@pytest.mark.parametrize(
    "line",
    [
        "",
        "garbage",
        "Aug 17 10:31:01 s sshd[1]: Connection closed by 10.0.0.1 port 22",
        "Aug 17 10:31:01 s CRON[1]: Failed password for root from 10.0.0.1 port 22",  # outro processo
        "Aug 17 10:31:01 s sshd[1]: Failed password for root",  # truncada
        "Foo 17 10:31:01 s sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",  # mês inválido
        "2026-99-99T99:99:99 s sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
    ],
)
def test_irrelevant_or_malformed_lines_return_none(parser, line):
    assert parser.parse(line) is None
