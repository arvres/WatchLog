from watchlog.detection import PasswordSprayRule
from watchlog.models import AlertType, EventType, Severity

USERS = ["admin", "root", "guest", "test", "user"]


def feed(rule, make_event, users, start=0, **kw):
    alerts = []
    for i, u in enumerate(users):
        alerts += rule.evaluate(make_event(at=start + i, user=u, **kw))
    return alerts


def test_no_alert_before_threshold(make_event):
    assert feed(PasswordSprayRule(5), make_event, USERS[:4]) == []


def test_alert_when_enough_distinct_users(make_event):
    (alert,) = feed(PasswordSprayRule(5), make_event, USERS)
    assert alert.type is AlertType.SSH_PASSWORD_SPRAY
    assert alert.severity is Severity.HIGH
    assert alert.event_count == 5
    assert alert.usernames == tuple(sorted(USERS))  # o original só guardava o ÚLTIMO usuário


def test_repeated_username_does_not_increase_count(make_event):
    assert feed(PasswordSprayRule(5), make_event, ["admin", "admin", "admin", "root"]) == []


def test_users_outside_window_do_not_accumulate(make_event):
    rule = PasswordSprayRule(5, window_seconds=60)
    alerts = []
    for i, u in enumerate(USERS):
        alerts += rule.evaluate(make_event(at=i * 1000, user=u))
    assert alerts == []


def test_invalid_user_events_count_but_dedupe_with_failed_password(make_event):
    rule = PasswordSprayRule(2)
    # sshd loga as duas linhas para a mesma tentativa: deve contar 1 usuário, não 2.
    assert rule.evaluate(make_event(EventType.INVALID_USER, user="x", at=0)) == []
    assert rule.evaluate(make_event(EventType.AUTH_FAILURE, user="x", at=1)) == []
    assert len(rule.evaluate(make_event(EventType.INVALID_USER, user="y", at=2))) == 1


def test_no_duplicate_alert_during_cooldown(make_event):
    rule = PasswordSprayRule(3)
    assert len(feed(rule, make_event, [f"u{i}" for i in range(30)])) == 1


def test_username_list_is_capped(make_event):
    big = PasswordSprayRule(1, cooldown_seconds=0)
    alerts = feed(big, make_event, [f"u{i:03d}" for i in range(100)])
    assert max(len(a.usernames) for a in alerts) == 20


def test_ignores_success_missing_ip_or_username(make_event):
    rule = PasswordSprayRule(1)
    assert rule.evaluate(make_event(EventType.AUTH_SUCCESS)) == []
    assert rule.evaluate(make_event(ip=None)) == []
    assert rule.evaluate(make_event(user=None)) == []
