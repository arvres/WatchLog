import pytest

from watchlog.detection import BruteForceRule
from watchlog.models import AlertType, EventType, Severity


def feed(rule, make_event, times, **kw):
    alerts = []
    for t in times:
        alerts += rule.evaluate(make_event(at=t, **kw))
    return alerts


def test_no_alert_before_threshold(make_event):
    assert feed(BruteForceRule(5), make_event, range(4)) == []


def test_alert_at_threshold(make_event):
    (alert,) = feed(BruteForceRule(5), make_event, range(5))
    assert alert.type is AlertType.SSH_BRUTE_FORCE
    assert alert.severity is Severity.HIGH
    assert alert.source_ip == "192.168.1.50"
    assert alert.usernames == ("admin",)
    assert alert.event_count == 5
    assert alert.rule == "brute_force"


def test_no_duplicate_alerts_during_cooldown(make_event):
    assert len(feed(BruteForceRule(5, 300), make_event, range(50))) == 1


def test_alerts_again_after_cooldown_expires(make_event):
    # Ataque contínuo: um alerta por janela, em vez de ficar mudo para sempre.
    alerts = feed(BruteForceRule(5, 60), make_event, range(0, 200))
    assert len(alerts) >= 3


def test_slow_failures_outside_window_do_not_accumulate(make_event):
    # Regressão do bug central do original: contador que nunca expira.
    assert feed(BruteForceRule(5, 300), make_event, [0, 1000, 2000, 3000, 4000, 5000]) == []


def test_different_users_from_same_ip_are_not_brute_force(make_event):
    rule = BruteForceRule(5)
    alerts = []
    for i, user in enumerate(["a", "b", "c", "d", "e", "f"]):
        alerts += rule.evaluate(make_event(at=i, user=user))
    assert alerts == []


def test_same_user_from_different_ips_are_not_aggregated(make_event):
    rule = BruteForceRule(3)
    alerts = []
    for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
        alerts += rule.evaluate(make_event(at=i, ip=ip))
    assert alerts == []


def test_ignores_success_and_missing_ip(make_event):
    rule = BruteForceRule(1)
    assert rule.evaluate(make_event(EventType.AUTH_SUCCESS)) == []
    assert rule.evaluate(make_event(ip=None)) == []
    assert rule.evaluate(make_event(EventType.INVALID_USER)) == []


@pytest.mark.parametrize("threshold,window", [(0, 10), (5, 0), (-1, -1)])
def test_invalid_parameters_rejected(threshold, window):
    with pytest.raises(ValueError):
        BruteForceRule(threshold, window)
