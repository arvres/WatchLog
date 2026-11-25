from watchlog.detection import LoginAfterFailuresRule
from watchlog.models import AlertType, EventType, Severity


def test_success_after_enough_failures_is_critical(make_event):
    rule = LoginAfterFailuresRule(5)
    for t in range(8):
        assert rule.evaluate(make_event(at=t)) == []
    (alert,) = rule.evaluate(make_event(EventType.AUTH_SUCCESS, at=9))
    assert alert.type is AlertType.SSH_LOGIN_AFTER_FAILURES
    assert alert.severity is Severity.CRITICAL
    assert alert.event_count == 8
    assert alert.usernames == ("admin",)


def test_success_with_few_failures_is_ignored(make_event):
    rule = LoginAfterFailuresRule(5)
    for t in range(4):
        rule.evaluate(make_event(at=t))
    assert rule.evaluate(make_event(EventType.AUTH_SUCCESS, at=5)) == []


def test_old_failures_do_not_count(make_event):
    rule = LoginAfterFailuresRule(5, window_seconds=60)
    for t in range(5):
        rule.evaluate(make_event(at=t))
    assert rule.evaluate(make_event(EventType.AUTH_SUCCESS, at=10_000)) == []


def test_history_is_cleared_after_alert(make_event):
    rule = LoginAfterFailuresRule(3)
    for t in range(3):
        rule.evaluate(make_event(at=t))
    assert len(rule.evaluate(make_event(EventType.AUTH_SUCCESS, at=4))) == 1
    assert rule.evaluate(make_event(EventType.AUTH_SUCCESS, at=5)) == []


def test_failures_from_other_ips_do_not_count(make_event):
    rule = LoginAfterFailuresRule(3)
    for t in range(3):
        rule.evaluate(make_event(at=t, ip="9.9.9.9"))
    assert rule.evaluate(make_event(EventType.AUTH_SUCCESS, at=4, ip="1.1.1.1")) == []


def test_success_without_history_or_ip(make_event):
    rule = LoginAfterFailuresRule(1)
    assert rule.evaluate(make_event(EventType.AUTH_SUCCESS)) == []
    assert rule.evaluate(make_event(EventType.AUTH_SUCCESS, ip=None)) == []
