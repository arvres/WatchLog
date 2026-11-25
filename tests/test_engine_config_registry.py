import pytest

from watchlog.config import Config, ConfigError, RuleSettings, load_config
from watchlog.detection import BruteForceRule, DetectionEngine, create_engine
from watchlog.detection.registry import RULE_FACTORIES
from watchlog.models import AlertType


def test_engine_aggregates_alerts_from_all_rules(make_event):
    engine = create_engine(
        Config(
            rules={
                **Config().rules,
                "brute_force": RuleSettings(threshold=2),
                "password_spray": RuleSettings(threshold=2),
            }
        )
    )
    alerts = []
    # 2 falhas do mesmo usuário -> brute force; 2 usuários distintos -> spray
    alerts += engine.process(make_event(at=0, user="a"))
    alerts += engine.process(make_event(at=1, user="a"))
    alerts += engine.process(make_event(at=2, user="b"))
    kinds = {a.type for a in alerts}
    assert kinds == {AlertType.SSH_BRUTE_FORCE, AlertType.SSH_PASSWORD_SPRAY}


def test_engine_with_no_rules_returns_nothing(make_event):
    assert DetectionEngine().process(make_event()) == []


def test_engine_add_rule(make_event):
    engine = DetectionEngine()
    engine.add_rule(BruteForceRule(1))
    assert len(engine.process(make_event())) == 1


def test_disabled_rule_is_not_created():
    cfg = Config(rules={**Config().rules, "password_spray": RuleSettings(enabled=False)})
    names = {r.name for r in create_engine(cfg).rules}
    assert "password_spray" not in names and "brute_force" in names


def test_every_default_rule_has_a_factory():
    assert set(Config().rules) == set(RULE_FACTORIES)


def test_load_config_merges_with_defaults(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text("[rules.brute_force]\nthreshold = 10\nwindow_seconds = 60\n")
    cfg = load_config(f)
    assert cfg.rules["brute_force"].threshold == 10
    assert cfg.rules["brute_force"].window_seconds == 60
    assert cfg.rules["password_spray"] == RuleSettings()


@pytest.mark.parametrize(
    "content",
    [
        "[rules.nope]\nthreshold = 1\n",
        "[rules.brute_force]\nthreshhold = 1\n",  # typo
        "[rules.brute_force]\nthreshold = 0\n",
        "[rules.brute_force]\nthreshold = true\n",
        "[rules.brute_force]\nwindow_seconds = 'x'\n",
        "[extra]\na = 1\n",
        "isto nao e toml",
    ],
)
def test_invalid_configs_raise(tmp_path, content):
    f = tmp_path / "c.toml"
    f.write_text(content)
    with pytest.raises(ConfigError):
        load_config(f)


def test_shipped_example_config_is_valid():
    from pathlib import Path

    load_config(Path(__file__).parent.parent / "watchlog.example.toml")
