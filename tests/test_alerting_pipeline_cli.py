import io
import json
from datetime import datetime
from pathlib import Path

import pytest

from watchlog.alerting import AlertManager, JsonLinesSink, TextSink
from watchlog.cli import main
from watchlog.detection import BruteForceRule, DetectionEngine
from watchlog.models import Alert, AlertType, Severity
from watchlog.parsers import SSHParser
from watchlog.pipeline import Pipeline

SAMPLES = Path(__file__).parent.parent / "samples"


def make_alert(sev=Severity.HIGH):
    return Alert(
        AlertType.SSH_BRUTE_FORCE, sev, "msg", "1.2.3.4", datetime(2026, 8, 17), 5, ("a",), 300, "r"
    )


def test_text_and_json_sinks():
    t, j = io.StringIO(), io.StringIO()
    TextSink(t).emit(make_alert())
    JsonLinesSink(j).emit(make_alert())
    assert "[HIGH]" in t.getvalue() and "ip=1.2.3.4" in t.getvalue()
    data = json.loads(j.getvalue())
    assert (
        data["severity"] == "high"
        and data["usernames"] == ["a"]
        and data["type"] == "ssh_brute_force"
    )


def test_manager_filters_by_min_severity():
    out = io.StringIO()
    m = AlertManager([TextSink(out)], Severity.HIGH)
    assert m.handle(make_alert(Severity.LOW)) is False
    assert m.handle(make_alert(Severity.CRITICAL)) is True
    assert out.getvalue().count("\n") == 1


def test_failing_sink_does_not_break_the_others():
    class Boom:
        def emit(self, alert):
            raise RuntimeError("x")

    out = io.StringIO()
    AlertManager([Boom(), TextSink(out)]).handle(make_alert())
    assert out.getvalue()


def test_pipeline_counts_and_skips_comments_blanks_and_noise():
    out = io.StringIO()
    p = Pipeline(
        SSHParser(year=2026), DetectionEngine([BruteForceRule(2)]), AlertManager([TextSink(out)])
    )
    line = "Aug 17 10:00:0{} s sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2"
    stats = p.run(["# comentario", "", "lixo", line.format(1), line.format(2)])
    assert (stats.lines_read, stats.events_parsed, stats.alerts_raised) == (5, 2, 1)


# ---------------------------------------------------------------- end-to-end via CLI
def run_cli(capsys, *args):
    code = main([str(a) for a in args])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_cli_brute_force_sample(capsys):
    code, out, _ = run_cli(capsys, SAMPLES / "auth.log", "--year", 2026, "--format", "json")
    assert code == 0
    types = [json.loads(line)["type"] for line in out.splitlines()]
    assert types == ["ssh_brute_force", "ssh_login_after_failures"]


def test_cli_password_spray_sample_has_no_false_brute_force(capsys):
    code, out, _ = run_cli(
        capsys, SAMPLES / "password_spray.log", "--year", 2026, "--format", "json"
    )
    assert [json.loads(line)["type"] for line in out.splitlines()] == ["ssh_password_spray"]


def test_cli_slow_failures_sample_raises_nothing(capsys):
    code, out, _ = run_cli(capsys, SAMPLES / "slow_failures.log", "--year", 2026)
    assert code == 0 and out == ""


def test_cli_stdout_has_only_alerts_and_summary_goes_to_stderr(capsys):
    _, out, err = run_cli(capsys, SAMPLES / "auth.log", "--year", 2026)
    assert all("[" in line for line in out.splitlines())
    assert "linhas" in err and "eventos" in err


def test_cli_min_severity_filter(capsys):
    _, out, _ = run_cli(capsys, SAMPLES / "auth.log", "--year", 2026, "--min-severity", "critical")
    assert out.count("\n") == 1 and "CRITICAL" in out


def test_cli_output_file_receives_jsonl(capsys, tmp_path):
    dest = tmp_path / "alerts.jsonl"
    run_cli(capsys, SAMPLES / "auth.log", "--year", 2026, "-o", dest)
    assert len(dest.read_text().splitlines()) == 2


def test_cli_custom_config_changes_behavior(capsys, tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text(
        "[rules.brute_force]\nthreshold = 3\n[rules.login_after_failures]\nenabled = false\n"
    )
    _, out, _ = run_cli(capsys, SAMPLES / "auth.log", "--year", 2026, "--format", "json", "-c", cfg)
    (alert,) = [json.loads(line) for line in out.splitlines()]
    assert alert["event_count"] == 3


def test_cli_missing_file_returns_1(capsys):
    code, _, err = run_cli(capsys, "/nao/existe.log")
    assert code == 1 and "erro" in err


def test_cli_bad_config_and_bad_severity_return_2(capsys, tmp_path):
    bad = tmp_path / "c.toml"
    bad.write_text("[rules.xyz]\n")
    assert run_cli(capsys, SAMPLES / "auth.log", "-c", bad)[0] == 2
    assert run_cli(capsys, SAMPLES / "auth.log", "--min-severity", "banana")[0] == 2
    assert run_cli(capsys, SAMPLES / "auth.log", "-c", tmp_path / "missing.toml")[0] == 1


def test_cli_requires_logfile(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2
