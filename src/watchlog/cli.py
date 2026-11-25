from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from contextlib import ExitStack

from watchlog import __version__
from watchlog.alerting import AlertManager, AlertSink, JsonLinesSink, TextSink
from watchlog.config import Config, ConfigError, load_config
from watchlog.detection import create_engine
from watchlog.models import Severity
from watchlog.parsers import SSHParser
from watchlog.pipeline import Pipeline
from watchlog.reader import follow_lines, read_lines

EXIT_OK = 0
EXIT_IO_ERROR = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="watchlog",
        description="Detecta ataques de autenticação SSH (força bruta, password spray, "
        "login após falhas) em logs do sshd.",
    )
    p.add_argument("logfile", help="caminho do log (ex.: /var/log/auth.log)")
    p.add_argument(
        "-f",
        "--follow",
        action="store_true",
        help="acompanha o arquivo em tempo real (como tail -F)",
    )
    p.add_argument(
        "--from-start",
        action="store_true",
        help="com --follow, processa o conteúdo existente antes de acompanhar",
    )
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="formato dos alertas no stdout (padrão: text)",
    )
    p.add_argument(
        "-o",
        "--output",
        metavar="ARQUIVO",
        help="grava também os alertas em JSON Lines neste arquivo (append)",
    )
    p.add_argument(
        "--min-severity",
        default="info",
        metavar="NÍVEL",
        help="severidade mínima: info, low, medium, high, critical (padrão: info)",
    )
    p.add_argument("-c", "--config", metavar="TOML", help="arquivo de configuração das regras")
    p.add_argument(
        "--year", type=int, help="ano dos logs (o syslog clássico não tem ano; padrão: inferido)"
    )
    p.add_argument("-v", "--verbose", action="store_true", help="loga cada evento em stderr")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        config = load_config(args.config) if args.config else Config()
        min_severity = Severity.parse(args.min_severity)
    except (ConfigError, ValueError) as exc:
        print(f"watchlog: erro de configuração: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"watchlog: não foi possível ler a configuração: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR

    try:
        with ExitStack() as stack:
            sinks: list[AlertSink] = [
                JsonLinesSink(sys.stdout) if args.format == "json" else TextSink(sys.stdout)
            ]
            if args.output:
                out = stack.enter_context(open(args.output, "a", encoding="utf-8"))
                sinks.append(JsonLinesSink(out))

            pipeline = Pipeline(
                parser=SSHParser(year=args.year),
                engine=create_engine(config),
                alerts=AlertManager(sinks, min_severity),
            )
            lines = (
                follow_lines(args.logfile, from_start=args.from_start)
                if args.follow
                else read_lines(args.logfile)
            )
            try:
                pipeline.run(lines)
            except KeyboardInterrupt:
                print("\nwatchlog: interrompido.", file=sys.stderr)

            s = pipeline.stats
            print(
                f"watchlog: {s.lines_read} linhas, {s.events_parsed} eventos, "
                f"{s.alerts_raised} alertas",
                file=sys.stderr,
            )
    except OSError as exc:
        print(f"watchlog: erro de E/S: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
