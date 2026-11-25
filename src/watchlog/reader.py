"""Leitura de linhas: modo batch (arquivo inteiro) e modo follow (estilo `tail -F`)."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path


def read_lines(path: str | Path) -> Iterator[str]:
    """Lê o arquivo linha a linha (streaming: não carrega tudo em memória)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\r\n")


def follow_lines(
    path: str | Path,
    *,
    from_start: bool = False,
    poll_interval: float = 0.5,
    stop: Callable[[], bool] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[str]:
    """
    Acompanha um arquivo em crescimento.

    - Só entrega linhas *completas* (termina em \\n); um trecho parcial fica em buffer.
    - Detecta rotação (inode mudou) e truncamento (tamanho < posição) e reabre o arquivo.
    - Limitação conhecida (igual ao `tail -f`): se o arquivo for truncado e reescrito além da
      posição anterior entre duas leituras, o truncamento não é percebido.
    - `stop` e `sleep` são injetáveis para testes; em uso normal o laço termina com Ctrl+C.
    """
    path = Path(path)
    fh = open(path, "rb")  # noqa: SIM115 - fechado no finally
    try:
        if not from_start:
            fh.seek(0, os.SEEK_END)
        inode = os.fstat(fh.fileno()).st_ino
        pending = b""

        while True:
            chunk = fh.readline()
            if chunk:
                pending += chunk
                if pending.endswith(b"\n"):
                    yield pending.decode("utf-8", errors="replace").rstrip("\r\n")
                    pending = b""
                continue

            # EOF: nada novo por enquanto.
            if stop is not None and stop():
                return
            try:
                st = os.stat(path)
            except FileNotFoundError:  # no meio de uma rotação
                sleep(poll_interval)
                continue
            if st.st_ino != inode or st.st_size < fh.tell():
                fh.close()
                fh = open(path, "rb")  # noqa: SIM115
                inode = os.fstat(fh.fileno()).st_ino
                pending = b""
                continue
            sleep(poll_interval)
    finally:
        fh.close()
