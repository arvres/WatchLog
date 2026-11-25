"""
Estruturas de estado para regras baseadas em tempo.

O original contava tentativas para sempre (um contador por IP que nunca zerava) e silenciava
alertas para sempre (`alerted[ip] = true`). Aqui o estado é limitado no tempo e na memória.
"""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Hashable


class SlidingWindow:
    """
    Janela deslizante sobre o *tempo dos eventos* (não o relógio da máquina), o que torna a
    análise de logs antigos determinística. Um item com instante `t` permanece enquanto
    `t > agora - seconds`, isto é, a janela é (agora - seconds, agora].
    """

    __slots__ = ("seconds", "_items", "_counts")

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self._items: deque[tuple[float, str]] = deque()
        self._counts: Counter[str] = Counter()

    def add(self, at: float, value: str) -> None:
        self.prune(at)
        self._items.append((at, value))
        self._counts[value] += 1

    def prune(self, now: float) -> None:
        cutoff = now - self.seconds
        while self._items and self._items[0][0] <= cutoff:
            _, value = self._items.popleft()
            self._counts[value] -= 1
            if self._counts[value] == 0:
                del self._counts[value]

    def __len__(self) -> int:
        """Total de eventos dentro da janela."""
        return len(self._items)

    @property
    def distinct(self) -> int:
        """Quantidade de valores distintos dentro da janela."""
        return len(self._counts)

    def values(self) -> set[str]:
        return set(self._counts)


class KeyedWindows:
    """Uma `SlidingWindow` por chave, com coleta periódica de janelas vazias (sem vazar memória)."""

    def __init__(self, seconds: float, gc_every: int = 1024) -> None:
        self.seconds = seconds
        self._gc_every = gc_every
        self._ops = 0
        self._windows: dict[Hashable, SlidingWindow] = {}

    def add(self, key: Hashable, at: float, value: str) -> SlidingWindow:
        window = self._windows.get(key)
        if window is None:
            window = self._windows[key] = SlidingWindow(self.seconds)
        window.add(at, value)
        self._ops += 1
        if self._ops % self._gc_every == 0:
            self._collect(at)
        return window

    def get(self, key: Hashable, at: float) -> SlidingWindow | None:
        window = self._windows.get(key)
        if window is not None:
            window.prune(at)
        return window

    def discard(self, key: Hashable) -> None:
        self._windows.pop(key, None)

    def _collect(self, now: float) -> None:
        for key, window in list(self._windows.items()):
            window.prune(now)
            if len(window) == 0:
                del self._windows[key]

    def __len__(self) -> int:
        return len(self._windows)


class Cooldown:
    """
    Evita alertas repetidos para a mesma chave por `seconds`. Diferente do `alerted[ip] = true`
    original, o silêncio expira: um ataque que recomeça horas depois volta a gerar alerta.
    """

    def __init__(self, seconds: float, gc_every: int = 1024) -> None:
        self.seconds = seconds
        self._gc_every = gc_every
        self._ops = 0
        self._last: dict[Hashable, float] = {}

    def try_acquire(self, key: Hashable, at: float) -> bool:
        last = self._last.get(key)
        if last is not None and at - last < self.seconds:
            return False
        self._last[key] = at
        self._ops += 1
        if self._ops % self._gc_every == 0:
            self._last = {k: t for k, t in self._last.items() if at - t < self.seconds}
        return True
