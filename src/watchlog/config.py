"""Configuração das regras (limiares, janelas). Carregada de TOML; tudo tem valor padrão."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RuleSettings:
    enabled: bool = True
    threshold: int = 5
    window_seconds: int = 300
    cooldown_seconds: int | None = None  # None => igual à janela

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ConfigError("'enabled' deve ser true/false")
        if not _is_int(self.threshold) or self.threshold < 1:
            raise ConfigError("'threshold' deve ser um inteiro >= 1")
        if not _is_int(self.window_seconds) or self.window_seconds < 1:
            raise ConfigError("'window_seconds' deve ser um inteiro >= 1")
        if self.cooldown_seconds is not None and (
            not _is_int(self.cooldown_seconds) or self.cooldown_seconds < 0
        ):
            raise ConfigError("'cooldown_seconds' deve ser um inteiro >= 0")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _default_rules() -> dict[str, RuleSettings]:
    return {
        "brute_force": RuleSettings(),
        "password_spray": RuleSettings(),
        "login_after_failures": RuleSettings(),
    }


@dataclass(frozen=True, slots=True)
class Config:
    rules: dict[str, RuleSettings] = field(default_factory=_default_rules)


_ALLOWED_KEYS = set(RuleSettings.__slots__)


def load_config(path: str | Path) -> Config:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"TOML inválido em {path}: {exc}") from exc

    unknown_top = set(data) - {"rules"}
    if unknown_top:
        raise ConfigError(f"seções desconhecidas: {sorted(unknown_top)}")

    rules = _default_rules()
    for name, values in data.get("rules", {}).items():
        if name not in rules:
            raise ConfigError(f"regra desconhecida: {name!r} (válidas: {sorted(rules)})")
        if not isinstance(values, dict):
            raise ConfigError(f"[rules.{name}] deve ser uma tabela")
        unknown = set(values) - _ALLOWED_KEYS
        if unknown:
            raise ConfigError(f"chaves desconhecidas em [rules.{name}]: {sorted(unknown)}")
        rules[name] = replace(rules[name], **values)
    return Config(rules=rules)
