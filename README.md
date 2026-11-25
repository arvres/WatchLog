# WatchLog

Detecta ataques de autenticação SSH em logs do `sshd`: **força bruta**, **password spray** e
**login bem-sucedido após falhas**. Python ≥ 3.11, sem dependências de runtime.

> Reescrita em Python do projeto C++ original. O que mudou e por quê:
> [`docs/REVISAO_ARQUITETURA.md`](docs/REVISAO_ARQUITETURA.md).

## Uso

```bash
pip install -e ".[dev]"          # ou apenas: PYTHONPATH=src python -m watchlog ...

watchlog /var/log/auth.log                       # analisa o arquivo inteiro
watchlog /var/log/auth.log --follow              # acompanha em tempo real (tail -F)
watchlog /var/log/auth.log -f --from-start       # processa o que já existe e continua acompanhando
watchlog samples/auth.log --year 2026 --format json
watchlog auth.log -o alertas.jsonl --min-severity high
watchlog auth.log --config watchlog.example.toml
```

Alertas vão para **stdout**; resumo e diagnósticos para **stderr** (`-v` loga cada evento).
Códigos de saída: `0` ok · `1` erro de E/S · `2` argumentos/configuração inválidos.

Exemplo de saída (`samples/auth.log`):

```
2026-08-17T10:31:07 [HIGH] ssh_brute_force ip=192.168.1.50 count=5 users=admin :: 5 falhas de login SSH ...
2026-08-17T10:31:12 [CRITICAL] ssh_login_after_failures ip=192.168.1.50 count=8 users=admin :: login bem-sucedido ...
```

## Regras

| Regra | Dispara quando… | Severidade |
|-------|-----------------|-----------|
| `brute_force` | ≥ N falhas, mesmo IP **e** mesmo usuário, em T segundos | HIGH |
| `password_spray` | ≥ N usuários **distintos** atacados pelo mesmo IP em T segundos | HIGH |
| `login_after_failures` | login com sucesso de um IP com ≥ N falhas nos últimos T segundos | CRITICAL |

Padrões: N = 5, T = 300 s; ajustáveis em TOML (veja `watchlog.example.toml`). Após alertar, a
mesma chave só alerta de novo depois de um *cooldown* (padrão = janela).

## Arquitetura

```
linhas ──► parsers/ ──► SecurityEvent ──► detection/ ──► Alert ──► alerting/ ──► stdout / arquivo
 reader.py   (ssh.py)    (models.py)      engine + rules  (models)   manager + sinks
                                   └──────────── pipeline.py ─────────────┘
```

* `models.py` – dados imutáveis, sem dependências.
* `parsers/` – `LogParser` (ABC) → `SSHParser`. Novo formato = nova subclasse.
* `detection/` – `DetectionRule` (ABC) + `state.py` (janelas/cooldown) + `registry.py`.
  Nova regra = subclasse + 1 linha em `RULE_FACTORIES` + entrada em `config.py`.
* `alerting/` – `AlertSink` (Protocol). Novo destino (webhook, e-mail…) = implementar `emit`.
* `pipeline.py` – une as peças; `cli.py` – só argumentos e I/O.

## Desenvolvimento

```bash
python -m pytest        # 90 testes
ruff check src tests
```

## Limitações conhecidas

* Só `sshd`/`sshd-session` (texto). Sem ingestão direta do journald nem de Windows Event Log.
* Eventos devem chegar em ordem cronológica (como em qualquer log normal).
* Sem ano no syslog clássico: inferido (ou `--year`).
* Sem detecção distribuída (muitos IPs com poucas tentativas cada).
