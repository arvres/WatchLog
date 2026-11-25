# Revisão de arquitetura do WatchLog (C++ → Python)

Este documento lista o que estava errado ou frágil no projeto C++ original e como cada ponto foi
tratado na reescrita em Python. Os itens estão em ordem de impacto.

## A. Bugs de corretude na detecção (o "produto" em si)

| # | Problema no original | Consequência | Correção |
|---|----------------------|--------------|----------|
| 1 | **Contadores sem janela de tempo** (`failedAttempts[ip]` só incrementa). | 5 falhas espalhadas em *meses* disparavam "brute force". Qualquer servidor com usuários que erram a senha de vez em quando gera falso positivo. | `SlidingWindow` sobre o tempo dos eventos; limiar + janela (`threshold`/`window_seconds`). |
| 2 | **`timestamp` era `std::string`** ("Aug 17 10:31:01"), sem ano e sem tipo de data. | Impossível calcular janelas; a correção do item 1 dependia disto. | `datetime`. O parser infere o ano (com tratamento de virada dez→jan), aceita `--year` e suporta ISO-8601. |
| 3 | **`alerted[ip] = true` para sempre.** | Um IP que atacou às 10h nunca mais gerava alerta, nem se atacasse de novo no dia seguinte. | `Cooldown` com expiração: um alerta por janela enquanto o ataque continua. |
| 4 | **Brute force e spray se sobrepunham.** Brute force contava falhas por IP (qualquer usuário). | `samples/password_spray.log` (5 usuários × 1 tentativa) disparava *também* "força bruta", o que é semanticamente errado. | Brute force = mesmo IP **e** mesmo usuário. Muitos usuários = spray. Regras ortogonais. |
| 5 | **Alerta de spray carregava só o *último* usuário** (`alert.username = username`). | Informação enganosa/inútil para o analista. | `Alert.usernames` com a lista (ordenada, limitada a 20). |
| 6 | **Faltava a detecção mais importante:** login *bem-sucedido* depois de falhas. O próprio `auth.log` de exemplo termina assim, mas nenhuma regra olhava `AUTHENTICATION_SUCCESS`. | O caso "o ataque funcionou" passava em branco. | `LoginAfterFailuresRule` (severidade CRITICAL). |
| 7 | **Estado ilimitado**: os `unordered_map` por IP só cresciam. | Vazamento de memória em execução contínua (um scan de internet gera milhões de IPs). | `KeyedWindows`/`Cooldown` com coleta periódica de chaves expiradas. |

## B. Cobertura do parser

| # | Problema | Correção |
|---|----------|----------|
| 8 | Só reconhecia `Failed password`; ignorava `Failed publickey`, `Invalid user …`, `keyboard-interactive/pam`. | Cobertos. `Invalid user` vira evento próprio (sem dupla contagem com `Failed password for invalid user`). |
| 9 | O regex **descartava** o `invalid user` (`(?:invalid user )?`), perdendo se a conta existia. | Flag `invalid_user` preservada no evento. |
| 10 | Exigia `sshd[pid]:`. OpenSSH ≥ 9.8 (Debian 13, Ubuntu recentes) loga como `sshd-session[pid]:`; o pid é opcional em alguns formatos. | Aceita `sshd` e `sshd-session`, pid opcional. |
| 11 | Só timestamp estilo syslog. | Também ISO-8601 (rsyslog moderno). |
| 12 | `std::stoi` sem proteção; `regex_search` sem âncora. | Regex ancorado, campos validados, linhas inválidas viram `None` (testado). |

## C. Design e manutenibilidade

| # | Problema | Correção |
|---|----------|----------|
| 13 | **Não compilava em Linux**: `securityEvent.hpp`, `logParser.hpp`, `sshParser.*`, `logReader.*` eram incluídos como `SecurityEvent.hpp`, `LogParser.hpp`…; funciona só em FS insensível a maiúsculas (Windows/macOS). | Sem o problema em Python; nomes em `snake_case`. |
| 14 | **`SecurityEvent` com campos não inicializados** (`event_type`, `severity`), e os testes criavam eventos sem preenchê-los (comportamento indefinido). | `@dataclass(frozen=True)` com todos os campos definidos; imutável. |
| 15 | **Dois enums de severidade** (`Severity` e `AlertSeverity`) idênticos; severidade no *evento* (decidida pelo parser) em vez de no *alerta*. | Um único `Severity` (`IntEnum`, permite `--min-severity`), só em `Alert`. Parser descreve fatos; regras decidem gravidade. |
| 16 | **`AlertType` com valores sem implementação** (`SUSPICIOUS_LOGIN`, `INVALID_USER_ATTACK`, `PRIVILEGE_ESCALATION`). | Removidos; o enum só tem tipos que existem. |
| 17 | **Limiares fixos no código** (`make_unique<BruteForceRule>(5)`). | `Config` + arquivo TOML; regras registráveis (`RULE_FACTORIES`), ligar/desligar por regra. |
| 18 | **Saída misturada em stdout**: JSON de *cada evento* + texto de alerta, e sem serialização do `Alert`. Inutilizável em pipe. | stdout só tem alertas (`--format text|json`); diagnóstico/resumo em stderr; `-o` grava JSONL. |
| 19 | `AlertManager` = um `cout`. | `AlertSink` (Protocol) + `TextSink`/`JsonLinesSink`; filtro de severidade; falha de um sink não derruba os demais. |
| 20 | Regras devolviam `optional<Alert>` (no máximo um). | `list[Alert]`. |
| 21 | `main()` acumulava parse + engine + saída. | `Pipeline` isolado (testável sem CLI); `cli.py` só faz I/O e argumentos. |
| 22 | **Só modo batch**: para um projeto chamado *WatchLog*, não "observava" nada. | `--follow` (estilo `tail -F`): linhas parciais em buffer, rotação e truncamento tratados. |
| 23 | Sem tratamento de erros além de `catch`; códigos de saída indiferenciados. | 0 ok · 1 erro de E/S · 2 uso/configuração inválidos. |

## D. Build e testes

| # | Problema | Correção |
|---|----------|----------|
| 24 | Dependência de rede no configure (FetchContent de nlohmann_json e googletest, mesmo para só compilar). `.gitignore` com `nlohmann` e `testes.txt`. | Zero dependências de runtime (stdlib). `pytest` só em `dev`. |
| 25 | Testes só cobriam as regras: nada de parser, reader, alertas, CLI. Nenhum teste de tempo (porque não havia tempo). | 90 testes: parser (incl. linhas malformadas), janelas, regras (incl. regressões de "falhas lentas"), reader (follow/rotação/truncamento), config, sinks, pipeline e CLI ponta a ponta sobre `samples/`. |

## Decisões que valem discussão

* **Brute force por (IP, usuário)** em vez de só por IP. Se você preferir "qualquer falha do IP",
  basta mudar a chave em `brute_force.py`; o custo é voltar a sobrepor com spray.
* **Janela = (agora − N, agora]** usando o tempo *do log*, não o relógio da máquina. Isso torna a
  análise de logs antigos determinística, mas pressupõe eventos em ordem cronológica.
* **Sem ano no syslog**: a inferência assume que o log é recente. Para logs antigos use `--year`.
* **Não cobre** ataques distribuídos (muitos IPs, poucas tentativas cada) nem correlação entre
  hosts; seriam novas regras sobre o mesmo `DetectionRule`.
