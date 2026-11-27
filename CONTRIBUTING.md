# Contributing to WatchLog

Thank you for your interest in contributing! This document outlines the process and standards for contributing to WatchLog.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold this code. Report unacceptable behavior to the maintainers.

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- (Optional) Docker for container testing

### Setup

```bash
# Fork and clone
git clone https://github.com/<your-fork>/watchlog.git
cd watchlog

# Install development dependencies
make install

# Verify everything works
make test
make check
```

## Development Workflow

### Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/<short-description>` | `feat/add-geoip-enrichment` |
| Bugfix | `fix/<short-description>` | `fix/parser-ipv6-handling` |
| Docs | `docs/<short-description>` | `docs/update-readme-examples` |
| Refactor | `refactor/<short-description>` | `refactor/detection-engine` |
| Chore | `chore/<short-description>` | `chore/update-dependencies` |

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`

Examples:
```
feat(parser): add support for sshd-session process name
fix(detection): correct cooldown expiration logic
docs(readme): add docker compose example
```

## Code Standards

### Python Style

- **Formatter:** Ruff (line length 100, target py311)
- **Linter:** Ruff (E, F, W, I, B, UP, SIM)
- **Type Checker:** MyPy (strict mode)
- **Security:** Bandit (low confidence, low severity)

Run all checks:
```bash
make check
```

### Architecture Principles

1. **Immutability:** Domain models are frozen dataclasses
2. **Separation of Concerns:** Parser → Models → Detection → Alerting
3. **Dependency Injection:** Protocols (ABC) for extensibility
4. **No Runtime Dependencies:** Stdlib only (dev deps allowed)
5. **Deterministic Time:** Use event timestamps, not wall clock
6. **Memory Safety:** Bounded state with explicit GC

### Adding a New Detection Rule

1. Create `src/watchlog/detection/<rule_name>.py`
2. Subclass `DetectionRule` from `base.py`
3. Implement `evaluate(event) -> list[Alert]`
4. Use `KeyedWindows`/`Cooldown` from `state.py` for time-bounded state
5. Register in `registry.py`:
   ```python
   RULE_FACTORIES: dict[str, RuleFactory] = {
       ...
       NewRule.name: _factory(NewRule),
   }
   ```
6. Add config defaults in `config.py`
7. Write tests in `tests/test_<rule_name>.py`

### Adding a New Parser

1. Create `src/watchlog/parsers/<name>.py`
2. Subclass `LogParser` from `base.py`
3. Implement `parse(line: str) -> SecurityEvent | None`
4. Register in `parsers/__init__.py`
5. Update CLI to support new parser (or auto-detect)

### Adding a New Alert Sink

1. Implement `AlertSink` protocol in `alerting/sinks.py`
2. Add `emit(alert: Alert) -> None` method
3. Handle errors gracefully (manager catches exceptions)
4. Register in CLI or config

## Testing

### Test Categories

| Category | Location | Run Command |
|----------|----------|-------------|
| Unit | `tests/test_*.py` | `make test` |
| Integration | `tests/test_*_pipeline_cli.py` | `make test-all` |
| Parser | `tests/test_parser_ssh.py` | `pytest tests/test_parser_ssh.py` |
| Detection | `tests/test_brute_force.py`, etc. | `pytest tests/test_brute_force.py` |

### Test Guidelines

- **Fast:** Unit tests < 100ms each
- **Deterministic:** No wall-clock time, use injected `now` callable
- **Isolated:** No shared state between tests
- **Descriptive:** Test names explain the scenario
- **Edge Cases:** Test boundaries, invalid input, time windows

### Running Tests

```bash
# Fast subset (pre-commit)
make test

# Full suite
make test-all

# With coverage
make coverage

# Specific test
pytest tests/test_brute_force.py::test_alert_at_threshold -v
```

## Pull Request Process

1. **Create PR** from your fork to `main`
2. **Fill template** with description, motivation, and testing done
3. **Pass CI** - all checks must be green
4. **Code Review** - address feedback
5. **Squash & Merge** - maintainers will squash on merge

### PR Checklist

- [ ] Tests added/updated for new functionality
- [ ] All tests pass (`make test-all`)
- [ ] Code passes quality checks (`make check`)
- [ ] Documentation updated (README, docstrings, CHANGELOG)
- [ ] No breaking changes without major version bump
- [ ] Commits follow Conventional Commits

## Release Process

Maintainers only:

1. **Version bump:** `make release-patch` (or minor/major)
2. **Changelog:** Update `CHANGELOG.md` with release notes
3. **Tag:** `git push origin main --tags`
4. **CI/CD:** GitHub Actions builds, tests, publishes to PyPI and GHCR

### Versioning

Follows [Semantic Versioning](https://semver.org/):

| Change | Version |
|--------|---------|
| Bug fixes | PATCH (0.2.1) |
| New features, backward compatible | MINOR (0.3.0) |
| Breaking changes | MAJOR (1.0.0) |

---

## Questions?

Open a [Discussion](https://github.com/<owner>/watchlog/discussions) or [Issue](https://github.com/<owner>/watchlog/issues).
