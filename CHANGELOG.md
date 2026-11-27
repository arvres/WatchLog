# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI/CD pipeline (test, lint, type-check, build, publish)
- Pre-commit hooks (ruff, mypy, bandit, standard hooks)
- Dockerfile (multi-stage, non-root user, minimal image)
- docker-compose.yml for local deployment
- Makefile for common development tasks
- Systemd service unit and tmpfiles configuration
- Comprehensive configuration file (watchlog.toml) with all options
- CHANGELOG.md following Keep a Changelog format
- CONTRIBUTING.md with development guidelines
- SECURITY.md with vulnerability reporting process
- CODEOWNERS for automatic review assignment
- Dependabot configuration for automated dependency updates

### Changed
- Fixed Windows test compatibility (skip rotation test on Windows)
- Improved project structure for professional distribution

### Security
- Bandit security scanning in CI
- Pip-audit for dependency vulnerability scanning
- Non-root user in Docker image
- Hardened systemd service with privilege restrictions

## [0.2.0] - 2026-11-25

### Added
- Complete Python rewrite of original C++ project
- Three detection rules: brute_force, password_spray, login_after_failures
- Sliding window time-based detection (fixes unbounded counters bug)
- Cooldown with expiration (fixes permanent silencing bug)
- Orthogonal rules: brute force = same IP + same user; spray = same IP + many users
- Login-after-failures detection (CRITICAL severity) - missing in original
- Memory-safe state management with periodic garbage collection
- Follow mode (tail -F style) with rotation and truncation handling
- TOML configuration with validation
- JSON and text output formats
- Structured logging to stderr, clean alerts to stdout
- 90 comprehensive tests (parser, detection, reader, CLI, pipeline)
- Zero runtime dependencies (stdlib only)
- Python 3.11+ support

### Fixed (from C++ original)
- Counters without time window → SlidingWindow with configurable window
- String timestamps without year → datetime with year inference/override
- Permanent alert silencing → Cooldown with expiration
- Brute force/spray overlap → Orthogonal rule definitions
- Spray alert only showed last user → Alert includes all attacked usernames
- Missing login-after-failures detection → New CRITICAL rule
- Unbounded memory growth → KeyedWindows with GC
- Case-sensitive header includes → Not applicable in Python
- Uninitialized struct fields → Frozen dataclasses with all fields required
- Dual severity enums → Single Severity IntEnum on Alert only
- Unimplemented AlertType values → Only implemented types in enum
- Hardcoded thresholds → Configurable via TOML
- Mixed stdout output → Separated alerts (stdout) from diagnostics (stderr)
- Single cout AlertManager → Pluggable AlertSink protocol
- Rules returned single optional Alert → Rules return list[Alert]
- Monolithic main() → Pipeline + CLI separation
- Batch-only mode → --follow for real-time monitoring
- Undifferentiated exit codes → 0=OK, 1=I/O error, 2=usage/config error

## [0.1.0] - 2026-01-15

### Added
- Initial C++ implementation
- Basic brute force detection
- Basic password spray detection
- CMake build system
- GoogleTest unit tests
- nlohmann/json dependency
- Sample log files

---

## Release Process

1. Update version in `pyproject.toml` and `src/watchlog/__init__.py`
2. Update CHANGELOG.md with release notes
3. Create git tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
4. Push tag: `git push origin vX.Y.Z`
5. GitHub Actions builds and publishes to PyPI and GHCR automatically
