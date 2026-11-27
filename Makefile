# WatchLog - Development Makefile
# Usage: make <target>

.PHONY: help install test test-all lint format type-check build clean coverage docs release check

# Default target
help:
	@echo "WatchLog Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  install       Install package in development mode with dev dependencies"
	@echo "  install-hooks Install pre-commit hooks"
	@echo ""
	@echo "Testing:"
	@echo "  test          Run fast test suite (unit tests only)"
	@echo "  test-all      Run all tests including slow/integration tests"
	@echo "  coverage      Run tests with coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint          Run ruff linter"
	@echo "  format        Format code with ruff"
	@echo "  type-check    Run mypy type checker"
	@echo "  check         Run all quality checks (lint + format + type-check)"
	@echo ""
	@echo "Building:"
	@echo "  build         Build wheel and sdist"
	@echo "  build-docker  Build Docker image"
	@echo ""
	@echo "Release:"
	@echo "  release-patch Bump patch version, tag, and push"
	@echo "  release-minor Bump minor version, tag, and push"
	@echo "  release-major Bump major version, tag, and push"
	@echo ""
	@echo "Utilities:"
	@echo "  clean         Remove build artifacts"
	@echo "  docs          Build documentation (if configured)"
	@echo "  run           Run watchlog on sample logs"

# =============================================================================
# Setup
# =============================================================================

install:
	pip install --upgrade pip
	pip install -e ".[dev]"
	pre-commit install

install-hooks:
	pre-commit install
	pre-commit install --hook-type commit-msg

# =============================================================================
# Testing
# =============================================================================

test:
	python -m pytest -x -q --tb=short

test-all:
	python -m pytest -v --tb=short

coverage:
	python -m pytest --cov=watchlog --cov-report=term-missing --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

# =============================================================================
# Code Quality
# =============================================================================

lint:
	ruff check src tests

format:
	ruff format src tests

type-check:
	mypy --strict src/watchlog

check: lint format type-check
	@echo "All checks passed!"

# =============================================================================
# Building
# =============================================================================

build:
	python -m build

build-docker:
	docker build -t watchlog:local .

# =============================================================================
# Release
# =============================================================================

# Usage: make release-patch (or release-minor, release-major)
release-patch release-minor release-major:
	@version=$$(grep '^version = ' pyproject.toml | cut -d'"' -f2); \
	IFS='.' read -r major minor patch <<< "$$version"; \
	if [ "$@" = "release-patch" ]; then patch=$$((patch + 1)); \
	elif [ "$@" = "release-minor" ]; then minor=$$((minor + 1)); patch=0; \
	elif [ "$@" = "release-major" ]; then major=$$((major + 1)); minor=0; patch=0; \
	fi; \
	new_version="$$major.$$minor.$$patch"; \
	sed -i "s/^version = .*/version = \"$$new_version\"/" pyproject.toml; \
	sed -i "s/^__version__ = .*/__version__ = \"$$new_version\"/" src/watchlog/__init__.py; \
	git add pyproject.toml src/watchlog/__init__.py; \
	git commit -m "chore: release v$$new_version"; \
	git tag -a "v$$new_version" -m "Release v$$new_version"; \
	echo "Release v$$new_version prepared. Push with: git push origin main --tags"

# =============================================================================
# Utilities
# =============================================================================

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

docs:
	@echo "Documentation not configured yet. Consider mkdocs or sphinx."

run:
	python -m watchlog samples/auth.log -v

run-follow:
	python -m watchlog samples/auth.log --follow --from-start -v

run-json:
	python -m watchlog samples/auth.log --format json

# =============================================================================
# Docker Compose
# =============================================================================

compose-up:
	docker compose up -d

compose-down:
	docker compose down

compose-logs:
	docker compose logs -f

# =============================================================================
# Security
# =============================================================================

security-scan:
	bandit -r src -ll
	pip-audit
