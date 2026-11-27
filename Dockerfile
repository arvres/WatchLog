# WatchLog - SSH Authentication Attack Detector
# Multi-stage build for minimal production image

# Build stage
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy only packaging files first for better caching
COPY pyproject.toml README.md ./
COPY src ./src

# Build wheel
RUN python -m build --wheel --no-isolation

# Runtime stage
FROM python:3.11-slim AS runtime

# Create non-root user
RUN groupadd -r watchlog && useradd -r -g watchlog -s /sbin/nologin -d /app watchlog

WORKDIR /app

# Install runtime dependencies only (none for watchlog, but keep for extensibility)
RUN pip install --no-cache-dir --upgrade pip

# Copy wheel from builder and install
COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Switch to non-root user
USER watchlog

# Default log directory (read-only in production)
VOLUME ["/var/log"]

# Entry point
ENTRYPOINT ["watchlog"]

# Default command shows help
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="WatchLog" \
      org.opencontainers.image.description="SSH authentication attack detector (brute force, password spray, login after failures)" \
      org.opencontainers.image.source="https://github.com/<owner>/watchlog" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="WatchLog Contributors"
