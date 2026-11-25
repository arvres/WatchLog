# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

Only the latest minor release receives security updates.

## Reporting a Vulnerability

**Do not report security vulnerabilities via public GitHub issues.**

Instead, email: **security@watchlog.example.com** (replace with actual contact)

Or use GitHub's private vulnerability reporting:
1. Go to the [Security tab](https://github.com/<owner>/watchlog/security)
2. Click "Report a vulnerability"
3. Fill in the details

We will acknowledge receipt within **48 hours** and provide a status update within **7 days**.

## Disclosure Process

1. **Report received** - Acknowledged within 48h
2. **Triage** - Validated and assessed within 7 days
3. **Fix development** - Target fix within 30 days for critical, 90 days for others
4. **Release** - Patch release with security fix
5. **Public disclosure** - CVE requested, advisory published after fix release

## Scope

### In Scope

- WatchLog application code (`src/watchlog/`)
- Configuration parsing and validation
- Log parsing and event extraction
- Detection logic and alerting
- CLI argument handling
- File reading and follow mode

### Out of Scope

- Underlying Python interpreter vulnerabilities
- Operating system / kernel vulnerabilities
- Third-party dependencies (none at runtime)
- Deployment infrastructure (Docker, systemd, etc.)
- Social engineering / physical access attacks

## Security Features

### Input Validation

- All log lines parsed with anchored regexes
- Invalid lines return `None` (never crash)
- TOML config validated with strict schema
- CLI arguments validated with argparse

### Memory Safety

- Bounded sliding windows with automatic GC
- No unbounded data structures
- Cooldown maps with periodic cleanup
- Max 20 usernames per alert (prevents memory exhaustion)

### Privilege Separation

- Docker: Runs as non-root user (`watchlog:watchlog`)
- Systemd: Hardened service with `NoNewPrivileges`, `ProtectSystem=strict`
- File access: Read-only access to log files

### Supply Chain

- Zero runtime dependencies (stdlib only)
- Dev dependencies pinned in `pyproject.toml`
- GitHub Actions with pinned action versions
- Dependabot for automated dependency updates
- Bandit static analysis in CI
- Pip-audit for vulnerability scanning

## Hardening Recommendations

### Production Deployment

```bash
# Run as dedicated user
useradd -r -s /sbin/nologin watchlog

# Restrict log file permissions
chmod 640 /var/log/auth.log
chown root:watchlog /var/log/auth.log

# Use systemd service (see packaging/systemd/watchlog.service)
systemctl enable --now watchlog
```

### Network

- WatchLog does not open network ports by default
- If adding webhook sinks: use HTTPS, validate certificates, restrict egress
- Consider network policies in Kubernetes

### Logging

- Alerts go to stdout (structured JSON recommended)
- Diagnostics go to stderr
- No sensitive data in logs (IPs and usernames are not secret)
- Rotate logs: `logrotate` config recommended

## Security Checklist for Contributors

- [ ] No `eval`, `exec`, `subprocess` with user input
- [ ] No hardcoded secrets or credentials
- [ ] All inputs validated and sanitized
- [ ] Regexes are anchored and tested against malicious input
- [ ] File operations use safe paths (no path traversal)
- [ ] Dependencies reviewed before adding
- [ ] Tests cover edge cases and invalid input

## Contact

For security questions or concerns not covered here, contact the maintainers via the private reporting channels above.