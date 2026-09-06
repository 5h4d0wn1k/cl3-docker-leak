# CL3 — Docker Secret Leaker

Docker image scanning for hardcoded secrets, environment variable extraction, and layer analysis.

## Overview

This project implements a Docker image security scanner that:
- Scans Docker image configs for embedded secrets and API keys
- Extracts and analyzes environment variables for sensitive values
- Analyzes each layer for embedded credentials
- Detects dangerous Dockerfile patterns (chmod 777, pipe-to-shell)
- Identifies secret types (AWS keys, JWT tokens, connection strings, etc.)
- Generates risk reports with per-finding details

## Features

- **Secret detection**: 15+ regex patterns for AWS keys, JWT, SSH keys, tokens, passwords
- **Environment analysis**: Flag sensitive env vars with masked values
- **Layer analysis**: Scan each image layer command for embedded secrets
- **Dockerfile parsing**: Detect dangerous patterns from build history
- **Risk scoring**: 0–100 score based on findings
- **Multi-image scan**: Scan one or all local images
- **JSON export**: Save results for integration with other tools

## Dependencies

**None** — uses only Python standard library (`subprocess`, `json`, `re`, `hashlib`).

Requires Docker daemon running locally.

## Usage

```bash
# Offline demo (no Docker daemon) — audit bundled fixtures
python3 docker_leak.py --demo

# Audit a custom image-metadata/Dockerfile fixtures file (offline)
python3 docker_leak.py --fixtures fixtures/docker-images.json

# Offline audit with JSON report + CI exit code
python3 docker_leak.py --demo --output reports/cl3-report.json --exit-code-on-findings

# Live (authorized, your own images, requires Docker daemon running):
python3 docker_leak.py nginx:latest python:3.11
python3 docker_leak.py --all-local
```

## Exit Codes

- `0` — completed cleanly (or demo finished without explicit CRITICAL/HIGH gate)
- `1` — error (missing fixtures, unreadable file, bad JSON)
- `2` — CRITICAL/HIGH findings present with `--exit-code-on-findings`

## Live Lab Test Plan

Runs entirely offline against `fixtures/docker-images.json` — no Docker daemon, no image pulls.

1. **Demo**: `python3 docker_leak.py --demo` — expect CRITICAL/HIGH/MEDIUM findings for embedded ENV secrets, COPY of `.env`/`id_rsa`, chmod 777, curl-pipe-sh, Dockerfile ENV secrets, and sensitive labels. Exit `0`.
2. **JSON report**: `python3 docker_leak.py --demo --output reports/cl3-report.json` — verify report has `finding_count > 0`, a `summary` map, and per-finding `severity`, `rule_id`, `message`, `remediation`.
3. **CI exit code**: `python3 docker_leak.py --demo --exit-code-on-findings; echo $?` — expect `2`.
4. **Unit tests**: `python3 -m unittest discover -s tests -v` — all pass (exercises regex patterns, dockerfile rule engine, fixture rule set, sensitive-file detection).
5. **Live (optional)**: pass image names at runtime with Docker daemon running. Only test images you own or are authorized to scan.

## Metrics

- Detection rules exercised offline (real code paths): 15 regex secret patterns from `DockerSecretScanner.SECRET_PATTERNS`; 6 dangerous-instruction rules (WORLD_WRITABLE, PIPE_TO_SHELL, PRIVILEGED, REMOTE_ADD, USER_ADD, UNNECESSARY_TOOLS); sensitive COPY detection for `.env`/`id_rsa`/`credentials`/`*.pem`/`*.key`; ENV secret embedding in config and Dockerfile.
- Every finding carries `severity`, `category`, `rule_id`, `image`, `message`, and a `remediation` string.
- Config/env/label/entrypoint scanning reuses the live scanner's regex engine (`scan_text`/`scan_layer_command`); the offline Dockerfile parser runs the same regex patterns against parsed instructions.
- Exit-code contract: `0` clean / `1` error / `2` findings (with `--exit-code-on-findings`).
- Zero third-party dependencies; `--demo` requires no Docker daemon or network of any kind.

## Legal Disclaimer

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST own the Docker images being scanned, or have explicit written permission from the image owner
- Scanning images you do not own may reveal proprietary configurations
- This tool should ONLY be used on images you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Docker Image Licenses**: Some images have restrictive licenses that prohibit reverse engineering
- **State Laws**: Many states have additional computer crime statutes
- **GDPR/CCPA**: Exposed secrets may contain personal data subject to privacy regulations

### Acceptable Use
- Auditing your own Docker images for leaked secrets
- CI/CD pipeline security scanning
- Authorized penetration testing with written scope
- Security education and training
- Checking base images before deployment

### Prohibited Use
- Scanning images you do not own without authorization
- Extracting and using secrets found in third-party images
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover leaked secrets in public images, follow responsible disclosure practices:
1. Report to the image owner/vendor privately
2. Allow reasonable time for remediation
3. Do not exploit or exfiltrate the secrets

## License

MIT
