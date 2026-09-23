> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# CL3 — Docker Secret-Leak Detector

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/cl3-docker-leak)
![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/cl3-docker-leak)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/cl3-docker-leak)

**Docker container secret-leak scanner** — detects hardcoded secrets, env-var exposure, layer-level credentials, and dangerous Dockerfile patterns (chmod 777, pipe-to-shell) across image layers, with per-finding risk reports.

## Why

Docker images leak secrets every day: base images are copied between teams and private keys, API tokens, and connection strings ride along in environment variables, labels, and build layers. CL3 audits container images the way a **cloud-security** reviewer should — scanning configs, env, labels, entrypoints, and every layer history for credential exposure and dangerous instruction patterns. It works fully offline against bundled fixtures (no Docker daemon required for the demo), and the live path only touches images **you own or are authorized to scan**. Findings carry severity, rule ID, and remediation guidance for CI/CD integration.

## Features

- **Secret detection** — 15+ regex patterns: AWS keys, JWT, SSH keys, tokens, passwords.
- **Environment analysis** — flags sensitive env vars with masked values.
- **Layer analysis** — scans each image-layer command for embedded secrets.
- **Dockerfile parsing** — detects dangerous patterns from build history (WORLD_WRITABLE, PIPE_TO_SHELL, PRIVILEGED, REMOTE_ADD, USER_ADD, UNNECESSARY_TOOLS).
- **Sensitive-file detection** — COPY of `.env`, `id_rsa`, `credentials`, `*.pem`, `*.key`.
- **Risk scoring** — 0–100 score based on findings; `--exit-code-on-findings` gates CI (exit `2`).
- **JSON export** — machine-readable reports for other tools.

## Quickstart

```bash
# Offline demo (no Docker daemon) against bundled fixtures
python3 docker_leak.py --demo

# Audit a custom fixtures file (offline)
python3 docker_leak.py --fixtures fixtures/docker-images.json

# JSON report + CI exit code (2 = CRITICAL/HIGH findings present)
python3 docker_leak.py --demo --output reports/cl3-report.json --exit-code-on-findings; echo $?

# Live scan of your own images (requires running Docker daemon)
python3 docker_leak.py nginx:latest python:3.11
python3 docker_leak.py --all-local
```

Exit codes: `0` clean, `1` error, `2` CRITICAL/HIGH findings with `--exit-code-on-findings`.

```bash
# Run the offline test suite
python3 -m unittest discover -s tests -v
```

## Project structure

```
cl3-docker-leak/
├── docker_leak.py        # main scanner (stdlib only)
├── fixtures/             # offline image-metadata/Dockerfile fixtures
├── tests/                # unittest suite (16 tests)
└── ETHICS.md, SCOPE.md   # authorized-use rules
```

## Documentation

- [ETHICS.md](ETHICS.md) — authorized-use policy
- [SCOPE.md](SCOPE.md) — audit scope
- [SECURITY.md](SECURITY.md) — security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Scan only images you own or are authorized to audit.

## License

MIT. See [LICENSE](LICENSE).