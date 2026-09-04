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
# Scan a specific image
python3 docker_leak.py nginx:latest

# Scan multiple images
python3 docker_leak.py nginx:latest python:3.11 redis:alpine

# Scan all local images
python3 docker_leak.py --all-local

# List local images
python3 docker_leak.py --list-images

# Save results to JSON
python3 docker_leak.py nginx:latest --output results.json
```

## Example Output

```
  Scanning Docker Image: nginx:latest
============================================================
  ID:              sha256:abc123...
  Created:         2024-01-15T10:30:00
  OS/Arch:         linux/amd64
  Size:            187.3 MB
  Env Vars:        3 total, 1 sensitive
    ⚠  API_KEY = a3f8****
  Config Secrets:  0
  Layers:          12
  Layer Secrets:   1
    Layer 5: 1 findings
  Risk Score:      10/100 (LOW)
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

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
