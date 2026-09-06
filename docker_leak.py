#!/usr/bin/env python3
"""CL3 — Docker Secret Leaker.

Scans Docker images for hardcoded secrets, extracts environment variables,
analyzes layers for sensitive data, and generates risk reports.
Uses only standard library.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


class DockerSecretScanner:
    """Scan Docker images for secrets and sensitive data."""

    # Regex patterns for secret detection
    SECRET_PATTERNS = {
        "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "aws_secret_key": re.compile(r"(?:aws_secret_access_key|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "private_key_begin": re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
        "generic_api_key": re.compile(r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?", re.IGNORECASE),
        "generic_secret": re.compile(r"(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]?(\S{8,})['\"]?", re.IGNORECASE),
        "generic_token": re.compile(r"(?:token|auth_token|access_token)\s*[=:]\s*['\"]?([A-Za-z0-9\-_\.]{20,})['\"]?", re.IGNORECASE),
        "connection_string": re.compile(r"(?:mongodb|mysql|postgres|redis|amqp)://\S+", re.IGNORECASE),
        "docker_env_secret": re.compile(r"(?:DOCKER_|KUBERNETES_).*(?:SECRET|PASSWORD|TOKEN|KEY)", re.IGNORECASE),
        "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
        "base64_long": re.compile(r"(?:eyJ|YWxh|Um9v)[A-Za-z0-9+/]{40,}={0,2}"),
        "ssh_rsa_pub": re.compile(r"ssh-rsa\s+AAAA[A-Za-z0-9+/]{100,}"),
        "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "slack_token": re.compile(r"xox[baprs]-[0-9]{10,}-[A-Za-z0-9\-]+"),
        "stripe_key": re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
        "gcp_key": re.compile(r"type\s*:\s*service_account"),
    }

    SENSITIVE_ENV_VARS = {
        "password", "passwd", "pwd", "secret", "api_key", "apikey",
        "api-key", "access_key", "access-key", "token", "auth_token",
        "auth-token", "private_key", "private-key", "database_url",
        "database-url", "db_password", "db-password", "redis_url",
        "redis-url", "aws_secret_access_key", "aws_access_key_id",
        "smtp_password", "mail_password", "encryption_key",
        "signing_key", "jwt_secret", "session_secret",
    }

    def __init__(self, docker_bin: str = "docker"):
        self.docker_bin = docker_bin

    def _check_docker(self):
        """Verify Docker is available."""
        try:
            result = subprocess.run(
                [self.docker_bin, "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                print(f"[!] Docker returned non-zero exit code")
        except FileNotFoundError:
            print(f"[!] Docker binary '{self.docker_bin}' not found")
            print("[!] Install Docker or specify path with --docker-bin")
        except subprocess.TimeoutExpired:
            print("[!] Docker version check timed out")

    def _run(self, args: list[str], timeout: int = 60) -> tuple[int, str, str]:
        """Run a docker command."""
        try:
            result = subprocess.run(
                [self.docker_bin] + args,
                capture_output=True, text=True, timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as exc:
            return -1, "", str(exc)

    def _run_inspect(self, image: str) -> dict | None:
        """Inspect a Docker image."""
        code, stdout, stderr = self._run(["inspect", image])
        if code != 0:
            print(f"[!] Cannot inspect {image}: {stderr}")
            return None
        try:
            data = json.loads(stdout)
            return data[0] if isinstance(data, list) and data else data
        except json.JSONDecodeError:
            return None

    def _get_history(self, image: str) -> list[dict]:
        """Get image layer history."""
        code, stdout, stderr = self._run(["history", image, "--no-trunc", "--format", "json"])
        if code != 0:
            return []
        layers = []
        for line in stdout.strip().split("\n"):
            if line.strip():
                try:
                    layers.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return layers

    # ── Secret scanning ──────────────────────────────────────────────

    def scan_text(self, text: str, source: str = "") -> list[dict]:
        """Scan text content for secrets."""
        findings = []
        for name, pattern in self.SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                secret = match.group(0) if not match.groups() else match.group(1)
                # Mask the secret value
                masked = secret[:4] + "*" * max(0, len(secret) - 8) + secret[-4:] if len(secret) > 8 else "****"
                findings.append({
                    "type": name,
                    "masked_value": masked,
                    "source": source,
                    "line": text[:match.start()].count("\n") + 1,
                })
        return findings

    def scan_layer_command(self, command: str, layer_index: int) -> list[dict]:
        """Scan a RUN/COPY command for embedded secrets."""
        findings = self.scan_text(command, source=f"layer_{layer_index}_command")
        if command.upper().startswith("ENV") or "=" in command:
            for match in re.finditer(r"([A-Z_]+)=(\S+)", command):
                var_name = match.group(1)
                var_value = match.group(2)
                if any(s in var_name.lower() for s in self.SENSITIVE_ENV_VARS):
                    findings.append({
                        "type": "env_in_command",
                        "variable": var_name,
                        "masked_value": var_value[:4] + "****" if len(var_value) > 4 else "****",
                        "source": f"layer_{layer_index}",
                    })
        return findings

    # ── Image analysis ───────────────────────────────────────────────

    def analyze_env_vars(self, image: str) -> dict:
        """Extract and analyze environment variables from image."""
        info = self._run_inspect(image)
        if not info:
            return {"error": "Cannot inspect image"}

        config = info.get("Config", {})
        env_vars = config.get("Env", [])

        result = {
            "total_env_vars": len(env_vars),
            "sensitive": [],
            "all_vars": [],
        }

        for env_str in env_vars:
            if "=" in env_str:
                key, _, value = env_str.partition("=")
                is_sensitive = any(s in key.lower() for s in self.SENSITIVE_ENV_VARS)
                entry = {"variable": key, "sensitive": is_sensitive}
                if is_sensitive:
                    masked = value[:4] + "****" if len(value) > 4 else "****"
                    entry["masked_value"] = masked
                    entry["reason"] = "Matches sensitive variable pattern"
                    result["sensitive"].append(entry)
                result["all_vars"].append(entry)

        return result

    def analyze_secrets(self, image: str) -> dict:
        """Scan image inspect data for secrets."""
        info = self._run_inspect(image)
        if not info:
            return {"error": "Cannot inspect image"}

        findings = []
        config = info.get("Config", {})

        # Scan env vars
        for env_str in config.get("Env", []):
            findings.extend(self.scan_text(env_str, source="env_var"))

        # Scan cmd
        cmd = config.get("Cmd", [])
        if cmd:
            findings.extend(self.scan_text(" ".join(cmd), source="cmd"))

        # Scan entrypoint
        entrypoint = config.get("Entrypoint", [])
        if entrypoint:
            findings.extend(self.scan_text(" ".join(entrypoint), source="entrypoint"))

        # Scan labels
        for key, val in config.get("Labels", {}).items():
            findings.extend(self.scan_text(f"{key}={val}", source="label"))

        # Scan exposed ports
        for port in config.get("ExposedPorts", {}):
            findings.extend(self.scan_text(port, source="exposed_port"))

        return {"findings": findings, "total": len(findings)}

    def analyze_layers(self, image: str) -> dict:
        """Analyze each image layer for secrets."""
        layers = self._get_history(image)
        result = {"layers": [], "total_secrets": 0}

        for i, layer in enumerate(layers):
            created_by = layer.get("createdBy", "")
            layer_info = {
                "index": i,
                "created_by": created_by[:200],
                "size": layer.get("size", 0),
                "findings": [],
            }

            # Scan the command itself
            layer_info["findings"].extend(self.scan_layer_command(created_by, i))

            # Check for inline secret assignment
            if "=" in created_by:
                parts = created_by.split()
                for part in parts:
                    layer_info["findings"].extend(self.scan_text(part, source=f"layer_{i}_token"))

            result["total_secrets"] += len(layer_info["findings"])
            result["layers"].append(layer_info)

        return result

    def analyze_dockerfile_secrets(self, image: str) -> dict:
        """Extract potential Dockerfile instructions from layers."""
        layers = self._get_history(image)
        instructions = []
        for i, layer in enumerate(layers):
            created = layer.get("createdBy", "")
            instruction = {
                "layer": i,
                "command": created[:500],
                "has_add": "/bin/sh -c #(nop) ADD" in created or created.startswith("ADD"),
                "has_copy": "/bin/sh -c #(nop) COPY" in created or created.startswith("COPY"),
                "has_run": created.startswith("RUN") or "/bin/sh -c" in created,
            }
            # Flag dangerous patterns
            if "chmod 777" in created:
                instruction["warning"] = "chmod 777 — world-writable"
            elif "curl" in created and ("| sh" in created or "| bash" in created):
                instruction["warning"] = "Pipe to shell — supply chain risk"
            elif "--privileged" in created:
                instruction["warning"] = "Privileged mode"
            instructions.append(instruction)
        return {"instructions": instructions}

    # ── Full scan ────────────────────────────────────────────────────

    def scan_image(self, image: str) -> dict:
        """Perform full security scan on a Docker image."""
        print(f"\n{'='*60}")
        print(f"  Scanning Docker Image: {image}")
        print(f"{'='*60}")

        results = {"image": image}

        # Image info
        info = self._run_inspect(image)
        if info:
            results["id"] = info.get("Id", "")[:20]
            results["created"] = info.get("Created", "")
            results["os"] = info.get("Os", "")
            results["architecture"] = info.get("Architecture", "")
            size_mb = info.get("Size", 0) / (1024 * 1024)
            print(f"  ID:              {results['id']}")
            print(f"  Created:         {results['created'][:19]}")
            print(f"  OS/Arch:         {results['os']}/{results['architecture']}")
            print(f"  Size:            {size_mb:.1f} MB")
        else:
            print(f"  [!] Cannot inspect image")
            return results

        # Env vars
        env_result = self.analyze_env_vars(image)
        results["env_vars"] = env_result
        sensitive_count = len(env_result.get("sensitive", []))
        print(f"  Env Vars:        {env_result.get('total_env_vars', 0)} total, {sensitive_count} sensitive")
        for s in env_result.get("sensitive", []):
            print(f"    ⚠  {s['variable']} = {s.get('masked_value', '****')}")

        # Secrets in config
        secrets = self.analyze_secrets(image)
        results["secrets"] = secrets
        print(f"  Config Secrets:  {secrets['total']}")
        for f in secrets.get("findings", []):
            print(f"    ⚠  {f['type']}: {f.get('masked_value', '****')} (in {f['source']})")

        # Layer analysis
        layer_result = self.analyze_layers(image)
        results["layers"] = layer_result
        print(f"  Layers:          {len(layer_result.get('layers', []))}")
        print(f"  Layer Secrets:   {layer_result['total_secrets']}")
        for layer in layer_result.get("layers", []):
            if layer["findings"]:
                print(f"    Layer {layer['index']}: {len(layer['findings'])} findings")

        # Dockerfile analysis
        df_result = self.analyze_dockerfile_secrets(image)
        results["dockerfile"] = df_result
        warnings = [i for i in df_result.get("instructions", []) if i.get("warning")]
        if warnings:
            print(f"  Dockerfile Warn: {len(warnings)}")
            for w in warnings:
                print(f"    ⚠  Layer {w['layer']}: {w['warning']}")

        # Risk score
        total_findings = (
            secrets["total"]
            + layer_result["total_secrets"]
            + sensitive_count
            + len(warnings)
        )
        risk_score = min(total_findings * 10, 100)
        risk_label = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 20 else "LOW"
        results["risk_score"] = risk_score
        print(f"  Risk Score:      {risk_score}/100 ({risk_label})")

        return results


def print_banner():
    banner = r"""
    ╔═══════════════════════════════════════════╗
    ║     CL3 — Docker Secret Leaker            ║
    ║     Standard Library · No Dependencies     ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)


# ---------------------------------------------------------------------------
# Offline fixture auditor
# ---------------------------------------------------------------------------

SENSITIVE_FILENAMES = (
    ".env", ".npmrc", ".pypirc", "id_rsa", "id_dsa", "id_ecdsa",
    "credentials", ".htpasswd", "*.pem", "*.key", "*.p12", "*.pfx",
    "kubeconfig", ".dockercfg", "config.json", "secrets", "secret",
)

DANGEROUS_PATTERNS = [
    (re.compile(r"chmod\s+777"), "WORLD_WRITABLE",
     "CRITICAL", "chmod 777 creates a world-writable file/directory."),
    (re.compile(r"(curl|wget)\s+\S+\s*\|\s*(sh|bash)"), "PIPE_TO_SHELL",
     "HIGH", "Piping a remote fetch into a shell executes untrusted code at build time."),
    (re.compile(r"--privileged"), "PRIVILEGED",
     "HIGH", "Privileged containers escape namespace isolation."),
    (re.compile(r"ADD\s+\S+://"), "REMOTE_ADD",
     "MEDIUM", "ADD with a remote URL is non-reproducible and can embed foreign content."),
    (re.compile(r"useradd|adduser"), "USER_ADD", "LOW",
     "USER_ADD — consider an explicit user for runtime (USER directive)."),
    (re.compile(r"apt(-get)?\s+install\b[^\n]*\b(?:sudo|curl|wget|tcpdump|nc|nmap)"),
     "UNNECESSARY_TOOLS", "LOW", "Build tools such as curl/nc in runtime images enlarge attack surface."),
]


class OfflineDockerAuditor:
    """Detect secrets and dangerous Dockerfile patterns from realistic
    image-metadata / Dockerfile fixtures without a Docker daemon."""

    def audit(self, images):
        findings = []
        for image in images:
            name = image.get("name", image.get("id", "unknown-image"))
            findings.extend(self._audit_config(name, image.get("config", {})))
            findings.extend(self._audit_history(name, image.get("history", [])))
            findings.extend(self._audit_dockerfile(name, image.get("dockerfile", "")))
        return findings

    def _audit_config(self, name, config):
        findings = []
        for env_str in config.get("Env", []):
            for f in DockerSecretScanner().scan_text(env_str, source="env_var"):
                findings.append(_to_finding(name, f, "config_env",
                                            f"Environment variable contains a {f['type']}.",
                                            "Pass secrets via Docker secrets / a secrets manager; never bake "
                                            "them into image ENV."))
            key = env_str.partition("=")[0]
            if "=" in env_str and any(s in key.lower() for s in DockerSecretScanner.SENSITIVE_ENV_VARS):
                findings.append(_to_finding(name, None, "sensitive_env",
                                            f"Sensitive environment variable '{key}' is embedded in the image.",
                                            "Use runtime-injected secrets instead of image ENV."))
        cmd = " ".join(config.get("Cmd", [])) + " " + " ".join(config.get("Entrypoint", []))
        for f in DockerSecretScanner().scan_text(cmd, source="cmd"):
            findings.append(_to_finding(name, f, "config_cmd",
                                        f"Command/entrypoint embeds a {f['type']}.",
                                        "Remove credentials from CMD/ENTRYPOINT arguments."))
        for key, val in config.get("Labels", {}).items():
            for f in DockerSecretScanner().scan_text(f"{key}={val}", source="label"):
                findings.append(_to_finding(name, f, "config_label",
                                            f"Image label contains a {f['type']}.",
                                            "Labels are visible to anyone pulling the image; remove secrets."))
        return findings

    def _audit_history(self, name, history):
        findings = []
        scanner = DockerSecretScanner()
        for i, layer in enumerate(history or []):
            created_by = layer.get("createdBy", "") or layer.get("created_by", "")
            for f in scanner.scan_layer_command(created_by, i):
                findings.append(_to_finding(name, f, "layer_command",
                                            f"Build layer {i} command embeds a {f.get('type', 'secret')}.",
                                            "Remove credentials from build instructions; use build-time ARGs "
                                            "with defaults or a secrets backend."))
        return findings

    def _audit_dockerfile(self, name, dockerfile):
        findings = []
        if not dockerfile:
            return findings
        for lineno, line in enumerate(dockerfile.splitlines(), start=1):
            stripped = line.strip()
            upper = stripped.upper()
            for pat, rule_id, severity, message in DANGEROUS_PATTERNS:
                if pat.search(line):
                    findings.append(_to_finding(name, None, rule_id,
                                                f"Dockerfile line {lineno}: {message}",
                                                "Rewrite the instruction to avoid the flagged construct."))
            if upper.startswith("COPY") or upper.startswith("ADD"):
                for frag in SENSITIVE_FILENAMES:
                    if frag.startswith("*"):
                        if frag[1:] in line:
                            findings.append(_to_finding(name, None, "SENSITIVE_COPY",
                                                        f"Dockerfile line {lineno}: COPY/ADD references "
                                                        f"sensitive file pattern '{frag}'.",
                                                        "Do not copy secret files into the image; mount or "
                                                        "inject them at runtime."))
                    elif regex_match_frag(line, frag):
                        findings.append(_to_finding(name, None, "SENSITIVE_COPY",
                                                    f"Dockerfile line {lineno}: COPY/ADD includes "
                                                    f"'{frag}' which typically holds credentials.",
                                                    "Keep secret material out of image layers."))
            if upper.startswith("ENV"):
                for f in DockerSecretScanner().scan_text(line, source="dockerfile_env"):
                    findings.append(_to_finding(name, f, "dockerfile_env",
                                                f"Dockerfile line {lineno}: ENV embeds a "
                                                f"{f['type']}.",
                                                "Use ARG/buildkit secrets or runtime injection."))
        return findings


def regex_match_frag(line, frag):
    """Return True when frag appears as a non-prefixed filename token."""
    if frag.startswith("*"):
        return False
    return re.search(r"(^|[\s/])" + re.escape(frag) + r"(\s|$)", line) is not None


def _to_finding(image, raw, category, message, remediation):
    return {
        "severity": "CRITICAL" if category in (
            "config_env", "config_cmd", "config_label", "sensitive_env",
            "SENSITIVE_COPY", "WORLD_WRITABLE") else "HIGH"
        if category in ("PIPE_TO_SHELL", "PRIVILEGED", "layer_command") else "MEDIUM",
        "category": category,
        "rule_id": "CL3-" + category,
        "image": image,
        "resource": f"docker://{image}",
        "message": message,
        "remediation": remediation,
        "masked_value": (raw or {}).get("masked_value", None),
    }


def load_image_fixtures(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise FileNotFoundError(f"Fixtures file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in fixtures file {path}: {exc}") from exc
    if isinstance(data, dict):
        return data.get("images", [])
    if isinstance(data, list):
        return data
    raise ValueError(f"Unsupported fixture structure in {path}")


def print_offline_report(images, findings):
    print("\n" + "=" * 64)
    print("  CL3 — Docker Offline Secret & Dockerfile Audit")
    print("=" * 64)
    print(f"  Images audited:  {len(images)}")
    print(f"  Findings:        {len(findings)}")
    print("=" * 64)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in counts:
            print(f"    {sev:9s}: {counts[sev]}")
    print()
    for f in findings:
        print(f"  [{f['severity']:8s}] {f['rule_id']} {f['image']}")
        print(f"      {f['message']}")
        print(f"      Fix: {f['remediation']}")
    print("\n" + "=" * 64 + "\n")


def write_report(report, output_path):
    parent = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(parent, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
    print(f"[+] JSON report written to {output_path}")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Docker Image Secret Scanner")
    parser.add_argument("images", nargs="*", help="Docker images to scan (live, requires docker daemon)")
    parser.add_argument("--docker-bin", default="docker", help="Path to docker binary")
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo against bundled fixture (no Docker daemon)")
    parser.add_argument("--fixtures", default="",
                        help="Path to image-metadata/Dockerfile fixtures JSON (offline audit)")
    parser.add_argument("--output", "-o", default="", help="JSON output file")
    parser.add_argument("--all-local", action="store_true", help="Scan all local images")
    parser.add_argument("--list-images", action="store_true", help="List local images")
    parser.add_argument("--exit-code-on-findings", action="store_true",
                        help="Exit 2 when CRITICAL/HIGH findings exist (CI-friendly)")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    if args.demo or args.fixtures or not (args.images or args.all_local or args.list_images):
        fixture = args.fixtures or os.path.join(base_dir, "fixtures", "docker-images.json")
        if not os.path.isfile(fixture):
            print(f"[!] Fixture not found: {fixture}. Run --demo from the repo root.", file=sys.stderr)
            return 1
        print(f"[*] Offline mode — auditing fixtures: {fixture}")
        try:
            images = load_image_fixtures(fixture)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        findings = OfflineDockerAuditor().audit(images)
        print_offline_report(images, findings)
        report = {
            "tool": "CL3-DockerLeakOfflineAuditor",
            "mode": "offline-fixture",
            "finding_count": len(findings),
            "summary": {},
            "findings": findings,
        }
        for f in findings:
            report["summary"][f["severity"]] = report["summary"].get(f["severity"], 0) + 1
        output = args.output or os.path.join(base_dir, "reports", "cl3-report.json")
        write_report(report, output)
        if args.exit_code_on_findings and any(f["severity"] in ("CRITICAL", "HIGH") for f in findings):
            return 2
        return 0

    scanner = DockerSecretScanner(args.docker_bin)
    all_results = []

    images_to_scan = list(args.images)

    if args.list_images or args.all_local:
        code, stdout, _ = scanner._run(["images", "--format", "{{.Repository}}:{{.Tag}}"])
        if code == 0:
            for line in stdout.strip().split("\n"):
                line = line.strip()
                if line and line != "<none>:<none>":
                    if args.all_local:
                        images_to_scan.append(line)
                    else:
                        print(f"  {line}")

    if not images_to_scan:
        print("[!] No images specified. Use --all-local or provide image names.")
        print("[!] Example: python3 docker_leak.py nginx:latest python:3.11")
        parser.print_help()
        return 1

    for image in images_to_scan:
        result = scanner.scan_image(image)
        all_results.append(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n[+] Results saved to {args.output}")

    # Summary
    total_risks = sum(1 for r in all_results if r.get("risk_score", 0) >= 50)
    total_secrets = sum(r.get("secrets", {}).get("total", 0) for r in all_results)
    print(f"\n{'='*60}")
    print(f"  Summary: {len(all_results)} images scanned, {total_secrets} secrets found, {total_risks} high-risk")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
