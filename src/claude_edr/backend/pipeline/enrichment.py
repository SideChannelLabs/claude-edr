"""Event enrichment pipeline stage.

Adds context to raw sensor events: classifies file sensitivity,
resolves network addresses, assigns base risk scores.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from claude_edr.backend.models.events import EDREvent, Severity

# Sensitive file path patterns and their severity
SENSITIVE_PATHS: list[tuple[str, Severity, str]] = [
    (r".*\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts|config)$", Severity.CRITICAL, "SSH key/config"),
    (r".*\.aws/credentials$", Severity.CRITICAL, "AWS credentials"),
    (r".*\.aws/config$", Severity.HIGH, "AWS config"),
    (r".*\.kube/config$", Severity.CRITICAL, "Kubernetes config"),
    (r".*\.env(\.[a-zA-Z]+)?$", Severity.HIGH, "Environment file"),
    (r".*\.npmrc$", Severity.HIGH, "NPM config (may contain tokens)"),
    (r".*\.pypirc$", Severity.HIGH, "PyPI config (may contain tokens)"),
    (r".*\.netrc$", Severity.CRITICAL, "Netrc credentials"),
    (r".*\.git-credentials$", Severity.CRITICAL, "Git credentials"),
    (r".*\.docker/config\.json$", Severity.HIGH, "Docker config"),
    (r".*/(secrets?|credentials?|tokens?|passwords?)(\.[a-z]+)?$", Severity.HIGH, "Secrets file"),
    (r".*/\.gnupg/.*$", Severity.HIGH, "GPG keyring"),
    (r"/etc/(passwd|shadow|sudoers)$", Severity.CRITICAL, "System auth file"),
    (r"/etc/.*\.(key|pem|crt)$", Severity.HIGH, "TLS certificate/key"),
]

SENSITIVE_PATH_COMPILED = [(re.compile(p), s, d) for p, s, d in SENSITIVE_PATHS]

# Dangerous command patterns
DANGEROUS_COMMANDS: list[tuple[str, Severity, str]] = [
    (r"curl\s.*\|\s*(ba)?sh", Severity.CRITICAL, "Curl pipe to shell"),
    (r"wget\s.*\|\s*(ba)?sh", Severity.CRITICAL, "Wget pipe to shell"),
    (r"rm\s+-rf\s+/", Severity.CRITICAL, "Recursive delete from root"),
    (r"rm\s+-rf\s+~", Severity.CRITICAL, "Recursive delete home"),
    (r"mkfs\.", Severity.CRITICAL, "Format filesystem"),
    (r"dd\s+if=.*/dev/", Severity.CRITICAL, "Raw disk write"),
    (r"chmod\s+777", Severity.HIGH, "World-writable permissions"),
    (r"chmod\s+\+s", Severity.CRITICAL, "Set SUID bit"),
    (r"nc\s+-[le]", Severity.HIGH, "Netcat listener (reverse shell)"),
    (r"python.*-c.*import\s+socket", Severity.HIGH, "Python reverse shell pattern"),
    (r"bash\s+-i\s+>&\s*/dev/tcp/", Severity.CRITICAL, "Bash reverse shell"),
    (r"git\s+push\s+.*--force", Severity.HIGH, "Force push"),
    (r"git\s+reset\s+--hard", Severity.MEDIUM, "Hard reset"),
    (r"docker\s+run\s+.*--privileged", Severity.HIGH, "Privileged container"),
    (r"base64\s+-d.*\|\s*(ba)?sh", Severity.CRITICAL, "Base64 decode to shell"),
    (r"eval\s+\$\(", Severity.HIGH, "Eval with command substitution"),
]

DANGEROUS_COMMANDS_COMPILED = [(re.compile(p), s, d) for p, s, d in DANGEROUS_COMMANDS]

# Known safe network destinations
KNOWN_SAFE_HOSTS = {
    "api.anthropic.com",
    "api.openai.com",
    "api.cursor.com",
    "copilot-proxy.githubusercontent.com",
    "api.codeium.com",
    "api.github.com",
    "github.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
}


def enrich_event(event: EDREvent) -> EDREvent:
    """Enrich an event with additional context and base risk scoring."""
    risk = 0.0

    # File sensitivity check
    if event.file and event.file.path:
        for pattern, severity, description in SENSITIVE_PATH_COMPILED:
            if pattern.match(event.file.path):
                event.severity = max(event.severity, severity, key=lambda s: s.value)
                risk = max(risk, severity.value * 25.0)
                break

        # Check if file is outside working directory
        if event.agent and event.agent.working_directory:
            try:
                file_path = PurePosixPath(event.file.path)
                work_dir = PurePosixPath(event.agent.working_directory)
                if not str(file_path).startswith(str(work_dir)):
                    risk += 10.0
            except (ValueError, TypeError):
                pass

    # Command danger check
    if event.process and event.process.cmdline:
        cmd = event.process.cmdline
        for pattern, severity, description in DANGEROUS_COMMANDS_COMPILED:
            if pattern.search(cmd):
                event.severity = max(event.severity, severity, key=lambda s: s.value)
                risk = max(risk, severity.value * 25.0)
                break

    # Network check
    if event.network:
        if event.network.domain and event.network.domain not in KNOWN_SAFE_HOSTS:
            risk += 15.0
        if event.network.remote_addr and not event.network.domain:
            # Direct IP connection (no domain) is suspicious
            risk += 20.0

    event.risk_score = min(risk, 100.0)
    return event
