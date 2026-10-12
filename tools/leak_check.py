"""Stop internal addresses and secrets from being committed to this (public) repo.

    python tools/leak_check.py            # check staged changes (what the pre-commit hook runs)
    python tools/leak_check.py --all      # check every tracked file (CI, or a one-off audit)

What counts as a leak:
  1. Any value from YOUR .env that identifies internal infrastructure: the Vault address and host, the CDO tenant
     URL and host, every IP in FTD_CAPTURE_HOSTS, and any other value that is an IP, URL or host name.
  2. Any of YOUR personal secrets that are set in the environment: CDO_API, CDO_UUID, CISCO_SRV_PWD,
     CISCO_SRV_ACCOUNT, VAULT_TOKEN (only their presence in a file is checked; they are never printed).
  3. Generic secret patterns: private keys, Vault tokens (hvs.), bearer tokens, AWS keys, and quoted
     password/secret/token/api_key assignments.

A line can opt out with the comment "leak-check: ignore" (use sparingly). Found values are shown masked.
Exit code 1 if anything is found.

Enable the hook once per clone:   git config core.hooksPath .githooks
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
SKIP_KEYS = {"VAULT_MOUNT", "VAULT_PATH", "LCMC_CACERT", "ISE_CACERT", "CAT_CACERT", "VAULT_CACERT"}
PERSONAL = ("CDO_API", "CDO_UUID", "CISCO_SRV_PWD", "CISCO_SRV_ACCOUNT", "VAULT_TOKEN")
PATTERNS = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Vault token", re.compile(r"\bhvs\.[A-Za-z0-9_-]{20,}")),
    ("bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{24,}=*")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("hard-coded secret", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*[\"'][^\"'\s{}$<>]{6,}[\"']")),
]
BINARY = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".xlsx", ".zip", ".gz", ".pem", ".pyc"}
IGNORE = "leak-check: ignore"
# Placeholder ranges used in docs (RFC 5737 / 3849) never count as leaks.
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _mask(value: str) -> str:
    return value[:3] + "*" * min(12, max(3, len(value) - 3)) if len(value) > 3 else "***"


def env_values() -> list[tuple[str, str]]:
    """(label, value) pairs from .env and the personal environment variables that must not be committed."""
    found: list[tuple[str, str]] = []
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
            if not m or m.group(1) in SKIP_KEYS or not m.group(2):
                continue
            key, value = m.group(1), m.group(2).strip("'\"")
            for token in filter(None, re.split(r"[,;\s]+", value)):
                token = token.split("=", 1)[0]  # FTD_CAPTURE_HOSTS ip=label: the IP is the sensitive part
                if token.startswith(("http://", "https://")):
                    found.append((f".env {key}", token))
                    host = urlparse(token).hostname
                    if host:
                        found.append((f".env {key} host", host))
                elif _is_ip(token) or re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", token):
                    found.append((f".env {key}", token))
    for key in PERSONAL:
        value = os.environ.get(key, "")
        if len(value) >= 6:
            found.append((f"env {key}", value))
    return found


def _is_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not any(ip in n for n in DOC_NETS)


def files_to_check(all_files: bool) -> list[tuple[str, str]]:
    """(path, content) of staged files (default) or every tracked file."""
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", check=True).stdout

    if all_files:
        paths = git("ls-files").splitlines()
        read = lambda p: (ROOT / p).read_text(encoding="utf-8", errors="replace")  # noqa: E731
    else:
        paths = git("diff", "--cached", "--name-only", "--diff-filter=ACMR").splitlines()
        read = lambda p: git("show", f":{p}")  # noqa: E731 - the staged version, not the working copy
    out = []
    for p in paths:
        if Path(p).suffix.lower() in BINARY or p.startswith("tools/leak_check.py"):
            continue
        try:
            out.append((p, read(p)))
        except (OSError, subprocess.CalledProcessError):
            continue
    return out


def scan(files: list[tuple[str, str]], values: list[tuple[str, str]]) -> list[str]:
    problems = []
    exact = [(label, v, re.compile(r"(?<![\w.])" + re.escape(v) + r"(?![\w])")) for label, v in values]
    for path, text in files:
        for n, line in enumerate(text.splitlines(), 1):
            if IGNORE in line:
                continue
            for label, value, rx in exact:
                if rx.search(line):
                    problems.append(f"{path}:{n}: {label} value {_mask(value)}")
            for name, rx in PATTERNS:
                m = rx.search(line)
                if m:
                    problems.append(f"{path}:{n}: {name} {_mask(m.group(0))}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description="Block internal addresses and secrets from being committed.")
    ap.add_argument("--all", action="store_true", help="check every tracked file instead of staged changes")
    args = ap.parse_args()
    problems = scan(files_to_check(args.all), env_values())
    if problems:
        print("LEAK CHECK FAILED - these would publish internal addresses or secrets:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print("Replace them with placeholders (192.0.2.x, <vault-host>, ...) or move them to .env.\n"
              "If a line is a false positive, add the comment 'leak-check: ignore' to it.", file=sys.stderr)
        return 1
    print(f"leak check: ok ({'all tracked files' if args.all else 'staged changes'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
