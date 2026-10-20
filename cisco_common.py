"""Shared pieces of the Cisco helpers: the read-only guard (validate_show), secret masking and MAC parsing."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from typing import Any

# Greedy ".*" so the LAST keyword on the line is used, e.g. "message-digest-key 1 md5 7 <secret>".
SECRET_LINE = re.compile(
    r"(?i)^(.*\b(?:secret|password|key-string|key|community|server-key|pre-shared-key|auth-key|"
    r"authentication-key|md5)\b(?:\s+[0-9]{1,2})?\s+)(?!Management\b)(\S+)(.*)$"  # not "Auth Key Management"
)
DESCRIPTION_LINE = re.compile(r"^\s*description\s", re.I)
# WLAN PSKs: "security wpa psk set-key ascii 8 <key>", MPSK "priority 0 set-key ascii 0 <key>".
SET_KEY_LINE = re.compile(r"(?i)^(.*\bset-key\s+(?:ascii|hex)\s+\d+\s+)(\S+)(.*)$")
# Pipes that write files or change state are never allowed.
FORBIDDEN_PIPES = re.compile(r"\|\s*(redirect|tee|append|copy)\b", re.I)


class CiscoError(Exception):
    """Bad command or target (never contains credentials)."""


def validate_show(command: str) -> str:
    """Allow only a single read-only `show` command."""
    command = command.strip()
    if "\n" in command or "\r" in command:
        raise CiscoError("only one command at a time")
    if not re.match(r"^show\s+\S", command, re.I):
        raise CiscoError(f"only 'show' commands are allowed: {command!r}")
    if FORBIDDEN_PIPES.search(command):
        raise CiscoError(f"output redirection is not allowed: {command!r}")
    return command


def mask_secrets(text: str) -> str:
    """Replace passwords, keys, communities and hashes in config output with <removed>."""
    def mask(line: str) -> str:
        if DESCRIPTION_LINE.match(line):
            return line
        m = SET_KEY_LINE.match(line) or SECRET_LINE.match(line)
        return m.group(1) + "<removed>" + m.group(3) if m else line

    return "\n".join(mask(line) for line in text.splitlines())


def parse_mac(text: str) -> str | None:
    """aabb.ccdd.eeff for a MAC in any common format (aa:bb:.., aa-bb-.., aabb.ccdd.eeff), else None."""
    if not re.fullmatch(r"[0-9a-fA-F:.\-]{12,17}", text.strip()):
        return None
    hexes = re.sub(r"[^0-9a-fA-F]", "", text).lower()
    return f"{hexes[0:4]}.{hexes[4:8]}.{hexes[8:12]}" if len(hexes) == 12 else None


def mac_formats(cisco_mac: str) -> dict[str, str]:
    """aabb.ccdd.eeff -> {'cisco': ..., 'colon': 'aa:bb:cc:dd:ee:ff'}."""
    hexes = re.sub(r"[^0-9a-f]", "", cisco_mac.lower())
    return {"cisco": cisco_mac.lower(), "colon": ":".join(hexes[i:i + 2] for i in range(0, 12, 2))}


# -- optional on-disk cache of show output (--cache SECONDS), for big WLC client lists ---------------------
CACHE_TTL = 0  # seconds; 0 = always ask the device
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")  # in .gitignore


def send(conn: Any, command: str, timeout: int) -> str:
    """validate_show(command), send it on a netmiko connection, and reuse output younger than CACHE_TTL seconds
    (the cache is one JSON file per host in .cache/; show output only, never credentials)."""
    command = validate_show(command)
    path = os.path.join(CACHE_DIR, re.sub(r"[^\w.-]", "_", str(conn.host)) + ".json")
    cache: dict[str, list] = {}
    if CACHE_TTL > 0:
        try:
            with open(path, encoding="utf-8") as fh:
                cache = json.load(fh)
        except (OSError, ValueError):
            cache = {}
        hit = cache.get(command)
        if hit and time.time() - hit[0] < CACHE_TTL:
            return hit[1]
    output = conn.send_command(command, read_timeout=timeout * 4)
    if CACHE_TTL > 0:
        cache[command] = [time.time(), output]
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    return output

def parent_interface(name: str) -> str:
    """GigabitEthernet0/0/1.110 -> GigabitEthernet0/0/1."""
    return name.split(".")[0]


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False
