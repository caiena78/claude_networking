"""Shared output and formatting code for the *_helper.py scripts.

    from helper_common import table, dig, to_json, Out, mac_colon, mac_cisco

- table(rows, ["name", "ip=primary_ip.address"], width=60): a text table. A column is a dotted path into each
  row, optionally named "label=path". Lists are joined with spaces, dicts shown as k:v, floats trimmed.
- to_json(data): indented JSON (pass mask= to scrub secrets first).
- Out: collects what a command prints so "-o FILE [--append]" can also save it.
- mac_colon / mac_cisco: a MAC in any common format -> aa:bb:cc:dd:ee:ff / aabb.ccdd.eeff (None if not a MAC).
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Callable


def dig(item: Any, path: str) -> Any:
    """item["a"]["b"] for path "a.b"; None when any step is missing."""
    for part in path.split("."):
        if not isinstance(item, dict):
            return None
        item = item.get(part)
    return item


def cell(value: Any, width: int = 60) -> str:
    """One table cell: lists joined, dicts as k:v, floats trimmed, newlines removed, long text cut."""
    if value is None:
        text = ""
    elif isinstance(value, list):
        text = " ".join(json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v) for v in value)
    elif isinstance(value, dict):
        text = " ".join(f"{k}:{v}" for k, v in sorted(value.items()))
    elif isinstance(value, float):
        text = f"{value:.2f}".rstrip("0").rstrip(".")
    else:
        text = str(value)
    text = text.replace("\n", " ")
    return text if len(text) <= width else text[:width - 3] + "..."


def table(rows: list[dict], columns: list[str], width: int = 60, mask: Callable[[Any], Any] | None = None) -> str:
    """A text table. A column is a dotted path into each row, optionally named "label=path"."""
    if not rows:
        return "(none)"
    specs = [c.split("=", 1) if "=" in c else [c, c] for c in columns]
    body = [[cell(dig(mask(r) if mask else r, path), width) for _, path in specs] for r in rows]
    labels = [label for label, _ in specs]
    widths = [max(len(x) for x in col) for col in zip(labels, *body)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*labels).rstrip(), fmt.format(*("-" * w for w in widths))]
    lines += [fmt.format(*r).rstrip() for r in body]
    return "\n".join(lines)


def to_json(data: Any, mask: Callable[[Any], Any] | None = None) -> str:
    return json.dumps(mask(data) if mask else data, indent=2, default=str)


class Out:
    """Collects what a command prints so -o FILE can also save it."""

    def __init__(self) -> None:
        self.chunks: list[str] = []

    def add(self, text: str) -> None:
        print(text)
        self.chunks.append(text)

    def section(self, title: str, body: str) -> None:
        self.add(f"===== {title}\n{body}\n")

    def text(self) -> str:
        return "\n".join(self.chunks) + "\n"

    def save(self, path: str | None, append: bool = False) -> None:
        if not path:
            return
        with open(path, "a" if append else "w", encoding="utf-8") as fh:
            fh.write(self.text())
        print(f"{'Appended to' if append else 'Wrote'} {path}", file=sys.stderr)


def _hex12(text: str) -> str | None:
    text = (text or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F:.\-]{12,17}", text):
        return None
    hexes = re.sub(r"[^0-9a-fA-F]", "", text).lower()
    return hexes if len(hexes) == 12 else None


def mac_colon(text: str) -> str | None:
    h = _hex12(text)
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if h else None


def mac_cisco(text: str) -> str | None:
    h = _hex12(text)
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}" if h else None


def is_mac(text: str) -> bool:
    return _hex12(text) is not None
