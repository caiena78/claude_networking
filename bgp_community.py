"""List the BGP community each wan_router sets on the routes it advertises.

For every NetBox device tagged wan_router, runs one read-only command that pulls the BGP
neighbor outbound route-maps and their `set community` lines, then writes a table to
bgp_community.txt (site, router, router IP, community).

Usage:
    python bgp_community.py
    python bgp_community.py --site Lakeside --output other.txt
"""

from __future__ import annotations

import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
COMMAND = r"show running-config | include ^router bgp|^route-map|set community|neighbor .* route-map .* out"


def parse_communities(output: str) -> tuple[str, list[str]]:
    """Return (asn, communities set by the BGP outbound route-maps) from the filtered config."""
    asn = ""
    out_maps: set[str] = set()
    set_by_map: dict[str, list[str]] = {}
    current_map = None

    for line in output.splitlines():
        line = line.strip()
        if m := re.match(r"router bgp (\d+)", line):
            asn = m.group(1)
        elif m := re.match(r"neighbor \S+ route-map (\S+) out", line):
            out_maps.add(m.group(1))
        elif m := re.match(r"route-map (\S+) (permit|deny)", line):
            current_map = m.group(1)
        elif line.startswith("set community") and current_map:
            values = [v for v in line.split()[2:] if v not in ("additive",)]
            set_by_map.setdefault(current_map, []).extend(values)

    maps = out_maps or set(set_by_map)
    communities: list[str] = []
    for name in sorted(maps):
        for value in set_by_map.get(name, []):
            if value not in communities:
                communities.append(value)
    return asn, communities


def query_device(device: dict[str, Any], creds: dict[str, str], timeout: int) -> dict[str, Any]:
    """SSH to one router and return its BGP outbound communities. Never raises."""
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

    result: dict[str, Any] = {**device, "asn": "", "communities": [], "error": None}
    try:
        with ConnectHandler(
            device_type=device["device_type"], host=device["host"],
            username=creds["ansible_user"], password=creds["ansible_password"],
            secret=creds["ansible_become_password"],
            conn_timeout=timeout, auth_timeout=timeout, banner_timeout=timeout,
        ) as conn:
            if not conn.check_enable_mode():
                conn.enable()
            output = conn.send_command(COMMAND, read_timeout=timeout * 2)
        result["asn"], result["communities"] = parse_communities(output)
        if not result["communities"]:
            result["error"] = "no set community found in BGP outbound route-maps"
    except NetmikoAuthenticationException:
        result["error"] = "authentication failed"
    except NetmikoTimeoutException:
        result["error"] = "timed out / unreachable"
    except Exception as exc:  # noqa: BLE001 - one bad device must not stop the run
        result["error"] = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
    return result


def write_table(results: list[dict[str, Any]], path: Path) -> str:
    headers = ["Site", "Router", "Router IP", "BGP AS", "BGP Community"]
    rows = [
        [r["site"] or "-", r["name"], r["host"], r["asn"] or "-",
         ", ".join(r["communities"]) or f"ERROR: {r['error']}"]
        for r in results
    ]
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    lines += [fmt.format(*row) for row in rows]
    text = "\n".join(lines) + "\n"
    path.write_text(text)
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description="List the BGP community each wan_router sets on its own routes.")
    parser.add_argument("--site", help="Only routers at this NetBox site (slug)")
    parser.add_argument("--device", help="Only routers whose name contains this text")
    parser.add_argument("--tag", default="wan_router", help="NetBox device tag (default: wan_router)")
    parser.add_argument("--workers", type=int, default=10, help="Routers to query at once (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds (default: 30)")
    parser.add_argument("--output", default=str(HERE / "bgp_community.txt"), help="Output file (default: bgp_community.txt)")
    args = parser.parse_args()

    import netbox_helper
    import vault_helper

    try:
        creds = vault_helper.get_secrets()
        nb = netbox_helper.connect(creds["netbox_url"], creds["netbox_token"])
        devices, skipped = netbox_helper.get_devices(nb, tag=args.tag, site=args.site, name_contains=args.device)
    except Exception as exc:  # noqa: BLE001
        print(f"Setup error: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}", file=sys.stderr)
        return 2
    if not devices:
        print(f"No devices with tag {args.tag!r} matched.", file=sys.stderr)
        return 2

    print(f"Querying {len(devices)} router(s)...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(query_device, d, creds, args.timeout) for d in devices]
        results = sorted((f.result() for f in as_completed(futures)), key=lambda r: (r["site"], r["name"]))

    print(write_table(results, Path(args.output)))
    for s in skipped:
        print(f"skipped {s['name']}: {s['reason']}", file=sys.stderr)
    print(f"Wrote {args.output}", file=sys.stderr)
    return 0 if all(r["communities"] for r in results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
