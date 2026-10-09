"""Look up a route on every NetBox device tagged wan_router.

Usage:
    python route.py 10.158.8.1
    python route.py 10.158.8.0/24 --site NOLA --vrf CORP
    python route.py 10.158.8.1 --json

Credentials come from Vault (vault_helper.py), the device list from NetBox (netbox_helper.py).
Only read-only show commands are sent to the routers.

Exit codes: 0 = at least one router has the route, 1 = no router has it, 2 = setup error.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
err_console = Console(stderr=True)

# Text that means the router has no route for the lookup.
NOT_FOUND_PATTERNS = re.compile(
    r"not in table|route not found|no route|network not in table|% Network not in table",
    re.IGNORECASE,
)
# Text that means the router showed a route entry.
FOUND_PATTERNS = re.compile(
    r"Routing entry for|\bvia\b|directly connected|\bubest/mbest\b|inet6?\.0:.*\d+ destinations",
    re.IGNORECASE,
)
# Text that means the router rejected the command.
ERROR_PATTERNS = re.compile(r"% ?Invalid input|syntax error|% ?Incomplete command|% ?Ambiguous command", re.IGNORECASE)
# Platforms where enable() is needed for privileged show commands.
NEEDS_ENABLE = {"cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos"}


def build_command(device_type: str, target: ipaddress.IPv4Network | ipaddress.IPv6Network | ipaddress.IPv4Address | ipaddress.IPv6Address,
                  vrf: str | None) -> str:
    """Return the route lookup command for a platform. This is the one place to add platforms."""
    is_v6 = target.version == 6
    ip_kw = "ipv6" if is_v6 else "ip"

    if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        cidr = str(target)
        # IOS/IOS-XE want "network mask" for IPv4 prefixes.
        ios_target = f"{target.network_address} {target.netmask}" if not is_v6 else cidr
    else:
        cidr = ios_target = str(target)

    if device_type in ("cisco_ios", "cisco_xe"):
        return f"show {ip_kw} route {'vrf ' + vrf + ' ' if vrf else ''}{ios_target}"
    if device_type == "cisco_nxos":
        return f"show {ip_kw} route {cidr}{' vrf ' + vrf if vrf else ''}"
    if device_type == "cisco_xr":
        return f"show route {'vrf ' + vrf + ' ' if vrf else ''}{'ipv6 ' if is_v6 else ''}{cidr}"
    if device_type == "arista_eos":
        return f"show {ip_kw} route {'vrf ' + vrf + ' ' if vrf else ''}{cidr}"
    if device_type == "juniper_junos":
        table = f" table {vrf}.inet{'6' if is_v6 else ''}.0" if vrf else ""
        return f"show route {cidr}{table}"
    # Unknown types fall back to IOS syntax.
    return f"show {ip_kw} route {'vrf ' + vrf + ' ' if vrf else ''}{ios_target}"


def classify(output: str) -> str:
    """Return 'found', 'not found' or 'error' for a command's output."""
    text = output.strip()
    if not text:
        return "not found"
    if ERROR_PATTERNS.search(text):
        return "error"
    if NOT_FOUND_PATTERNS.search(text):
        return "not found"
    if FOUND_PATTERNS.search(text):
        return "found"
    return "not found"


def query_device(device: dict[str, Any], creds: dict[str, str], target, vrf: str | None, timeout: int) -> dict[str, Any]:
    """SSH to one router, run the lookup, and return a result dict. Never raises."""
    # Imported here so `route.py --help` works even before netmiko is installed.
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

    command = build_command(device["device_type"], target, vrf)
    result: dict[str, Any] = {**device, "command": command, "status_result": "error", "output": "", "error": None}

    params = {
        "device_type": device["device_type"],
        "host": device["host"],
        "username": creds["ansible_user"],
        "password": creds["ansible_password"],
        "secret": creds["ansible_become_password"],
        "conn_timeout": timeout,
        "auth_timeout": timeout,
        "banner_timeout": timeout,
        "fast_cli": False,
    }
    try:
        with ConnectHandler(**params) as conn:
            if device["device_type"] in NEEDS_ENABLE:
                try:
                    if not conn.check_enable_mode():
                        conn.enable()
                except Exception:  # noqa: BLE001 - most show route commands work without enable
                    result["error"] = "enable failed; ran command unprivileged"
            output = conn.send_command(command, read_timeout=timeout * 2)
        result["output"] = output
        result["status_result"] = classify(output)
        if result["status_result"] == "error" and not result["error"]:
            result["error"] = "router rejected the command"
    except NetmikoAuthenticationException:
        result["error"] = "authentication failed"
    except NetmikoTimeoutException:
        result["error"] = "timed out / unreachable"
    except Exception as exc:  # noqa: BLE001 - one bad device must not stop the run
        result["error"] = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
    return result


def parse_target(value: str):
    """Accept an IPv4/IPv6 address or prefix."""
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        return ipaddress.ip_address(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid IP address or prefix")


def print_results(results: list[dict[str, Any]], skipped: list[dict[str, str]], raw: bool) -> None:
    if raw:
        for r in results:
            print(f"===== {r['name']} ({r['host']}) : {r['command']}")
            print(r["output"] if r["output"] else f"[{r['error']}]")
            print()
        return

    styles = {"found": "green", "not found": "yellow", "error": "red"}
    for r in results:
        header = f"[bold]{r['name']}[/]  site={r['site'] or '-'}  host={r['host']}  [dim]{r['device_type']}[/]"
        body = f"[cyan]$ {r['command']}[/]\n"
        body += r["output"].rstrip() if r["output"] else f"[red]{r['error']}[/]"
        if r["output"] and r["error"]:
            body += f"\n[yellow]note: {r['error']}[/]"
        console.print(Panel(body, title=header, title_align="left", border_style=styles[r["status_result"]]))

    table = Table(title="Summary")
    table.add_column("Router")
    table.add_column("Site")
    table.add_column("Host")
    table.add_column("Result")
    table.add_column("Note")
    for r in results:
        style = styles[r["status_result"]]
        table.add_row(r["name"], r["site"] or "-", r["host"], f"[{style}]{r['status_result']}[/]", r["error"] or "")
    for s in skipped:
        table.add_row(s["name"], "-", "-", "[dim]skipped[/]", s["reason"])
    console.print(table)


def main() -> int:
    parser = argparse.ArgumentParser(description="Look up a route on every NetBox device tagged wan_router.")
    parser.add_argument("target", type=parse_target, help="IPv4/IPv6 address or prefix, e.g. 10.158.8.1 or 10.158.8.0/24")
    parser.add_argument("--site", help="Only routers at this NetBox site (slug)")
    parser.add_argument("--device", help="Only routers whose name contains this text")
    parser.add_argument("--vrf", help="Look up the route in this VRF")
    parser.add_argument("--tag", default="wan_router", help="NetBox device tag (default: wan_router)")
    parser.add_argument("--workers", type=int, default=10, help="Routers to query at once (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds (default: 30)")
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    output_group.add_argument("--raw", action="store_true", help="Print router output with no formatting")
    args = parser.parse_args()

    import netbox_helper
    import vault_helper

    try:
        creds = vault_helper.get_secrets()
    except vault_helper.VaultError as exc:
        err_console.print(f"[red]Vault error:[/] {exc}")
        err_console.print("Log in with: vault login -method=oidc   (VAULT_ADDR must be set)")
        return 2
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Could not reach Vault:[/] {type(exc).__name__}")
        return 2

    try:
        nb = netbox_helper.connect(creds["netbox_url"], creds["netbox_token"])
        devices, skipped = netbox_helper.get_devices(nb, tag=args.tag, site=args.site, name_contains=args.device)
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]NetBox error:[/] {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}")
        return 2

    if not devices:
        err_console.print(f"[red]No devices with tag {args.tag!r} matched the filters.[/]")
        return 2

    if not args.json:
        err_console.print(f"Querying {len(devices)} router(s) for [bold]{args.target}[/]"
                          f"{' in VRF ' + args.vrf if args.vrf else ''}...")

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(query_device, d, creds, args.target, args.vrf, args.timeout) for d in devices]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda r: r["name"])

    if args.json:
        print(json.dumps({
            "target": str(args.target),
            "vrf": args.vrf,
            "results": [
                {k: r[k] for k in ("name", "site", "host", "platform", "device_type", "command", "output", "error")}
                | {"result": r["status_result"]}
                for r in results
            ],
            "skipped": skipped,
        }, indent=2))
    else:
        print_results(results, skipped, args.raw)

    return 0 if any(r["status_result"] == "found" for r in results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
