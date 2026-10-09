"""NetBox, the network inventory: devices, sites, IP addresses and prefixes (read-only).

get_devices() returns devices to connect to, with the host to SSH to and the netmiko device_type.
The NetBox URL and token come from Vault (netbox_url / netbox_token).

From the command line:
    python netbox_helper.py sites [--name Lake]
    python netbox_helper.py devices --site Lakeside [--tag wan_router] [--role router] [--name wlc]
    python netbox_helper.py device lakeview-wlc-ha01          # full record for one device
    python netbox_helper.py ip 10.158.8.21                    # which device/interface has an IP
    python netbox_helper.py prefix 10.158.10.25               # prefixes containing an IP (or a prefix itself)
    python netbox_helper.py tags
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import pynetbox
import requests

# NetBox platform slug -> netmiko device_type. Add new platforms here.
PLATFORM_MAP: dict[str, str] = {
    "ios": "cisco_ios",
    "cisco-ios": "cisco_ios",
    "cisco_ios": "cisco_ios",
    "ios-xe": "cisco_xe",
    "iosxe": "cisco_xe",
    "cisco-ios-xe": "cisco_xe",
    "cisco_xe": "cisco_xe",
    "nxos": "cisco_nxos",
    "nx-os": "cisco_nxos",
    "cisco-nxos": "cisco_nxos",
    "cisco-nx-os": "cisco_nxos",
    "cisco_nxos": "cisco_nxos",
    "iosxr": "cisco_xr",
    "ios-xr": "cisco_xr",
    "cisco-ios-xr": "cisco_xr",
    "cisco_xr": "cisco_xr",
    "eos": "arista_eos",
    "arista-eos": "arista_eos",
    "arista_eos": "arista_eos",
    "junos": "juniper_junos",
    "juniper-junos": "juniper_junos",
    "juniper_junos": "juniper_junos",
}
DEFAULT_DEVICE_TYPE = "cisco_ios"


def connect(url: str, token: str) -> pynetbox.api:
    """Return a pynetbox API client."""
    nb = pynetbox.api(url.rstrip("/"), token=token)
    nb.http_session = requests.Session()
    return nb


def device_type_for(platform_slug: str | None, device_name: str = "") -> str:
    """Map a NetBox platform slug to a netmiko device_type, warning when it is unknown."""
    if platform_slug and platform_slug.lower() in PLATFORM_MAP:
        return PLATFORM_MAP[platform_slug.lower()]
    print(f"warning: {device_name or 'device'} has platform {platform_slug!r}, "
          f"which is not in PLATFORM_MAP; using {DEFAULT_DEVICE_TYPE}", file=sys.stderr)
    return DEFAULT_DEVICE_TYPE


def _host_for(device: Any) -> str | None:
    """Primary IPv4 without the prefix length, then primary IP, then the device name."""
    for ip in (device.primary_ip4, device.primary_ip):
        if ip and getattr(ip, "address", None):
            return str(ip.address).split("/")[0]
    return device.name or None


def resolve_site(nb: pynetbox.api, site: str) -> str:
    """Return the slug for a site given its slug, exact name, or a unique part of its name."""
    if nb.dcim.sites.get(slug=site):
        return site
    matches = list(nb.dcim.sites.filter(name__ie=site)) or list(nb.dcim.sites.filter(name__ic=site))
    if len(matches) == 1:
        return matches[0].slug
    if not matches:
        raise ValueError(f"no NetBox site matches {site!r}")
    raise ValueError(f"{site!r} matches {len(matches)} sites: {', '.join(s.name for s in matches[:10])}")


def get_devices(
    nb: pynetbox.api,
    tag: str | None = "wan_router",
    site: str | None = None,
    name_contains: str | None = None,
    role: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Return (devices, skipped) matching the filters. tag=None means any tag.
    site can be a slug, a site name, or a unique part of a site name.

    Each device dict has: name, host, platform, device_type, site, status.
    Each skipped dict has: name, reason.
    """
    filters: dict[str, Any] = {}
    if tag:
        filters["tag"] = tag
    if site:
        filters["site"] = resolve_site(nb, site)
    if name_contains:
        filters["name__ic"] = name_contains
    if role:
        filters["role"] = role

    devices: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for device in nb.dcim.devices.filter(**filters):
        name = device.name or f"id-{device.id}"
        host = _host_for(device)
        if not host:
            skipped.append({"name": name, "reason": "no primary IP or name"})
            continue
        platform = device.platform.slug if device.platform else None
        devices.append({
            "name": name,
            "host": host,
            "platform": platform,
            "device_type": device_type_for(platform, name),
            "site": device.site.name if device.site else "",
            "status": device.status.value if device.status else "",
            "role": _slug(getattr(device, "role", None) or getattr(device, "device_role", None)),
            "model": _slug(device.device_type),
        })
    devices.sort(key=lambda d: d["name"])
    return devices, skipped


# ---------------------------------------------------------------------------
# Inventory lookups
# ---------------------------------------------------------------------------

def _slug(obj: Any) -> str:
    """Display value for a nested NetBox object (name, model, slug, value) or ''."""
    if obj is None:
        return ""
    for attr in ("name", "model", "display", "slug", "value"):
        value = getattr(obj, attr, None)
        if value:
            return str(value)
    return str(obj)


def device_record(nb: pynetbox.api, name: str) -> list[dict[str, Any]]:
    """Full inventory record(s) for a device: exact name (any case), else names containing the text."""
    found = list(nb.dcim.devices.filter(name__ie=name)) or list(nb.dcim.devices.filter(name__ic=name))
    records = []
    for d in found[:25]:
        records.append({
            "name": d.name, "id": d.id, "status": _slug(d.status), "site": _slug(d.site),
            "location": _slug(getattr(d, "location", None)), "rack": _slug(d.rack),
            "role": _slug(getattr(d, "role", None) or getattr(d, "device_role", None)),
            "manufacturer": _slug(getattr(d.device_type, "manufacturer", None)) if d.device_type else "",
            "model": _slug(d.device_type), "platform": _slug(d.platform), "serial": d.serial or "",
            "asset_tag": d.asset_tag or "", "primary_ip4": str(d.primary_ip4) if d.primary_ip4 else "",
            "primary_ip6": str(d.primary_ip6) if d.primary_ip6 else "",
            "tags": [_slug(t) for t in (d.tags or [])], "description": getattr(d, "description", "") or "",
            "comments": (d.comments or "")[:500], "custom_fields": d.custom_fields or {},
            "url": getattr(d, "display_url", None) or d.url,
        })
    return records


def ip_lookup(nb: pynetbox.api, ip: str) -> list[dict[str, Any]]:
    """Which device / interface an IP address is assigned to in NetBox."""
    rows = []
    for a in nb.ipam.ip_addresses.filter(q=ip.split("/")[0]):
        if str(a.address).split("/")[0] != ip.split("/")[0]:
            continue
        obj = a.assigned_object
        rows.append({
            "address": str(a.address), "status": _slug(a.status), "role": _slug(a.role),
            "dns_name": a.dns_name or "", "vrf": _slug(a.vrf), "description": a.description or "",
            "device": _slug(getattr(obj, "device", None)) or _slug(getattr(obj, "virtual_machine", None)),
            "interface": _slug(obj), "tenant": _slug(a.tenant),
        })
    return rows


def prefix_lookup(nb: pynetbox.api, value: str) -> list[dict[str, Any]]:
    """Prefixes containing an IP (or equal to / inside a given prefix), most specific first."""
    flt = {"q": value} if "/" in value else {"contains": value}
    rows = []
    for p in nb.ipam.prefixes.filter(**flt):
        rows.append({
            "prefix": str(p.prefix), "status": _slug(p.status), "site": _slug(getattr(p, "site", None) or getattr(p, "scope", None)),
            "vlan": f"{p.vlan.vid} {p.vlan.name}" if p.vlan else "", "vrf": _slug(p.vrf),
            "role": _slug(p.role), "tenant": _slug(p.tenant), "description": p.description or "",
        })
    return sorted(rows, key=lambda r: -int(r["prefix"].split("/")[1]))


def sites(nb: pynetbox.api, name_contains: str | None = None) -> list[dict[str, Any]]:
    flt = {"name__ic": name_contains} if name_contains else {}
    return [{"name": s.name, "slug": s.slug, "status": _slug(s.status), "region": _slug(s.region),
             "facility": s.facility or "", "devices": getattr(s, "device_count", None),
             "description": s.description or ""} for s in nb.dcim.sites.filter(**flt)]


def tags(nb: pynetbox.api) -> list[dict[str, Any]]:
    return [{"name": t.name, "slug": t.slug, "items": getattr(t, "tagged_items", None),
             "description": t.description or ""} for t in nb.extras.tags.all()]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print(rows: Any, as_json: bool, columns: list[str] | None = None) -> None:
    if as_json or not isinstance(rows, list) or not rows or not columns:
        print(json.dumps(rows, indent=2, default=str))
        return
    table = [[str(r.get(c, "") if r.get(c) is not None else "")[:45] for c in columns] for r in rows]
    widths = [max(len(x) for x in col) for col in zip(columns, *table)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*columns))
    print(fmt.format(*("-" * w for w in widths)))
    for row in table:
        print(fmt.format(*row))
    print(f"\n{len(rows)} row(s)", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only NetBox inventory lookups.")
    parser.add_argument("--json", action="store_true", help="print JSON")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("sites", help="list sites")
    p.add_argument("--name", help="site names containing this text")
    p = sub.add_parser("devices", help="list devices")
    p.add_argument("--site", help="site name or slug")
    p.add_argument("--tag", help="tag, e.g. wan_router")
    p.add_argument("--role", help="device role slug, e.g. router")
    p.add_argument("--name", help="device names containing this text")
    p = sub.add_parser("device", help="full record for one device (exact name, else names containing the text)")
    p.add_argument("name")
    p = sub.add_parser("ip", help="which device/interface has this IP")
    p.add_argument("address")
    p = sub.add_parser("prefix", help="prefixes containing an IP, or matching a prefix")
    p.add_argument("value")
    sub.add_parser("tags", help="list tags")
    # Accept --json after the subcommand too (SUPPRESS keeps a --json given before it).
    for subparser in sub.choices.values():
        subparser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="print JSON")
    args = parser.parse_args()

    import vault_helper

    creds = vault_helper.get_secrets(interactive=False)
    nb = connect(creds["netbox_url"], creds["netbox_token"])
    try:
        if args.cmd == "sites":
            _print(sites(nb, args.name), args.json, ["name", "slug", "status", "region", "facility", "description"])
        elif args.cmd == "devices":
            if not (args.site or args.tag or args.role or args.name):
                print("give at least one of --site, --tag, --role, --name", file=sys.stderr)
                return 2
            found, skipped = get_devices(nb, tag=args.tag, site=args.site, name_contains=args.name, role=args.role)
            _print(found, args.json, ["name", "host", "site", "role", "model", "platform", "status"])
            for s in skipped:
                print(f"skipped {s['name']}: {s['reason']}", file=sys.stderr)
        elif args.cmd == "device":
            _print(device_record(nb, args.name), True)
        elif args.cmd == "ip":
            _print(ip_lookup(nb, args.address), args.json, ["address", "device", "interface", "vrf", "status", "dns_name", "description"])
        elif args.cmd == "prefix":
            _print(prefix_lookup(nb, args.value), args.json, ["prefix", "site", "vlan", "vrf", "role", "status", "description"])
        elif args.cmd == "tags":
            _print(tags(nb), args.json, ["name", "slug", "items", "description"])
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
