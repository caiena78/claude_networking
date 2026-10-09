"""NetBox lookups for the route tool.

get_devices() returns the routers to query, with the host to SSH to and the netmiko device_type.
"""

from __future__ import annotations

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
        })
    devices.sort(key=lambda d: d["name"])
    return devices, skipped
