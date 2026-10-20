"""Route lookups for cisco_helper.py: the show command per platform, parsing and classifying the output, the
core-switch VRF rules (CORE_VRFS) and recursive next-hop resolution."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from cisco_common import CiscoError, validate_show

# Route lookups: text that means the device has no route, has one, or rejected the command.
ROUTE_NOT_FOUND = re.compile(r"not in table|route not found|no route|network not in table", re.I)
ROUTE_FOUND = re.compile(r"Routing entry for|\bvia\b|directly connected|\bubest/mbest\b|inet6?\.0:.*\d+ destinations", re.I)
ROUTE_ERROR = re.compile(r"% ?Invalid input|syntax error|% ?Incomplete command|% ?Ambiguous command", re.I)


# Sites whose core switches route user subnets in a VRF (NetBox site name -> VRF). Only the cores (NetBox role
# "Core") have it; the WAN routers there use the global table. Route and ARP lookups on these cores use this
# VRF only, unless --vrf says otherwise.
CORE_VRFS = {"Lakeview Hospital": "buyer", "Lakeside": "buyer", "Tulane": "buyer"}


# On those cores, these VRFs ("" = the global table) hold isolated networks that are not routed to the WAN.
# locate only looks there when the normal WAN-router trace finds nothing.
CORE_ISOLATED_VRFS = ["div", ""]


def default_vrf(device: dict[str, Any]) -> str | None:
    """The VRF to use for route/ARP lookups on a device when none was given (see CORE_VRFS)."""
    if (device.get("role") or "").lower() == "core":
        return CORE_VRFS.get(device.get("site") or "")
    return None


def parse_route_target(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Accept an IPv4/IPv6 address or prefix for a route lookup."""
    try:
        return ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
    except ValueError:
        raise CiscoError(f"{value!r} is not a valid IP address or prefix") from None


def route_command(device_type: str, target: Any, vrf: str | None = None) -> str:
    """The route lookup command for a platform (address or prefix, IPv4 or IPv6, optional VRF)."""
    is_v6 = target.version == 6
    ip_kw = "ipv6" if is_v6 else "ip"
    if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        cidr = str(target)
        # IOS/IOS-XE want "network mask" for IPv4 prefixes.
        ios_target = f"{target.network_address} {target.netmask}" if not is_v6 else cidr
    else:
        cidr = ios_target = str(target)

    if device_type == "cisco_nxos":
        return f"show {ip_kw} route {cidr}{' vrf ' + vrf if vrf else ''}"
    if device_type == "cisco_xr":
        return f"show route {'vrf ' + vrf + ' ' if vrf else ''}{'ipv6 ' if is_v6 else ''}{cidr}"
    if device_type == "arista_eos":
        return f"show {ip_kw} route {'vrf ' + vrf + ' ' if vrf else ''}{cidr}"
    if device_type == "juniper_junos":
        table = f" table {vrf}.inet{'6' if is_v6 else ''}.0" if vrf else ""
        return f"show route {cidr}{table}"
    # IOS, IOS-XE and anything unknown.
    return f"show {ip_kw} route {'vrf ' + vrf + ' ' if vrf else ''}{ios_target}"


def parse_route(output: str) -> dict[str, Any]:
    """Pull the matched prefix, protocol, AD/metric and next hops (with interfaces) out of IOS/IOS-XE
    'show ip route <ip>' output. Fields are empty when the format isn't recognized."""
    detail: dict[str, Any] = {"prefix": "", "protocol": "", "distance": "", "metric": "", "next_hops": []}
    if m := re.search(r"Routing entry for (\S+)", output):
        detail["prefix"] = m.group(1).rstrip(",")
    if m := re.search(r'Known via "([^"]+)"(?:, distance (\d+), metric (\d+))?', output):
        detail["protocol"], detail["distance"], detail["metric"] = m.group(1), m.group(2) or "", m.group(3) or ""
    for line in output.splitlines():
        line = line.strip()
        # "* 10.143.100.1, from 10.143.1.22, 1w0d ago, via TenGigabitEthernet0/1/0"; static: "* 10.75.71.84"
        # or "* 10.75.71.84, via Vlan10"
        if m := re.match(r"^\*?\s*(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+:[0-9a-fA-F:]*)(?:, from \S+,.*?)?(?:,? ?via (\S+))?$", line):
            detail["next_hops"].append({"next_hop": m.group(1), "interface": m.group(2) or "",
                                        "active": line.startswith("*")})
        # "* directly connected, via Vlan110"
        elif m := re.match(r"^\*?\s*directly connected, via (\S+)", line):
            detail["next_hops"].append({"next_hop": "connected", "interface": m.group(1), "active": line.startswith("*")})
    return detail


def classify_route(output: str) -> str:
    """Return 'found', 'not found' or 'error' for route lookup output."""
    text = output.strip()
    if not text:
        return "not found"
    if ROUTE_ERROR.search(text):
        return "error"
    if ROUTE_NOT_FOUND.search(text):
        return "not found"
    return "found" if ROUTE_FOUND.search(text) else "not found"


def resolve_route(conn: Any, detail: dict[str, Any], vrf: str | None, timeout: int,
                  depth: int = 2) -> dict[str, Any]:
    """Fill in the outgoing interface for next hops that don't show one (BGP and other recursive
    routes) by looking up the route to the next hop on the same device, up to `depth` levels."""
    for hop in detail.get("next_hops", []):
        nh = hop.get("next_hop")
        if hop.get("interface") or not nh or nh == "connected" or depth <= 0:
            continue
        try:
            target = parse_route_target(nh)
        except CiscoError:
            continue
        out = conn.send_command(validate_show(route_command("cisco_xe", target, vrf)), read_timeout=timeout * 2)
        if classify_route(out) != "found":
            continue
        inner = resolve_route(conn, parse_route(out), vrf, timeout, depth - 1)
        first = next((h for h in inner["next_hops"] if h.get("interface")), None)
        if first:
            hop["interface"] = first["interface"]
            hop["resolved_via"] = f"{inner['prefix']} {inner['protocol']} -> {first['next_hop']}"
    return detail
