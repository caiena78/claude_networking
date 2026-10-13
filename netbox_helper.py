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
    python netbox_helper.py devices --site Lakeside --summary [role,model]   # counts instead of rows
    Every command takes -o FILE [--append] to also save the output.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

import pynetbox
import requests

from helper_common import Out, table, to_json

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
    "airos": "cisco_wlc_ssh",          # AireOS WLCs (5508, 5520, 8540, 3504)
    "aireos": "cisco_wlc_ssh",
    "cisco-aireos": "cisco_wlc_ssh",
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


def _device_entry(raw: dict, name: str) -> dict[str, Any]:
    """Device dict for the runners, from a device as the API returned it (dict(record))."""
    ip = (raw.get("primary_ip4") or raw.get("primary_ip") or {}).get("address")
    platform = (raw.get("platform") or {}).get("slug")
    return {
        "name": name,
        "host": str(ip).split("/")[0] if ip else raw.get("name"),
        "platform": platform,
        "device_type": device_type_for(platform, name),
        "site": (raw.get("site") or {}).get("name", ""),
        "status": (raw.get("status") or {}).get("value", ""),
        "role": _slug(raw.get("role") or raw.get("device_role")),
        "model": _slug(raw.get("device_type")),
    }


def get_devices(
    nb: pynetbox.api,
    tag: str | None = "wan_router",
    site: str | None = None,
    name_contains: str | None = None,
    role: str | None = None,
    collapse_vc: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Return (devices, skipped) matching the filters. tag=None means any tag.
    site can be a slug, a site name, or a unique part of a site name.

    Virtual chassis (switch stacks, VSS/StackWise Virtual pairs) are collapsed into ONE device named after the
    virtual chassis, which connects to the master's management IP (the members share one control plane and
    usually only the master has a primary IP in NetBox). It also has "members" (member device names) and
    "vc": True. A name_contains filter also matches virtual chassis names. collapse_vc=False lists members.

    Each device dict has: name, host, platform, device_type, site, status, role, model.
    Each skipped dict has: name, reason.
    """
    filters: dict[str, Any] = {}
    if tag:
        filters["tag"] = tag
    if site:
        filters["site"] = resolve_site(nb, site)
    if role:
        filters["role"] = role

    records = {d.id: dict(d) for d in nb.dcim.devices.filter(**filters, **({"name__ic": name_contains}
                                                                           if name_contains else {}))}
    if name_contains and collapse_vc:
        # Stacks whose virtual chassis name matches, even when the member names don't.
        vc_ids = [vc.id for vc in nb.dcim.virtual_chassis.filter(name__ic=name_contains)]
        if vc_ids:
            for d in nb.dcim.devices.filter(**filters, virtual_chassis_id=vc_ids):
                records.setdefault(d.id, dict(d))

    devices: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    stacks: dict[int, list[dict]] = {}
    for raw in records.values():
        vc = raw.get("virtual_chassis")
        if vc and collapse_vc:
            stacks.setdefault(vc["id"], []).append(raw)
            continue
        name = raw.get("name") or f"id-{raw['id']}"
        entry = _device_entry(raw, name)
        if not entry["host"]:
            skipped.append({"name": name, "reason": "no primary IP or name"})
            continue
        devices.append(entry)

    for vc_id, members in stacks.items():
        vc = members[0]["virtual_chassis"]
        master_id = (vc.get("master") or {}).get("id")
        with_ip = [m for m in members if m.get("primary_ip4") or m.get("primary_ip")]
        if not with_ip:
            # The filter may have matched only non-master members: fetch the whole stack.
            full = [dict(d) for d in nb.dcim.devices.filter(virtual_chassis_id=vc_id)]
            with_ip = [m for m in full if m.get("primary_ip4") or m.get("primary_ip")]
            members = full or members
        chosen = next((m for m in with_ip if m["id"] == master_id), None) or \
            (sorted(with_ip, key=lambda m: m.get("vc_position") or 99)[0] if with_ip else None)
        vc_name = vc.get("name") or members[0].get("name")
        if not chosen:
            skipped.append({"name": vc_name, "reason": "virtual chassis has no member with a primary IP"})
            continue
        entry = _device_entry(chosen, vc_name)
        entry.update(vc=True, master=chosen.get("name"),
                     members=[m["name"] for m in sorted(members, key=lambda m: m.get("vc_position") or 99)])
        devices.append(entry)
    devices.sort(key=lambda d: d["name"])
    return devices, skipped


def virtual_chassis(nb: pynetbox.api, name: str) -> list[dict[str, Any]]:
    """Virtual chassis whose name equals (else contains) the text, with every member's position, model and serial."""
    found = list(nb.dcim.virtual_chassis.filter(name__ie=name)) or list(nb.dcim.virtual_chassis.filter(name__ic=name))
    out = []
    for vc in found[:25]:
        raw = dict(vc)
        members = [dict(d) for d in nb.dcim.devices.filter(virtual_chassis_id=vc.id)]
        out.append({
            "name": raw.get("name"), "id": raw.get("id"), "domain": raw.get("domain") or "",
            "master": (raw.get("master") or {}).get("name", ""), "member_count": raw.get("member_count"),
            "members": [{"name": m.get("name"), "position": m.get("vc_position"), "priority": m.get("vc_priority"),
                         "model": _slug(m.get("device_type")), "serial": m.get("serial") or "",
                         "primary_ip": ((m.get("primary_ip4") or {}).get("address") or ""),
                         "status": (m.get("status") or {}).get("value", ""), "site": (m.get("site") or {}).get("name", "")}
                        for m in sorted(members, key=lambda m: m.get("vc_position") or 99)],
        })
    return out


# ---------------------------------------------------------------------------
# Inventory lookups
# ---------------------------------------------------------------------------

def _slug(obj: Any) -> str:
    """Display value for a nested NetBox object (name, model, slug, value) or ''."""
    if obj is None:
        return ""
    # Read the nested object as the API returned it. getattr() on a field it didn't send (e.g. "name" on a
    # nested device type, which only has "model") makes pynetbox fetch the full record: one extra API call
    # per device, which made device lists thousands of calls long.
    try:
        data = dict(obj)
    except (TypeError, ValueError):
        data = None
    if isinstance(data, dict):
        for key in ("name", "model", "display", "slug", "value", "label"):
            if data.get(key):
                return str(data[key])
        return str(obj)
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


def inventory(nb: pynetbox.api, **filters: Any) -> list[dict[str, Any]]:
    """Every device (or those matching filters) with the fields needed to compare against other systems."""
    return [{
        "name": d.name or "", "serial": (d.serial or "").strip(), "site": _slug(d.site),
        "role": _slug(getattr(d, "role", None) or getattr(d, "device_role", None)),
        "model": _slug(d.device_type), "status": _slug(d.status),
        "primary_ip": str(d.primary_ip4).split("/")[0] if d.primary_ip4 else "",
    } for d in (nb.dcim.devices.filter(**filters) if filters else nb.dcim.devices.all())]


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
    rows = [_prefix_row(p) for p in nb.ipam.prefixes.filter(**flt)]
    return sorted(rows, key=lambda r: -int(r["prefix"].split("/")[1]))


def _prefix_row(p: Any) -> dict[str, Any]:
    # Read the record as returned (dict(p)): asking pynetbox for an attribute the API didn't send (e.g. 'site'
    # on NetBox 4.2+, where prefixes have 'scope') makes it fetch the full record, one extra call per prefix.
    raw = dict(p)
    scope = raw.get("site") or (raw.get("scope") if str(raw.get("scope_type", "")).endswith("site") else None) \
        or raw.get("scope")
    name = lambda v, *keys: next((str(v[k]) for k in keys if isinstance(v, dict) and v.get(k)), "")  # noqa: E731
    vlan = raw.get("vlan") or {}
    return {
        "prefix": str(raw.get("prefix")), "status": name(raw.get("status"), "value", "label"),
        "site": name(scope, "name", "display"),
        "vlan": f"{vlan.get('vid')} {vlan.get('name')}" if vlan else "", "vrf": name(raw.get("vrf"), "name"),
        "role": name(raw.get("role"), "name"), "tenant": name(raw.get("tenant"), "name"),
        "description": raw.get("description") or "",
    }


def prefixes(nb: pynetbox.api, site: str | None = None, vlan: str | None = None, vrf: str | None = None,
             role: str | None = None, search: str | None = None) -> list[dict[str, Any]]:
    """Every prefix (subnet) matching the filters, in address order: the subnet -> site map.

    site: name, slug or unique part of a name. vlan: VLAN ID. vrf: VRF name. search: free text (prefix,
    description...)."""
    flt: dict[str, Any] = {}
    if site:
        flt["site"] = resolve_site(nb, site)
    if vlan:
        flt["vlan_vid"] = vlan
    if vrf:
        flt["vrf"] = vrf
    if role:
        flt["role"] = role
    if search:
        flt["q"] = search
    rows = [_prefix_row(p) for p in (nb.ipam.prefixes.filter(**flt) if flt else nb.ipam.prefixes.all())]
    import ipaddress

    return sorted(rows, key=lambda r: ipaddress.ip_network(r["prefix"], strict=False).network_address.packed
                  + bytes([int(r["prefix"].split("/")[1])]))


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

def _print(out: Out, rows: Any, as_json: bool, columns: list[str] | None = None) -> None:
    if as_json or not isinstance(rows, list) or not rows or not columns:
        out.add(to_json(rows))
        return
    out.add(table(rows, columns))
    print(f"\n{len(rows)} row(s)", file=sys.stderr)


def count_by(rows: list[dict], fields: list[str]) -> list[dict]:
    """Count rows by the values of fields, most common first."""
    counts: dict[tuple, int] = {}
    for r in rows:
        key = tuple("" if r.get(f) is None else str(r.get(f)) for f in fields)
        counts[key] = counts.get(key, 0) + 1
    return [{**dict(zip(fields, k)), "count": c} for k, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]


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
    p.add_argument("--name", help="device (or virtual chassis) names containing this text")
    p.add_argument("--members", action="store_true", help="list virtual chassis members separately")
    p.add_argument("--summary", nargs="?", const="role,model", metavar="FIELDS",
                   help="count devices instead of listing them, by comma-separated fields "
                        "(default role,model; also site, platform, status)")
    p = sub.add_parser("vc", help="virtual chassis (switch stack) and its members: position, model, serial, IP")
    p.add_argument("name")
    p = sub.add_parser("device", help="full record for one device (exact name, else names containing the text)")
    p.add_argument("name")
    p = sub.add_parser("ip", help="which device/interface has this IP")
    p.add_argument("address")
    p = sub.add_parser("prefix", help="prefixes containing an IP, or matching a prefix")
    p.add_argument("value")
    p = sub.add_parser("prefixes", help="list subnets and the site each belongs to (filter by site, VLAN, VRF, text)")
    p.add_argument("--site", help="site name, slug or unique part of a name")
    p.add_argument("--vlan", help="VLAN ID")
    p.add_argument("--vrf", help="VRF name")
    p.add_argument("--role", help="prefix role slug")
    p.add_argument("--search", help="free text: prefix, description...")
    sub.add_parser("tags", help="list tags")
    # Accept --json after the subcommand too (SUPPRESS keeps a --json given before it).
    for subparser in sub.choices.values():
        subparser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="print JSON")
        subparser.add_argument("-o", "--output", help="also write the output to this file")
        subparser.add_argument("--append", action="store_true", help="with -o: append")
    args = parser.parse_args()

    import vault_helper

    creds = vault_helper.get_secrets(interactive=False)
    nb = connect(creds["netbox_url"], creds["netbox_token"])
    out = Out()
    try:
        if args.cmd == "sites":
            _print(out, sites(nb, args.name), args.json, ["name", "slug", "status", "region", "facility", "description"])
        elif args.cmd == "devices":
            if not (args.site or args.tag or args.role or args.name):
                print("give at least one of --site, --tag, --role, --name", file=sys.stderr)
                return 2
            found, skipped = get_devices(nb, tag=args.tag, site=args.site, name_contains=args.name, role=args.role,
                                         collapse_vc=not args.members)
            for d in found:
                d["stack"] = f"{len(d['members'])} members" if d.get("vc") else ""
            if args.summary:
                fields = args.summary.split(",")
                _print(out, count_by(found, fields), args.json, fields + ["count"])
            else:
                _print(out, found, args.json, ["name", "host", "site", "role", "model", "platform", "status", "stack"])
            for s in skipped:
                print(f"skipped {s['name']}: {s['reason']}", file=sys.stderr)
        elif args.cmd == "vc":
            vcs = virtual_chassis(nb, args.name)
            if args.json or not vcs:
                _print(out, vcs, True)
            for vc in ([] if args.json else vcs):
                out.add(f"{vc['name']}  master {vc['master']}  members {vc['member_count']}"
                        + (f"  domain {vc['domain']}" if vc["domain"] else ""))
                _print(out, vc["members"], False, ["position", "name", "model", "serial", "primary_ip", "status", "site"])
                out.add("")
        elif args.cmd == "device":
            _print(out, device_record(nb, args.name), True)
        elif args.cmd == "ip":
            _print(out, ip_lookup(nb, args.address), args.json, ["address", "device", "interface", "vrf", "status", "dns_name", "description"])
        elif args.cmd == "prefix":
            _print(out, prefix_lookup(nb, args.value), args.json, ["prefix", "site", "vlan", "vrf", "role", "status", "description"])
        elif args.cmd == "prefixes":
            if not (args.site or args.vlan or args.vrf or args.role or args.search):
                print("give at least one of --site, --vlan, --vrf, --role, --search (there are ~4000 prefixes)", file=sys.stderr)
                return 2
            _print(out, prefixes(nb, args.site, args.vlan, args.vrf, args.role, args.search), args.json,
                   ["prefix", "site", "vlan", "vrf", "role", "status", "description"])
        elif args.cmd == "tags":
            _print(out, tags(nb), args.json, ["name", "slug", "items", "description"])
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out.save(args.output, args.append)
    return 0


if __name__ == "__main__":
    sys.exit(main())
