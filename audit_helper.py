"""NetBox drift reports: where NetBox (the source of truth) disagrees with the network. Read-only.

    python audit_helper.py prefixes --site "Lakeview Hospital"   # NetBox prefixes vs subnets connected on the site's cores
    python audit_helper.py devices [--source catalyst|meraki|all] # devices other systems manage that NetBox lacks or names differently
    python audit_helper.py meraki-vlans [--network PUC]           # Meraki MX VLAN subnets with no NetBox prefix

Every report ends with a list of NetBox fixes to consider. Nothing is changed anywhere.

prefixes
    Runs "show ip route connected" on the site's core switches (NetBox role Core) - in the global table and, for
    the CORE_VRFS sites, in VRF buyer and div too - and compares with NetBox:
      - connected subnet with no NetBox prefix                      -> add the prefix
      - connected subnet whose NetBox prefix is at another site     -> fix the prefix's site
      - NetBox prefix at the site, with a VLAN, not connected on a core (may be routed elsewhere; check it)
devices
    Catalyst Center (excluding access points) and/or Meraki device serials compared with NetBox serials:
      - serial NetBox doesn't have                                  -> add the device
      - same serial, different name                                 -> fix one of the names
meraki-vlans
    Every Meraki MX VLAN subnet compared with NetBox prefixes (exact match).
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from typing import Any

from helper_common import Out, table, to_json

CONNECTED = re.compile(r"^\s*C\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+is directly connected,\s*(\S+)", re.M)


def _netbox():
    import netbox_helper
    import vault_helper

    c = vault_helper.get_secrets(interactive=False)
    return netbox_helper.connect(c["netbox_url"], c["netbox_token"])


def parse_connected(output: str) -> list[tuple[str, str]]:
    """[(subnet, interface)] from 'show ip route [vrf X] connected' (IOS / IOS-XE)."""
    return CONNECTED.findall(output)


def _prefix_index(nb) -> dict[str, list[dict]]:
    import netbox_helper

    idx: dict[str, list[dict]] = {}
    for p in (netbox_helper._prefix_row(x) for x in nb.ipam.prefixes.all()):
        idx.setdefault(str(ipaddress.ip_network(p["prefix"], strict=False)), []).append(p)
    return idx


def audit_prefixes(site: str, log) -> dict[str, Any]:
    import cisco_helper
    import netbox_helper

    nb = _netbox()
    slug = netbox_helper.resolve_site(nb, site)
    site_name = nb.dcim.sites.get(slug=slug).name
    cores, _ = netbox_helper.get_devices(nb, tag=None, site=slug, role="core")
    cores = [d for d in cores if cisco_helper.is_ip(d["host"])]
    if not cores:
        raise SystemExit(f"no Core devices with a management IP at {site_name} in NetBox")
    vrfs = [None]
    if site_name in cisco_helper.CORE_VRFS:
        vrfs += [cisco_helper.CORE_VRFS[site_name]] + [v for v in cisco_helper.CORE_ISOLATED_VRFS if v]
    runner = cisco_helper.CiscoRunner()
    connected: dict[str, dict] = {}
    errors = []
    for vrf in vrfs:
        cmd = f"show ip route vrf {vrf} connected" if vrf else "show ip route connected"
        log(f"{cmd} on {', '.join(d['name'] for d in cores)}")
        for r in runner.run(cores, raw_command=cmd):
            if r["error"]:
                errors.append(f"{r['device']} ({vrf or 'global'}): {r['error']}")
                continue
            for subnet, intf in parse_connected(r["output"] or ""):
                net = ipaddress.ip_network(subnet, strict=False)
                if net.prefixlen >= 31 or intf.lower().startswith(("loopback", "lo")):
                    continue  # point-to-point links and loopbacks
                connected.setdefault(str(net), {"subnet": str(net), "vrf": vrf or "global", "interface": intf,
                                                "core": r["device"]})
    log("NetBox prefixes")
    idx = _prefix_index(nb)
    missing, wrong_site = [], []
    for sub, c in sorted(connected.items(), key=lambda kv: ipaddress.ip_network(kv[0])):
        rows = idx.get(sub, [])
        if not rows:
            missing.append(c)
        elif not any(p["site"] == site_name for p in rows) and any(p["site"] for p in rows):
            wrong_site.append({**c, "netbox_site": ", ".join(sorted({p["site"] for p in rows if p["site"]}))})
    site_prefixes = [p for rows in idx.values() for p in rows if p["site"] == site_name and p["vlan"]]
    not_connected = [p for p in site_prefixes if str(ipaddress.ip_network(p["prefix"], strict=False)) not in connected]
    return {"site": site_name, "cores": [d["name"] for d in cores], "vrfs": [v or "global" for v in vrfs],
            "connected": len(connected), "missing": missing, "wrong_site": wrong_site,
            "not_connected": sorted(not_connected, key=lambda p: ipaddress.ip_network(p["prefix"], strict=False)),
            "errors": errors}


def print_prefixes(r: dict, out: Out) -> None:
    out.add(f"PREFIX DRIFT  {r['site']}  cores: {', '.join(r['cores'])}  tables: {', '.join(r['vrfs'])}  "
            f"connected subnets: {r['connected']}")
    out.section(f"Connected on a core, no NetBox prefix ({len(r['missing'])}) -> add the prefix",
                table(r["missing"], ["subnet", "vrf", "interface", "core"]))
    out.section(f"Connected here, NetBox has it at another site ({len(r['wrong_site'])}) -> fix the prefix's site",
                table(r["wrong_site"], ["subnet", "vrf", "interface", "core", "netbox_site"]))
    out.section(f"NetBox prefix at {r['site']} with a VLAN, not connected on a core ({len(r['not_connected'])}) "
                "-> check (may be routed elsewhere, or stale)",
                table(r["not_connected"], ["prefix", "vlan", "vrf", "status", "description"]))
    for e in r["errors"]:
        out.add(f"! {e}")


def audit_devices(source: str, log) -> dict[str, Any]:
    import netbox_helper

    nb = _netbox()
    log("NetBox inventory")
    nbx = netbox_helper.inventory(nb)
    by_serial = {d["serial"].upper(): d for d in nbx if d["serial"]}
    res: dict[str, Any] = {"netbox_devices": len(nbx), "sources": {}}

    def same_name(a: str, b: str) -> bool:
        """Names match ignoring case, a domain suffix and NetBox's '(n)' stack/HA member suffix."""
        norm = lambda s: re.sub(r"\(\d+\)$", "", s.split(".")[0].strip().lower())  # noqa: E731
        return norm(a) == norm(b)

    def compare(name, rows):
        missing, renamed = [], []
        for r in rows:
            nbd = by_serial.get(r["serial"].upper())
            if not nbd:
                missing.append(r)
            elif r["name"] and nbd["name"] and not same_name(r["name"], nbd["name"]):
                renamed.append({**r, "netbox_name": nbd["name"], "netbox_site": nbd["site"]})
        res["sources"][name] = {"checked": len(rows), "missing": missing, "renamed": renamed}

    if source in ("catalyst", "all"):
        from catalyst_helper import Catalyst

        log("Catalyst Center inventory (excluding access points)")
        rows = [{"name": d.get("hostname") or "", "serial": (d.get("serialNumber") or "").split(",")[0].strip(),
                 "ip": d.get("managementIpAddress"), "model": d.get("platformId"), "family": d.get("family")}
                for d in Catalyst().devices(max_items=None)
                if d.get("family") != "Unified AP" and d.get("serialNumber")]
        compare("catalyst", rows)
    if source in ("meraki", "all"):
        from meraki_helper import Meraki

        log("Meraki inventory")
        m = Meraki()
        names = m.network_names()
        rows = [{"name": d.get("name") or "", "serial": d["serial"], "ip": d.get("lanIp"), "model": d.get("model"),
                 "family": names.get(d.get("networkId"), "")} for d in m.devices()]
        compare("meraki", rows)
    return res


def print_devices(r: dict, out: Out) -> None:
    out.add(f"DEVICE DRIFT  NetBox devices: {r['netbox_devices']}")
    for name, s in r["sources"].items():
        label = "network" if name == "meraki" else "family"
        if s["checked"] and len(s["missing"]) == s["checked"]:
            out.add(f"\n{name}: NetBox has none of the {s['checked']} {name} devices (by serial) - {name} isn't tracked "
                    f"in NetBox. Add them if NetBox should be the inventory for {name} too (list with --json).")
            continue
        out.section(f"{name}: {len(s['missing'])} of {s['checked']} devices have a serial NetBox doesn't -> add them",
                    table(s["missing"], ["name", "serial", "ip", "model", label]))
        out.section(f"{name}: {len(s['renamed'])} devices with the same serial but a different name -> fix a name",
                    table(s["renamed"], ["name", "netbox_name", "serial", "netbox_site", "ip"]))


def audit_meraki_vlans(network: str | None, log) -> dict[str, Any]:
    from meraki_helper import Meraki, MerakiError

    m = Meraki()
    nb = _netbox()
    log("NetBox prefixes")
    idx = _prefix_index(nb)
    missing, ok, errors = [], 0, []
    nets = m.networks_matching(network, "appliance")
    log(f"Meraki VLANs on {len(nets)} networks")
    for net in nets:
        try:
            vlans = m.vlans(net["id"])
        except MerakiError as exc:
            if "VLANs are not enabled" in str(exc):
                single = m.try_get(f"networks/{net['id']}/appliance/singleLan")
                if "error" in single:  # e.g. an MX in passthrough mode has no LAN subnet
                    continue
                vlans = [{"id": "(single LAN)", "name": "", "subnet": single.get("subnet")}]
            else:
                errors.append(f"{net['name']}: {exc}")
                continue
        for v in vlans:
            if not v.get("subnet"):
                continue
            key = str(ipaddress.ip_network(v["subnet"], strict=False))
            if key in idx:
                ok += 1
            else:
                missing.append({"network": net["name"], "vlan": v.get("id"), "name": v.get("name"), "subnet": key})
    return {"networks": len(nets), "in_netbox": ok, "missing": missing, "errors": errors}


def print_meraki_vlans(r: dict, out: Out) -> None:
    out.add(f"MERAKI VLAN DRIFT  networks: {r['networks']}  subnets already in NetBox: {r['in_netbox']}")
    out.section(f"Meraki VLAN subnets with no NetBox prefix ({len(r['missing'])}) -> add the prefix",
                table(r["missing"], ["network", "vlan", "name", "subnet"]))
    for e in r["errors"]:
        out.add(f"! {e}")


def main() -> int:
    ap = argparse.ArgumentParser(description="NetBox drift reports (read-only).")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-o", "--output")
    ap.add_argument("--append", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prefixes", help="NetBox prefixes vs subnets connected on a site's cores")
    p.add_argument("--site", required=True)
    p = sub.add_parser("devices", help="devices in Catalyst Center / Meraki that NetBox lacks or names differently")
    p.add_argument("--source", choices=["catalyst", "meraki", "all"], default="all")
    p = sub.add_parser("meraki-vlans", help="Meraki MX VLAN subnets with no NetBox prefix")
    p.add_argument("--network", help="only networks whose name equals, else contains, this text")
    for sp in sub.choices.values():
        sp.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        sp.add_argument("-o", "--output", default=argparse.SUPPRESS)
        sp.add_argument("--append", action="store_true", default=argparse.SUPPRESS)
    args = ap.parse_args()

    def log(msg: str) -> None:
        print(f"... {msg}", file=sys.stderr)

    out = Out()
    if args.cmd == "prefixes":
        r = audit_prefixes(args.site, log)
        out.add(to_json(r)) if args.json else print_prefixes(r, out)
    elif args.cmd == "devices":
        r = audit_devices(args.source, log)
        out.add(to_json(r)) if args.json else print_devices(r, out)
    else:
        r = audit_meraki_vlans(args.network, log)
        out.add(to_json(r)) if args.json else print_meraki_vlans(r, out)
    out.save(args.output, args.append)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
