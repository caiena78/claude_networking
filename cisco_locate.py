"""IP/MAC -> switchport trace for cisco_helper.py (LocateMixin is mixed into CiscoRunner; it uses the runner's
resolve(), connect(), run(), nb and timeout)."""
from __future__ import annotations

import re
from typing import Any

from cisco_common import CiscoError, is_ip, mac_formats, parent_interface, validate_show
from cisco_parse import (cdp_neighbor_kind, parse_arp, parse_cdp_detail, parse_mac_table,
                         parse_port_channel_members)
from cisco_route import CORE_ISOLATED_VRFS, CORE_VRFS, default_vrf, parse_route_target


class LocateMixin:
    """locate(ip) and trace_mac(mac) for CiscoRunner."""

    def _device_for(self, name_or_ip: str, hint_ip: str = "") -> dict[str, Any]:
        """A device dict for a CDP device ID or next-hop IP: NetBox by name, then by IP assignment, else the IP."""
        import netbox_helper

        if not is_ip(name_or_ip):
            short = name_or_ip.split(".")[0].split("(")[0]
            found, _ = netbox_helper.get_devices(self.nb, tag=None, name_contains=short)
            exact = [d for d in found if d["name"].lower() in (short.lower(), name_or_ip.lower())]
            if exact:
                return exact[0]
            name_or_ip = hint_ip
        if name_or_ip:
            for row in netbox_helper.ip_lookup(self.nb, name_or_ip):
                if row["device"]:
                    found, _ = netbox_helper.get_devices(self.nb, tag=None, name_contains=row["device"])
                    exact = [d for d in found if d["name"].lower() == row["device"].lower()]
                    if exact:
                        return {**exact[0], "host": exact[0]["host"]}
            return {"name": name_or_ip, "host": name_or_ip, "device_type": "cisco_ios", "site": "", "platform": None}
        raise CiscoError("no name or IP to connect to")

    def locate(self, ip: str, vrf: str | None = None, start: list[dict[str, Any]] | None = None,
               max_hops: int = 8, log=None) -> dict[str, Any]:
        """Find the switchport where an IP lives.

        1. NetBox: the prefix (site, VLAN) and any device the IP is assigned to.
        2. Route lookup on the wan_router devices (at the prefix's site when it has some, else all),
           following next hops router by router until one has the subnet directly connected (the gateway).
        3. 'show ip arp <ip>' on the gateway for the MAC.
        4. 'show mac address-table address <mac>' switch by switch, following the port's CDP neighbor
           ('show cdp neighbors <port> detail') while it is another Cisco switch, until the access port.
        Only show commands are sent. Returns a dict with every step in 'path'."""
        import netbox_helper

        log = log or (lambda msg: None)
        target = parse_route_target(ip)
        result: dict[str, Any] = {"ip": ip, "netbox_prefix": [], "netbox_ip": [], "route_path": [], "gateway": None,
                                  "mac": None, "path": [], "location": None, "notes": []}
        result["netbox_prefix"] = netbox_helper.prefix_lookup(self.nb, ip)
        result["netbox_ip"] = netbox_helper.ip_lookup(self.nb, ip)
        site = next((p["site"] for p in result["netbox_prefix"] if p["site"]), "")

        # Step 2: where is the subnet connected?
        candidates = start
        if not candidates and site:
            try:
                candidates = self.resolve(site=site, tag="wan_router")
                if candidates:
                    log(f"NetBox: {ip} is in {result['netbox_prefix'][0]['prefix']} at site {site}")
            except (CiscoError, ValueError):
                candidates = None
        site_scoped = bool(candidates) and not start
        if not candidates:
            candidates = self.resolve(tag="wan_router")
        looked: dict[tuple, dict[str, Any]] = {}  # (host, vrf) -> route step, so each lookup runs once

        def lookup(devices: list[dict[str, Any]], use_vrf: str | None = vrf, label: str = "") -> list[dict[str, Any]]:
            new = [d for d in devices if (d["host"], use_vrf) not in looked]
            if new:
                where = "" if use_vrf is None else f" ({'VRF ' + use_vrf if use_vrf else 'global table'})"
                log(f"route lookup for {ip}{where} on {', '.join(d['name'] for d in new)}")
                for r in self.run(new, "route", ip, vrf=use_vrf):
                    dev = next(d for d in new if d["host"] == r["host"])
                    detail = r.get("route_detail") or {}
                    step = {"device": r["device"], "host": r["host"], "vrf": r.get("vrf") or "",
                            "result": r.get("route_result") or "error", "error": r["error"],
                            "prefix": detail.get("prefix", ""), "protocol": detail.get("protocol", ""),
                            "next_hops": detail.get("next_hops", []), "note": label, "_device": dev}
                    looked[(r["host"], use_vrf)] = step
                    result["route_path"].append(step)
            return [looked[(d["host"], use_vrf)] for d in devices]

        def connected(step: dict[str, Any]) -> bool:
            return step["result"] == "found" and any(h["next_hop"] == "connected" for h in step["next_hops"])

        def specific(step: dict[str, Any]) -> bool:
            return step["result"] == "found" and bool(step["prefix"]) and not step["prefix"].startswith("0.0.0.0/0")

        def best(steps: list[dict[str, Any]]) -> dict[str, Any] | None:
            usable = [s for s in steps if specific(s)]
            return max(usable, key=lambda s: int(s["prefix"].split("/")[1]) if "/" in s["prefix"] else 0) if usable else None

        steps = lookup(candidates)
        if site_scoped and not any(specific(s) for s in steps):
            # NetBox's site for the prefix may be wrong or stale: ask every WAN router instead.
            result["notes"].append(f"the wan_routers at NetBox site {site!r} have no specific route to {ip}; "
                                   "asked every wan_router (NetBox's site for this prefix may be wrong)")
            steps = lookup(self.resolve(tag="wan_router"))

        gateways: list[dict[str, Any]] = []
        current = next((s for s in steps if connected(s)), None) or best(steps)
        if not current:
            result["notes"].append("no router had a specific route to the subnet (only the default route, or none)")
        for _ in range(8):  # follow next hops router by router
            if not current:
                break
            if connected(current):
                gw_if = next(h["interface"] for h in current["next_hops"] if h["next_hop"] == "connected")
                gateways.append({**current["_device"], "interface": gw_if, "prefix": current["prefix"],
                                 "vrf": current["vrf"]})
                break
            nh = next((h for h in current["next_hops"] if h.get("active")), None) or \
                (current["next_hops"][0] if current["next_hops"] else None)
            if not nh or not is_ip(nh["next_hop"]):
                result["notes"].append(f"{current['device']} has no usable next hop for {ip}")
                break
            nxt_dev = self._device_for(nh["next_hop"], nh["next_hop"])
            log(f"{current['device']}: {ip} via {nh['next_hop']} ({nh.get('interface') or '?'}) -> {nxt_dev['name']}")
            nxt = lookup([nxt_dev])[0]
            if nxt["result"] == "error":
                result["notes"].append(
                    f"next hop {nh['next_hop']} ({nxt_dev['name']}) did not answer ({nxt['error']}); it is probably a "
                    "firewall or a non-Cisco device with the subnet behind it. Get the host's MAC from Ordr or ISE and "
                    f"run 'cisco_helper.py locate <mac> -d {current['device']}' to trace it at layer 2.")
                break
            if not specific(nxt):
                result["notes"].append(f"{nxt['device']} has no specific route to {ip} "
                                       f"({'VRF ' + nxt['vrf'] if nxt['vrf'] else 'global table'})")
                break
            current = nxt
        if not gateways and vrf is None:
            # Isolated networks: on the CORE_VRFS cores, VRF div and the global table hold networks that are not
            # routed to the WAN, so a WAN trace never finds them. Ask those cores directly, NetBox's site first.
            sites = sorted(CORE_VRFS, key=lambda name: name != site)
            for core_site in sites:
                found, _ = netbox_helper.get_devices(self.nb, tag=None, site=core_site, role="core")
                cores = [d for d in found if is_ip(d["host"])]
                for iso_vrf in CORE_ISOLATED_VRFS:
                    hit = next((s for s in lookup(cores, iso_vrf, "isolated") if connected(s)), None)
                    if hit:
                        gw_if = next(h["interface"] for h in hit["next_hops"] if h["next_hop"] == "connected")
                        gateways.append({**hit["_device"], "interface": gw_if, "prefix": hit["prefix"], "vrf": iso_vrf})
                        result["notes"].append(
                            f"{ip} is on an isolated network ({'VRF ' + iso_vrf if iso_vrf else 'global table'}) on "
                            f"{hit['device']} at {core_site}: it is not routed to the WAN")
                        break
                if gateways:
                    break
        if not gateways:
            if "meraki" in site.lower():
                result["notes"].append(f"NetBox puts this prefix at site {site!r}: it is behind a Meraki MX. "
                                       f"Use 'meraki_helper.py client {ip}' (add --network to make it faster).")
            result["notes"].append("did not find a router with the subnet directly connected. If the IP is in a "
                                   "Meraki network, try meraki_helper.py client <ip>.")
            for s in result["route_path"]:
                s.pop("_device", None)
            return result
        for s in result["route_path"]:
            s.pop("_device", None)
        gw_site = gateways[0].get("site") or ""
        if site and gw_site and gw_site != site:
            result["notes"].append(f"NetBox puts {result['netbox_prefix'][0]['prefix']} at site {site!r}, but it is "
                                   f"connected on {gateways[0]['name']} at {gw_site!r}: NetBox's site looks wrong")

        # Step 3: ARP on the gateway(s); HSRP pairs both have the subnet connected, so try each.
        arp = None
        for gw in gateways:
            gw_vrf = vrf if vrf is not None else (gw["vrf"] if "vrf" in gw else default_vrf(gw))
            command = validate_show(f"show ip arp {'vrf ' + gw_vrf + ' ' if gw_vrf else ''}{ip}")
            try:
                with self.connect(gw) as conn:
                    out = conn.send_command(command, read_timeout=self.timeout * 2)
            except Exception as exc:  # noqa: BLE001 - try the other gateway
                result["notes"].append(f"could not reach gateway {gw['name']}: {type(exc).__name__}")
                continue
            arp = parse_arp(out, ip)
            log(f"{gw['name']}: {command} -> {arp['mac'] + ' on ' + arp['interface'] if arp else 'no entry'}")
            if arp:
                result["gateway"] = {"device": gw["name"], "host": gw["host"], "interface": gw["interface"],
                                     "prefix": gw["prefix"], "arp_interface": arp["interface"]}
                break
        if not arp:
            result["gateway"] = {"device": gateways[0]["name"], "host": gateways[0]["host"],
                                 "interface": gateways[0]["interface"], "prefix": gateways[0]["prefix"]}
            result["notes"].append("no ARP entry on the gateway: the host is probably offline or silent")
            return result
        mac = arp["mac"]
        result["mac"] = mac_formats(mac)
        gw = next(g for g in gateways if g["name"] == result["gateway"]["device"])

        return self.trace_mac(mac, gw, result, arp["interface"], max_hops, log)

    def trace_mac(self, mac: str, device: dict[str, Any], result: dict[str, Any] | None = None, arp_if: str = "",
                  max_hops: int = 8, log=None) -> dict[str, Any]:
        """Follow a MAC from a device down to its access port: MAC table, then the port's CDP neighbor while it
        is another Cisco switch. arp_if is the gateway's ARP interface (used when it is a routed interface)."""
        log = log or (lambda msg: None)
        mac = mac_formats(mac)["cisco"]
        if result is None:
            result = {"ip": None, "netbox_prefix": [], "netbox_ip": [], "route_path": [], "gateway": None,
                      "mac": mac_formats(mac), "path": [], "location": None, "notes": []}
        gw = device
        seen: set[str] = set()
        for _ in range(max_hops):
            if device["host"] in seen:
                result["notes"].append(f"loop detected at {device['name']}")
                break
            seen.add(device["host"])
            hop: dict[str, Any] = {"device": device["name"], "host": device["host"], "port": "", "vlan": "",
                                   "neighbor": None, "error": None}
            result["path"].append(hop)
            try:
                with self.connect(device) as conn:
                    def show(cmd: str) -> str:
                        return conn.send_command(validate_show(cmd), read_timeout=self.timeout * 2)

                    rows = parse_mac_table(show(f"show mac address-table address {mac}"), mac)
                    if rows:
                        hop["port"], hop["vlan"] = rows[0]["port"], rows[0]["vlan"]
                    elif device is gw and arp_if and not arp_if.lower().startswith("vlan"):
                        hop["port"] = parent_interface(arp_if)  # routed (sub)interface: the L2 next is its neighbor
                    else:
                        hop["error"] = "MAC not in this device's MAC address table"
                        if device is gw and arp_if:
                            result["notes"].append("the gateway has an ARP entry but the MAC has aged out of the MAC "
                                                   "table (the host has been idle); try again once it sends traffic")
                        break
                    port = hop["port"]
                    if re.match(r"^(Po|Port-channel)", port, re.I):
                        summary = show("show port-channel summary" if device["device_type"] == "cisco_nxos"
                                       else "show etherchannel summary")
                        members = parse_port_channel_members(summary, port)
                        hop["port_channel_members"] = members
                        port = members[0] if members else port
                    cdp_cmd = (f"show cdp neighbors interface {port} detail" if device["device_type"] == "cisco_nxos"
                               else f"show cdp neighbors {port} detail")
                    neighbors = parse_cdp_detail(show(cdp_cmd))
                    switch = next((n for n in neighbors if cdp_neighbor_kind(n) == "switch"), None)
                    other = next((n for n in neighbors if cdp_neighbor_kind(n) != "switch"), None)
                    log(f"{device['name']}: {mac} on {hop['port']} vlan {hop['vlan'] or '?'}"
                        + (f" -> CDP {(switch or other)['device_id']} ({(switch or other)['platform']})" if (switch or other) else ""))
                    if switch:
                        hop["neighbor"] = {**switch, "kind": "switch"}
                        device = self._device_for(switch["device_id"], switch["ip"])
                        continue
                    # Access port: record port status and whatever is attached (phone, AP, Meraki switch).
                    hop["neighbor"] = {**other, "kind": cdp_neighbor_kind(other)} if other else None
                    status = show(f"show interfaces {hop['port']} status")
                    hop["port_status"] = next((l.strip() for l in status.splitlines()
                                               if l.strip() and not l.lstrip().startswith(("Port", "-"))), "")
                    result["location"] = {"switch": device["name"], "host": device["host"], "port": hop["port"],
                                          "vlan": hop["vlan"], "port_status": hop["port_status"],
                                          "attached": hop["neighbor"]}
                    kind = (hop["neighbor"] or {}).get("kind")
                    if kind == "phone":
                        result["notes"].append("the host is behind an IP phone on this port")
                    elif kind == "ap":
                        result["notes"].append("this port goes to an access point: the host is a wireless client "
                                               "(check catalyst_helper.py client <mac> or ise_helper.py auth <mac>)")
                    elif kind == "meraki":
                        result["notes"].append("this port goes to a Meraki device: continue with "
                                               "meraki_helper.py client <mac>")
                    break
            except Exception as exc:  # noqa: BLE001 - report where the trace stopped
                hop["error"] = f"could not connect or run commands: {type(exc).__name__}"
                break
        else:
            result["notes"].append(f"stopped after {max_hops} switches")
        return result


def format_locate(r: dict[str, Any]) -> str:
    """Human-readable summary of a locate() result."""
    lines = [f"Locate {r['ip'] or r['mac']['colon']}"]
    for p in r["netbox_prefix"][:1]:
        lines.append(f"  NetBox prefix   {p['prefix']}  site {p['site'] or '?'}  vlan {p['vlan'] or '?'}  vrf {p['vrf'] or 'global'}"
                     + (f"  ({p['description']})" if p["description"] else ""))
    for a in r["netbox_ip"]:
        lines.append(f"  NetBox IP       {a['address']} assigned to {a['device'] or '?'} {a['interface']}  {a['dns_name']}".rstrip())
    for step in r["route_path"]:
        hops = "; ".join(f"{h['next_hop']} via {h.get('interface') or '?'}" for h in step["next_hops"])
        vrf_label = f"[vrf {step['vrf']}] " if step.get("vrf") else ""
        if step.get("note") == "isolated":
            vrf_label = f"[isolated: {'vrf ' + step['vrf'] if step['vrf'] else 'global'}] "
        lines.append(f"  route           {step['device']:<22} {step['result']:<9} {vrf_label}{step['prefix']} {step['protocol']} {hops}"
                     .rstrip() + (f"  {step['error']}" if step["error"] and step["result"] != "found" else ""))
    if r["gateway"]:
        g = r["gateway"]
        lines.append(f"  gateway         {g['device']} ({g['host']}) {g['interface']}  {g['prefix']}")
    if r["mac"]:
        lines.append(f"  MAC             {r['mac']['cisco']}  ({r['mac']['colon']})")
    for hop in r["path"]:
        n = hop.get("neighbor")
        via = f" -> {n['device_id']} {n['remote_port']} [{n['kind']}: {n['platform']}]" if n else ""
        members = f" ({', '.join(hop['port_channel_members'])})" if hop.get("port_channel_members") else ""
        lines.append(f"  L2 hop          {hop['device']:<22} port {hop['port'] or '?'}{members} vlan {hop['vlan'] or '?'}{via}"
                     + (f"  ERROR: {hop['error']}" if hop["error"] else ""))
    loc = r["location"]
    if loc:
        lines.append(f"  LOCATION        {loc['switch']} ({loc['host']}) port {loc['port']} vlan {loc['vlan'] or '?'}")
        if loc.get("port_status"):
            lines.append(f"  port status     {loc['port_status']}")
    else:
        lines.append("  LOCATION        not found")
    for note in r["notes"]:
        lines.append(f"  note            {note}")
    return "\n".join(lines)
