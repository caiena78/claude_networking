"""One-command answers that combine the other helpers. Read-only.

    python endpoint_helper.py whois 10.158.0.139            # what and where is this IP / MAC?
    python endpoint_helper.py whois ac:b4:80:b9:a0:1f --all
    python endpoint_helper.py path 10.194.23.182 10.194.2.10 --port 443 [--proto tcp]

whois <ip|mac>
    1. NetBox: the prefix (site, VLAN, VRF) and any device the IP is assigned to.
    2. Where it is plugged in: for an IP, cisco_helper locate (WAN routers -> gateway ARP -> MAC table / CDP ->
       access switchport). Skip with --no-trace.
    3. What it is, in the team's lookup order, stopping at the first system that knows it (--all asks every one):
       Ordr (identity, profile, risk), then ISE (authentication, switch/WLC and port), then Catalyst Center
       (assurance: AP/switch, SSID, VLAN, health).
    4. Meraki: if the prefix is at a Meraki site, or nothing above knew the MAC, the org-wide Meraki client search.

path <src> <dst> --port <port>
    NetBox site/VLAN for both ends, then every CDO-managed FTD between them (from each firewall's interface
    subnets and static routes), and for each firewall the policy verdict in evaluation order: the prefilter
    policy first (FASTPATH or BLOCK ends it), then the access control policy (first match, else its default
    action), plus any NAT rule that rewrites the destination. Firewalls that CDO doesn't manage (Meraki MX,
    other vendors) aren't seen. For proof with live traffic, use ftd_capture_helper.py.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import ipaddress
import sys
from typing import Any

from helper_common import Out, is_mac, mac_colon, table, to_json


def _try(label: str, fn, errors: list[str]):
    """Run one lookup; a failing system is reported, never fatal."""
    try:
        return fn()
    except SystemExit as exc:
        errors.append(f"{label}: {exc}")
    except Exception as exc:  # noqa: BLE001 - one system being down must not stop the others
        errors.append(f"{label}: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}")
    return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# whois
# ---------------------------------------------------------------------------

ORDR_KEYS = ["MacAddress", "IpAddress", "dhcpHostname", "Group", "Profile", "MfgName", "ModelNameNo", "OsType",
             "Vlan", "RiskState", "connStatus", "nwEquipHostname", "nwEquipInterface", "essid", "deviceLocation",
             "lastSeen"]


def whois(value: str, trace: bool = True, ask_all: bool = False, log=None) -> dict[str, Any]:
    log = log or (lambda msg: None)
    errors: list[str] = []
    res: dict[str, Any] = {"query": value, "ip": None, "mac": None, "netbox": {}, "location": None,
                           "identity": {}, "meraki": None, "errors": errors}
    if _is_ip(value):
        res["ip"] = value
    elif is_mac(value):
        res["mac"] = mac_colon(value)
    else:
        raise SystemExit(f"{value!r} is not an IP address or a MAC")

    # 1. NetBox
    if res["ip"]:
        import vault_helper
        import netbox_helper

        def nb_lookup():
            c = vault_helper.get_secrets(interactive=False)
            nb = netbox_helper.connect(c["netbox_url"], c["netbox_token"])
            return {"prefix": netbox_helper.prefix_lookup(nb, res["ip"]), "ip": netbox_helper.ip_lookup(nb, res["ip"])}
        log("NetBox prefix / IP lookup")
        res["netbox"] = _try("NetBox", nb_lookup, errors) or {}
    site = next((p["site"] for p in res["netbox"].get("prefix", []) if p["site"]), "")
    meraki_site = "meraki" in site.lower()

    # 2. Where it is plugged in (IP only; Meraki sites are traced by Meraki instead)
    if res["ip"] and trace and not meraki_site:
        import cisco_helper

        log("tracing the IP to its switchport (cisco_helper locate)")
        loc = _try("locate", lambda: cisco_helper.CiscoRunner().locate(res["ip"], log=lambda m: log(f"  {m}")), errors)
        if loc:
            res["location"] = {k: loc.get(k) for k in ("gateway", "location", "notes")}
            if loc.get("mac"):
                res["mac"] = loc["mac"]["colon"]

    # 3. Identity: Ordr -> ISE -> Catalyst Center
    def ordr():
        from ordr_helper import Ordr
        found = Ordr().device(res["mac"] or res["ip"])
        return [{k: d.get(k) for k in ORDR_KEYS if d.get(k) not in (None, "")} for d in found] or None

    log("Ordr")
    res["identity"]["ordr"] = _try("Ordr", ordr, errors)
    if not res["mac"] and res["identity"]["ordr"]:
        res["mac"] = mac_colon(res["identity"]["ordr"][0].get("MacAddress") or "")

    if ask_all or not res["identity"]["ordr"]:
        def ise():
            from ise_helper import ISE, SESSION_FIELDS
            i = ISE()
            if res["mac"]:
                looked = i.lookup(res["mac"])
                sess = looked.get("session")
                out = {"endpoint": {k: (looked.get("endpoint") or {}).get(k) for k in ("mac", "groupId", "profileId",
                                                                                    "staticGroupAssignment", "description")
                                    if (looked.get("endpoint") or {}).get(k)} or None,
                       "session": {k: sess.get(k) for k in SESSION_FIELDS if sess and sess.get(k) not in (None, "")} or None}
                if not out["session"]:
                    recent = i.auth_status(res["mac"], hours=24, records=1)
                    out["last_auth"] = {k: recent[0].get(k) for k in SESSION_FIELDS
                                        if recent and recent[0].get(k) not in (None, "")} or None
                return out if any(out.values()) else None
            sess = i.session(res["ip"])
            return {"session": {k: sess.get(k) for k in SESSION_FIELDS if sess.get(k) not in (None, "")}} if sess else None
        log("ISE")
        res["identity"]["ise"] = _try("ISE", ise, errors)

    if (ask_all or not any(res["identity"].values())) and res["mac"]:
        def catalyst():
            from catalyst_helper import Catalyst
            c = Catalyst().client(res["mac"])
            if not c:
                return None
            dev = c.get("connectedNetworkDevice") or {}
            return {"name": c.get("name"), "ip": c.get("ipv4Address"), "user": c.get("username"), "type": c.get("type"),
                    "deviceType": c.get("deviceType"), "status": c.get("connectionStatus"), "site": c.get("siteHierarchy"),
                    "connectedTo": dev.get("connectedNetworkDeviceName"), "interface": dev.get("interfaceName"),
                    "ssid": (c.get("connection") or {}).get("ssid"), "vlan": (c.get("connection") or {}).get("vlanId"),
                    "health": (c.get("health") or {}).get("overallScore")}
        log("Catalyst Center")
        res["identity"]["catalyst"] = _try("Catalyst", catalyst, errors)

    # 4. Meraki
    if res["mac"] and (meraki_site or ask_all or not any(res["identity"].values())):
        def meraki():
            from meraki_helper import Meraki
            found = Meraki().client_search(res["mac"])
            return [{"network": (r.get("network") or {}).get("name"), "ip": r.get("ip"), "vlan": r.get("vlan"),
                     "ssid": r.get("ssid"), "switchport": r.get("switchport"), "description": r.get("description"),
                     "status": r.get("status"), "lastSeen": r.get("lastSeen")} for r in found.get("records", [])] or None
        log("Meraki")
        res["meraki_asked"] = True
        res["meraki"] = _try("Meraki", meraki, errors)
    elif meraki_site and res["ip"] and not res["mac"]:
        res["errors"].append(f"NetBox puts this prefix at {site!r} (Meraki). For an IP-only lookup run "
                             f"'meraki_helper.py client {res['ip']} --network <network>'.")
    return res


def print_whois(res: dict, out: Out) -> None:
    out.add(f"WHOIS {res['query']}")
    out.add(f"  IP {res['ip'] or '?'}   MAC {res['mac'] or '?'}")
    for p in res["netbox"].get("prefix", [])[:1]:
        out.add(f"  NetBox prefix  {p['prefix']}  site {p['site'] or '?'}  vlan {p['vlan'] or '?'}  vrf {p['vrf'] or 'global'}"
                + (f"  ({p['description']})" if p.get("description") else ""))
    for a in res["netbox"].get("ip", []):
        out.add(f"  NetBox IP      assigned to {a['device'] or '?'} {a['interface']} {a['dns_name']}".rstrip())
    loc = res.get("location") or {}
    if loc.get("location"):
        L = loc["location"]
        out.add(f"  Plugged in     {L['switch']} ({L['host']}) port {L['port']} vlan {L['vlan'] or '?'}")
        if L.get("attached"):
            out.add(f"                 behind {L['attached'].get('kind')}: {L['attached'].get('device_id')}")
    elif loc.get("gateway"):
        out.add(f"  Gateway        {loc['gateway']['device']} {loc['gateway']['interface']} (switchport not found)")
    for note in loc.get("notes") or []:
        out.add(f"                 note: {note}")
    ident = res["identity"]
    if ident.get("ordr"):
        out.add("\n  Ordr")
        out.add("    " + table(ident["ordr"], ["MacAddress", "IpAddress", "dhcpHostname", "Group", "Profile", "MfgName",
                                               "RiskState", "nwEquipHostname", "nwEquipInterface", "lastSeen"]).replace("\n", "\n    "))
    for name in ("ise", "catalyst"):
        if ident.get(name):
            out.add(f"\n  {name.upper() if name == 'ise' else 'Catalyst Center'}")
            out.add("    " + to_json(ident[name]).replace("\n", "\n    "))
    if res.get("meraki"):
        out.add("\n  Meraki")
        out.add("    " + table(res["meraki"], ["network", "ip", "vlan", "ssid", "switchport", "description", "status", "lastSeen"])
                .replace("\n", "\n    "))
    empty = [n for n, v in ident.items() if not v] + (["meraki"] if res.get("meraki_asked") and not res.get("meraki") else [])
    if empty:
        out.add(f"\n  No record in: {', '.join(empty)}")
    for e in res["errors"]:
        out.add(f"  ! {e}")


# ---------------------------------------------------------------------------
# path
# ---------------------------------------------------------------------------

def _iface_networks(cdo, device_id: str) -> list[tuple]:
    """[(network, nameif, zone)] for a device's interfaces with a static IPv4 address."""
    nets = []
    for it in cdo.interfaces(device_id):
        st = ((it.get("ipv4") or {}).get("static") or {})
        if st.get("address") and st.get("netmask"):
            try:
                net = ipaddress.ip_network(f"{st['address']}/{st['netmask']}", strict=False)
            except ValueError:
                continue
            nets.append((net, it.get("ifname") or it.get("name"), (it.get("securityZone") or {}).get("name")))
    return nets


_ROUTES: dict[str, list] = {}


def _route_iface(cdo, device_id: str, ip: ipaddress.IPv4Address, iface_zone: dict,
                 specific_only: bool = False) -> tuple | None:
    """(nameif, zone, how) for ip on a firewall from its most specific static route. With specific_only,
    a default route (0.0.0.0/0) doesn't count."""
    import cdo_helper as C

    if device_id not in _ROUTES:
        _ROUTES[device_id] = cdo.static_routes(device_id)
    best = None
    for r in _ROUTES[device_id]:
        for obj in r.get("selectedNetworks") or []:
            elements, _ = C.resolve_network(obj, "")
            for ver, lo, hi, _label in elements:
                if ver == 4 and lo <= int(ip) <= hi:
                    size = hi - lo
                    if specific_only and size >= 2 ** 32 - 1:
                        continue
                    if best is None or size < best[0]:
                        best = (size, r.get("interfaceName"), obj.get("name"))
    if best:
        return best[1], iface_zone.get(best[1]), f"static route {best[2]}"
    return None


def path(src: str, dst: str, port: str, proto: str = "tcp", log=None, all_firewalls: bool = False) -> dict[str, Any]:
    import cdo_helper as C

    log = log or (lambda msg: None)
    errors: list[str] = []
    res: dict[str, Any] = {"src": src, "dst": dst, "port": f"{proto}/{port}", "netbox": {}, "firewalls": [], "errors": errors}

    import vault_helper
    import netbox_helper

    def nb():
        c = vault_helper.get_secrets(interactive=False)
        n = netbox_helper.connect(c["netbox_url"], c["netbox_token"])
        return {side: (netbox_helper.prefix_lookup(n, ip) or [None])[0] for side, ip in (("src", src), ("dst", dst))}
    log("NetBox prefixes")
    res["netbox"] = _try("NetBox", nb, errors) or {}

    cdo = C.client()
    log("loading CDO objects")
    with contextlib.redirect_stdout(io.StringIO()):
        C.preload_objects()
    s_ip, d_ip = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    secondaries = {(h.get("secondary") or {}).get("name") for h in cdo.ha_pairs()}
    req = C.parse_requested_ports(f"{proto}/{port}" if proto != "icmp" else "icmp")
    for dev in cdo.devices():
        if dev["name"] in secondaries:
            continue  # same config as the primary
        log(f"checking {dev['name']}")
        nets = _try(f"{dev['name']} interfaces", lambda: _iface_networks(cdo, dev["id"]), errors) or []
        zones = {n[1]: n[2] for n in nets}
        side = {}
        for label, ip in (("src", s_ip), ("dst", d_ip)):
            # Connected subnet first, then the most specific static route (a default route says nothing).
            side[label] = next(((n[1], n[2], f"connected {n[0]}") for n in nets if ip in n[0]), None) or _try(
                f"{dev['name']} routes", lambda: _route_iface(cdo, dev["id"], ip, zones, specific_only=True), errors)
        if not (side["src"] or side["dst"]):
            continue  # this firewall knows neither end specifically: not on the path
        for label, ip in (("src", s_ip), ("dst", d_ip)):
            if not side[label]:
                side[label] = _try(f"{dev['name']} routes", lambda: _route_iface(cdo, dev["id"], ip, zones), errors) \
                    or ("?", None, "no route found (default route?)")
        if side["src"][0] == side["dst"][0] and side["src"][0] != "?":
            continue  # both ends behind the same interface: traffic doesn't cross this firewall
        # "on path": both ends reached by connected subnets or specific routes. "possible": one end only via a
        # default route (e.g. an internet firewall that summarises RFC1918 inside) - listed, not evaluated.
        defaultish = [s for s in side.values() if s[0] == "?" or "any-ipv4" in s[2] or "0.0.0.0" in s[2]]
        fw: dict[str, Any] = {"device": dev["name"], "ingress": side["src"], "egress": side["dst"],
                              "confidence": "possible" if defaultish else "on path"}
        if defaultish and not all_firewalls:
            res["firewalls"].append(fw)
            continue
        pols = _try(f"{dev['name']} policies", lambda: cdo.policies_for_device(dev["name"]), errors) or {}
        fw["policies"] = pols
        # Prefilter first
        verdict, reason = None, ""
        if pols.get("PrefilterPolicy"):
            rules = cdo.prefilter_rules(cdo.prefilter_policy(pols["PrefilterPolicy"])["id"])
            with contextlib.redirect_stdout(io.StringIO()):
                first = C.check_ports(rules, C.Target(src), C.Target(dst), req, pols["PrefilterPolicy"])
            hit = next(iter(first.values()))
            if hit:
                rule = hit[0]
                fw["prefilter"] = f"#{rule['metadata']['ruleIndex']} {rule['name']} ({rule.get('action')})"
                if rule.get("action") == "FASTPATH":
                    verdict, reason = "ALLOWED", f"prefilter FASTPATH {fw['prefilter']} (access policy skipped)"
                elif rule.get("action") == "BLOCK":
                    verdict, reason = "DENIED", f"prefilter BLOCK {fw['prefilter']}"
            else:
                fw["prefilter"] = "no match (goes on to the access policy)"
        # Then the access control policy
        if verdict is None and pols.get("AccessPolicy"):
            pol = cdo.access_policy(pols["AccessPolicy"])
            acp = C.acp_evaluate(cdo.access_rules(pol["id"]), (pol.get("defaultAction") or {}).get("action"),
                                 C.Target(src), C.Target(dst), req)
            a = next(iter(acp.values()))
            rule = a["rule"]
            fw["access"] = (f"#{rule['metadata']['ruleIndex']} {rule['name']} ({a['action']})" if rule
                            else a["action"])
            fw["access_passed_over"] = [s[0]["name"] for s in a["skipped"]]
            verdict, reason = a["verdict"], f"access policy {pols['AccessPolicy']}: {fw['access']}"
        fw["verdict"], fw["reason"] = verdict or "UNKNOWN", reason or "no prefilter or access policy found"
        if pols.get("FTDNatPolicy"):
            nat = cdo.nat_rules(cdo.nat_policy(pols["FTDNatPolicy"])["id"])
            fw["nat"] = [f"{h['rule']['kind']} {h['rule'].get('natType', '')}: "
                         + ", ".join(f"{k}={v}" for k, v in h["fields"].items())
                         for h in C.nat_matches(nat, C.Target(dst))]
        res["firewalls"].append(fw)
    return res


def print_path(res: dict, out: Out) -> None:
    out.add(f"PATH {res['src']} -> {res['dst']} {res['port']}")
    for side in ("src", "dst"):
        p = res["netbox"].get(side)
        out.add(f"  {side}  {res[side]:15}  " + (f"{p['prefix']}  site {p['site'] or '?'}  vlan {p['vlan'] or '?'}  vrf {p['vrf'] or 'global'}"
                                                 if p else "(no NetBox prefix)"))
    if not res["firewalls"]:
        out.add("\n  No CDO-managed FTD has either end on a connected interface: the traffic doesn't cross one of them")
        out.add("  (it may still cross a Meraki MX or a non-Cisco firewall, which this can't see).")
    possible = [f for f in res["firewalls"] if f["confidence"] == "possible" and "verdict" not in f]
    for fw in [f for f in res["firewalls"] if f not in possible]:
        i, e = fw["ingress"], fw["egress"]
        out.add(f"\n  Firewall {fw['device']}  [{fw['confidence']}]")
        out.add(f"    in  {i[0]} ({'zone ' + i[1] + ', ' if i[1] else ''}{i[2]})")
        out.add(f"    out {e[0]} ({'zone ' + e[1] + ', ' if e[1] else ''}{e[2]})")
        if "prefilter" in fw:
            out.add(f"    prefilter  {fw['policies'].get('PrefilterPolicy')}: {fw['prefilter']}")
        if "access" in fw:
            out.add(f"    access     {fw['policies'].get('AccessPolicy')}: {fw['access']}")
            skipped = fw.get("access_passed_over") or []
            if skipped:
                out.add(f"               passed over {len(skipped)} rule(s) with app/URL/user conditions that may match "
                        f"first: {', '.join(skipped[:3])}{' ...' if len(skipped) > 3 else ''}")
        for n in fw.get("nat") or []:
            out.add(f"    NAT        {n}")
        out.add(f"    VERDICT    {fw['verdict']} - {fw['reason']}")
    if possible:
        out.add("\n  Possible (one end reached only via a default route; not evaluated - use --all-firewalls):")
        for fw in possible:
            out.add(f"    {fw['device']:26} {fw['ingress'][0]} -> {fw['egress'][0]}  ({fw['ingress'][2]} / {fw['egress'][2]})")
    out.add("\n  Policy verdicts ignore zones/interfaces on rules. To prove it with live traffic, run a capture with "
            "ftd_capture_helper.py (if the firewall is in FTD_CAPTURE_HOSTS).")
    for e in res["errors"]:
        out.add(f"  ! {e}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Read-only answers that combine the other helpers.")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-o", "--output", help="also write the output to this file")
    ap.add_argument("--append", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("whois", help="what and where is this IP or MAC")
    p.add_argument("value", help="IP address or MAC (any format)")
    p.add_argument("--no-trace", action="store_true", help="don't trace an IP to its switchport")
    p.add_argument("--all", action="store_true", help="ask Ordr, ISE and Catalyst even after one knows the device")
    p = sub.add_parser("path", help="which CDO firewalls sit between two IPs, and what their policies decide")
    p.add_argument("src")
    p.add_argument("dst")
    p.add_argument("--port", required=True, help="destination port, e.g. 443 (or 0 with --proto icmp)")
    p.add_argument("--proto", default="tcp", choices=["tcp", "udp", "icmp"])
    p.add_argument("--all-firewalls", action="store_true", help="also evaluate policies on 'possible' firewalls")
    for sp in sub.choices.values():
        sp.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        sp.add_argument("-o", "--output", default=argparse.SUPPRESS)
        sp.add_argument("--append", action="store_true", default=argparse.SUPPRESS)
    args = ap.parse_args()

    def log(msg: str) -> None:
        print(f"... {msg}", file=sys.stderr)

    out = Out()
    if args.cmd == "whois":
        res = whois(args.value, trace=not args.no_trace, ask_all=args.all, log=log)
        out.add(to_json(res)) if args.json else print_whois(res, out)
    else:
        for ip in (args.src, args.dst):
            if not _is_ip(ip):
                raise SystemExit(f"{ip!r} is not an IP address")
        res = path(args.src, args.dst, args.port, args.proto, log=log, all_firewalls=args.all_firewalls)
        out.add(to_json(res)) if args.json else print_path(res, out)
    out.save(args.output, args.append)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
