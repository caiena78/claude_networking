"""Run read-only show commands on Cisco devices (IOS, IOS-XE, NX-OS) over SSH.

Credentials come from Vault (ansible_user / ansible_password / ansible_become_password, see
vault_helper.py). Devices are picked by name or IP (-d), or by NetBox site / tag / name filters.
Only `show` commands are ever sent, and secrets in config output are masked.

Usage:
    python cisco_helper.py uptime -d tls-wan-rtr-01 -d tls-wan-rtr-02
    python cisco_helper.py uptime --site Lakeside --tag wan_router
    python cisco_helper.py interfaces -d 10.158.136.51
    python cisco_helper.py interface Te0/1/0 -d tls-wan-rtr-01
    python cisco_helper.py log -d tls-wan-rtr-01 --lines 100
    python cisco_helper.py section "router bgp" -d tls-wan-rtr-01
    python cisco_helper.py bgp --tag wan_router
    python cisco_helper.py show "show ip nat translations total" -d tls-wan-rtr-01
    python cisco_helper.py route 10.158.10.1                      # route lookup on every wan_router device
    python cisco_helper.py route 10.158.8.0/24 --site Lakeside --vrf CORP
    python cisco_helper.py locate 10.158.0.139                    # trace an IP to its access switchport
    python cisco_helper.py locate ac:b4:80:b9:a0:1f -d lv-mdf-core-9500(1)   # trace a MAC from a starting device
    python cisco_helper.py list                         # list the built-in commands

As a module:
    from cisco_helper import CiscoRunner
    runner = CiscoRunner()
    devices = runner.resolve(names=["tls-wan-rtr-01"])
    results = runner.run(devices, "uptime")

Exit codes: 0 = every device answered, 1 = at least one device failed, 2 = setup error.
For `route <ip>`: 0 = at least one device has the route, 1 = none has it, 2 = setup error.
For `locate`: 0 = switchport found, 1 = not found, 2 = setup error.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from helper_common import table

# name: (help text, IOS / IOS-XE command, NX-OS command or None for "same", argument: None / "required" / "optional")
# In commands, {arg} is replaced with the argument. Optional-argument commands list the no-argument form after "||".
COMMANDS: dict[str, tuple[str, str, str | None, str | None]] = {
    "version":      ("show version", "show version", None, None),
    "uptime":       ("uptime, last restart and reload reason",
                     "show version | include uptime|restarted|reload reason|returned to ROM",
                     "show version | include uptime|reason", None),
    "interfaces":   ("IP interface summary (show ip interface brief)", "show ip interface brief",
                     "show ip interface brief vrf all", None),
    "status":       ("switchport status (show interfaces status)", "show interfaces status", None, None),
    "desc":         ("interface descriptions", "show interfaces description", "show interface description", None),
    "interface":    ("one interface in detail, e.g. Te0/1/0", "show interfaces {arg}", "show interface {arg}", "required"),
    "errors":       ("interface error counters",
                     "show interfaces | include line protocol|input errors|CRC|output errors|drops",
                     "show interface counters errors", None),
    "transceivers": ("optic levels", "show interfaces transceiver", "show interface transceiver details", None),
    "run":          ("running config (secrets masked)", "show running-config", None, None),
    "section":      ("running-config section, e.g. 'router bgp'", "show running-config | section {arg}",
                     "show running-config | section {arg}", "required"),
    "log":          ("recent log messages (see --lines)", "show logging", None, None),
    "inventory":    ("hardware inventory and serials", "show inventory", None, None),
    "cdp":          ("CDP neighbors", "show cdp neighbors", None, None),
    "cdp-detail":   ("CDP neighbors with IPs and platforms", "show cdp neighbors detail", None, None),
    "lldp":         ("LLDP neighbors", "show lldp neighbors", None, None),
    "arp":          ("ARP table, optionally for one IP", "show ip arp {arg}||show ip arp", None, "optional"),
    "mac":          ("MAC address table, optionally for one MAC",
                     "show mac address-table address {arg}||show mac address-table", None, "optional"),
    "route":        ("route lookup for an IP/prefix (defaults to all wan_router devices; --vrf), or the full table",
                     "show ip route {arg}||show ip route", None, "optional"),
    "bgp":          ("BGP neighbor summary", "show ip bgp summary", "show bgp ipv4 unicast summary", None),
    "ospf":         ("OSPF neighbors", "show ip ospf neighbor", None, None),
    "eigrp":        ("EIGRP neighbors", "show ip eigrp neighbors", None, None),
    "standby":      ("HSRP status", "show standby brief", "show hsrp brief", None),
    "vrrp":         ("VRRP status", "show vrrp brief", None, None),
    "vlan":         ("VLANs", "show vlan brief", None, None),
    "stp":          ("spanning-tree summary", "show spanning-tree summary", None, None),
    "power":        ("PoE usage", "show power inline", None, None),
    "cpu":          ("top CPU processes", "show processes cpu sorted", "show system resources", None),
    "memory":       ("memory usage", "show memory statistics", "show system resources", None),
    "env":          ("fans, power supplies, temperature", "show environment", None, None),
    "ntp":          ("NTP associations", "show ntp associations", "show ntp peer-status", None),
    "clock":        ("device clock", "show clock", None, None),
    "users":        ("logged-in users", "show users", None, None),
    "sla":          ("IP SLA status", "show ip sla summary", None, None),
    "license":      ("license summary", "show license summary", "show license usage", None),
    "wlans":        ("WLAN / SSID summary (Catalyst 9800)", "show wlan summary", None, None),
    "ssid":         ("everything for one SSID on a 9800: WLAN profile, policy tags, policy profiles, show wlan",
                     "show wlan summary", None, "required"),
    "ssid-auth":    ("clients on one SSID by EAP type (PEAP, EAP-TLS...) on 9800 WLCs; defaults to every 9800 in NetBox",
                     "show wlan summary", None, "required"),
    "ssid-count":   ("clients per SSID on a 9800 (one show wlan summary + one client summary); "
                     "defaults to every 9800 in NetBox", "show wlan summary", None, None),
    "wclient":      ("wireless client by MAC on the WLCs (9800 and AireOS): AP, SSID, VLAN, IP, state, user; "
                     "defaults to every WLC in NetBox", "show wireless client mac-address {arg} detail", None, "required"),
}
# IOS-XE has better resource views than classic IOS.
XE_OVERRIDES = {"memory": "show platform resources"}

# Output of these commands can include config, so secrets are masked.
CONFIG_WORDS = re.compile(r"\b(run|running-config|startup-config|config|tech)", re.I)
# Greedy ".*" so the LAST keyword on the line is used, e.g. "message-digest-key 1 md5 7 <secret>".
SECRET_LINE = re.compile(
    r"(?i)^(.*\b(?:secret|password|key-string|key|community|server-key|pre-shared-key|auth-key|"
    r"authentication-key|md5)\b(?:\s+[0-9]{1,2})?\s+)(?!Management\b)(\S+)(.*)$"  # not "Auth Key Management"
)
DESCRIPTION_LINE = re.compile(r"^\s*description\s", re.I)
# WLAN PSKs: "security wpa psk set-key ascii 8 <key>", MPSK "priority 0 set-key ascii 0 <key>".
SET_KEY_LINE = re.compile(r"(?i)^(.*\bset-key\s+(?:ascii|hex)\s+\d+\s+)(\S+)(.*)$")
# Pipes that write files or change state are never allowed.
FORBIDDEN_PIPES = re.compile(r"\|\s*(redirect|tee|append|copy)\b", re.I)
TRIM_LINES = {"cpu": 30}


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


class CiscoError(Exception):
    """Bad command or target (never contains credentials)."""


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


def validate_show(command: str) -> str:
    """Allow only a single read-only `show` command."""
    command = command.strip()
    if "\n" in command or "\r" in command:
        raise CiscoError("only one command at a time")
    if not re.match(r"^show\s+\S", command, re.I):
        raise CiscoError(f"only 'show' commands are allowed: {command!r}")
    if FORBIDDEN_PIPES.search(command):
        raise CiscoError(f"output redirection is not allowed: {command!r}")
    return command


def mask_secrets(text: str) -> str:
    """Replace passwords, keys, communities and hashes in config output with <removed>."""
    def mask(line: str) -> str:
        if DESCRIPTION_LINE.match(line):
            return line
        m = SET_KEY_LINE.match(line) or SECRET_LINE.match(line)
        return m.group(1) + "<removed>" + m.group(3) if m else line

    return "\n".join(mask(line) for line in text.splitlines())


def build_command(name: str, device_type: str, arg: str | None = None) -> str:
    """Return the show command for a built-in command name on a platform."""
    if name not in COMMANDS:
        raise CiscoError(f"unknown command {name!r}; run 'python cisco_helper.py list'")
    _, ios, nxos, arg_mode = COMMANDS[name]
    template = nxos if (device_type == "cisco_nxos" and nxos) else ios
    if device_type == "cisco_xe" and name in XE_OVERRIDES:
        template = XE_OVERRIDES[name]
    if arg_mode == "required" and not arg:
        raise CiscoError(f"'{name}' needs an argument")
    if arg_mode == "optional":
        with_arg, without_arg = template.split("||")
        template = with_arg if arg else without_arg
    return validate_show(template.format(arg=arg or ""))


# ---------------------------------------------------------------------------
# IP -> switchport trace (locate): parsers for ARP, MAC table, port-channel and CDP output
# ---------------------------------------------------------------------------

CISCO_MAC = r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
# MAC table "ports" that aren't real ports.
NOT_A_PORT = re.compile(r"^(CPU|Router|Switch|Drop|sup-eth\d*|vPC Peer-Link|Sup)$", re.I)


def parse_mac(text: str) -> str | None:
    """aabb.ccdd.eeff for a MAC in any common format (aa:bb:.., aa-bb-.., aabb.ccdd.eeff), else None."""
    if not re.fullmatch(r"[0-9a-fA-F:.\-]{12,17}", text.strip()):
        return None
    hexes = re.sub(r"[^0-9a-fA-F]", "", text).lower()
    return f"{hexes[0:4]}.{hexes[4:8]}.{hexes[8:12]}" if len(hexes) == 12 else None


def mac_formats(cisco_mac: str) -> dict[str, str]:
    """aabb.ccdd.eeff -> {'cisco': ..., 'colon': 'aa:bb:cc:dd:ee:ff'}."""
    hexes = re.sub(r"[^0-9a-f]", "", cisco_mac.lower())
    return {"cisco": cisco_mac.lower(), "colon": ":".join(hexes[i:i + 2] for i in range(0, 12, 2))}


def parse_arp(output: str, ip: str) -> dict[str, str] | None:
    """MAC and interface for an IP from 'show ip arp <ip>' (IOS / IOS-XE / NX-OS)."""
    for line in output.splitlines():
        if not re.search(rf"(^|\s){re.escape(ip)}(\s|$)", line):
            continue
        mac = re.search(CISCO_MAC, line)
        if mac:
            return {"mac": mac.group(0).lower(), "interface": line.split()[-1]}
    return None


def parse_mac_table(output: str, mac: str) -> list[dict[str, str]]:
    """[{vlan, port, type}] for a MAC from 'show mac address-table address <mac>'."""
    rows = []
    for line in output.splitlines():
        if mac.lower() not in line.lower():
            continue
        tokens = line.replace("*", " ").split()
        vlan = next((t for t in tokens if t.isdigit()), "")
        port = tokens[-1] if tokens else ""
        kind = next((t for t in tokens if t.lower() in ("dynamic", "static", "secure")), "")
        if port and not NOT_A_PORT.match(port) and not re.fullmatch(CISCO_MAC, port):
            rows.append({"vlan": vlan, "port": port, "type": kind.lower()})
    return rows


def parse_port_channel_members(output: str, port_channel: str) -> list[str]:
    """Member ports (bundled first) of a port-channel from 'show etherchannel / port-channel summary'."""
    number = re.sub(r"\D", "", port_channel)
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if re.search(rf"\bPo{number}\(", line):
            # Members can wrap onto the next lines; collect until the next group number.
            text = line
            for nxt in lines[i + 1:]:
                if re.match(r"^\s*\d+\s+Po\d+", nxt) or not nxt.strip():
                    break
                text += " " + nxt
            members = re.findall(r"(\S+?)\((\w+)\)", text.split(f"Po{number}(", 1)[1])
            bundled = [m for m, flag in members if flag in ("P", "p", "bndl")]
            return bundled or [m for m, _ in members]
    return []


def parse_cdp_detail(output: str) -> list[dict[str, str]]:
    """Neighbors from 'show cdp neighbors <port> detail': device_id, ip, platform, capabilities, port, remote_port."""
    neighbors = []
    for block in re.split(r"^-{5,}\s*$", output, flags=re.M):
        dev = re.search(r"Device ID:\s*(\S+)", block)
        if not dev:
            continue
        ip = re.search(r"(?:IP address|IPv4 Address):\s*(\d+\.\d+\.\d+\.\d+)", block)
        plat = re.search(r"Platform:\s*([^,\n]+)", block)
        caps = re.search(r"Capabilities:\s*([^\n]+)", block)
        intf = re.search(r"Interface:\s*([^,\n]+),\s*Port ID \(outgoing port\):\s*(\S+)", block)
        neighbors.append({
            "device_id": dev.group(1), "ip": ip.group(1) if ip else "",
            "platform": plat.group(1).strip() if plat else "", "capabilities": caps.group(1).strip() if caps else "",
            "port": intf.group(1).strip() if intf else "", "remote_port": intf.group(2) if intf else "",
        })
    return neighbors


def cdp_neighbor_kind(neighbor: dict[str, str]) -> str:
    """'switch' for a Cisco switch/router we can follow, 'meraki', 'ap', 'phone', or 'other'."""
    plat, caps = neighbor["platform"].lower(), neighbor["capabilities"].lower()
    if "meraki" in plat or plat.startswith(("ms", "mr", "mx")):
        return "meraki"
    if "phone" in caps or "phone" in plat:
        return "phone"
    if "trans-bridge" in caps or re.search(r"\bair-|\bap\b|c91\d\dax|cw91\d\d", plat):
        return "ap"
    if "switch" in caps or "router" in caps:
        return "switch"
    return "other"


# "Key ....... value" (AireOS) or "Key : value" (9800) -> canonical field name.
WCLIENT_FIELDS = {
    "client mac address": "mac", "client ipv4 address": "ip", "ip address": "ip",
    "ap name": "ap", "wireless lan network name (ssid)": "ssid", "wireless lan network name": "ssid",
    "vlan": "vlan", "client state": "state", "policy manager state": "policy_state", "policy state": "policy_state",
    "client username": "user", "client user name": "user", "username": "user",
    "wireless lan profile name": "wlan_profile", "radio type": "radio", "connected for": "connected_for",
    "mobility state": "mobility", "mobility role": "mobility",
    "mobility foreign ip address": "foreign_wlc", "mobility anchor ip address": "anchor_wlc",
}


def parse_wireless_client(output: str) -> dict[str, str]:
    """Key fields of 'show wireless client mac-address <mac> detail' (9800) or 'show client detail <mac>'
    (AireOS). Empty dict when the client isn't on that controller."""
    found: dict[str, str] = {}
    for line in output.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9 ()/\-]+?)\s*(?:\.{2,}|:)\s*(.+?)\s*$", line)
        if not m:
            continue
        key = WCLIENT_FIELDS.get(m.group(1).strip().lower())
        if key and key not in found and m.group(2).strip():
            found[key] = m.group(2).strip()
    return found if (found.get("mac") or found.get("ap")) else {}


def wlan_ids_for_ssid(wlan_summary: str, ssid: str) -> list[str]:
    """WLAN IDs in 'show wlan summary' whose SSID or profile name equals ssid (case-insensitive)."""
    rows = re.findall(r"^\s*(\d+)\s+(.+?)\s{2,}(.+?)\s{2,}(?:UP|DOWN)\b", wlan_summary, re.M | re.I)
    return [i for i, prof, name in rows if ssid.lower() in (prof.strip().lower(), name.strip().lower())]


def wlan_rows(wlan_summary: str) -> dict[str, tuple[str, str, str]]:
    """WLAN ID -> (profile, SSID, status) from 'show wlan summary'."""
    rows = re.findall(r"^\s*(\d+)\s+(.+?)\s{2,}(.+?)\s{2,}(UP|DOWN)\b", wlan_summary, re.M | re.I)
    return {i: (prof.strip(), name.strip(), st.upper()) for i, prof, name, st in rows}


def client_counts_by_wlan(client_summary: str) -> Counter:
    """Clients per WLAN ID in 'show wireless client summary'."""
    return Counter(m.group(1) for m in re.finditer(
        r"^\s*[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\s.*?\bWLAN\s+(\d+)\b", client_summary, re.M | re.I))


def clients_on_wlans(client_summary: str, wlan_ids: list[str]) -> list[str]:
    """MACs (aaaa.bbbb.cccc) of clients on those WLAN IDs in 'show wireless client summary'."""
    macs = []
    for line in client_summary.splitlines():
        m = re.match(r"^\s*([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s.*?\bWLAN\s+(\d+)\b", line, re.I)
        if m and m.group(2) in wlan_ids:
            macs.append(m.group(1).lower())
    return macs


def parse_eap_type(detail: str) -> str:
    """'EAP Type' of 'show wireless client mac-address <mac> detail' (PEAP, EAP-TLS...), else '(none)'."""
    m = re.search(r"^\s*EAP Type\s*:\s*(\S.*?)\s*$", detail, re.M)
    return m.group(1) if m else "(none)"


def parent_interface(name: str) -> str:
    """GigabitEthernet0/0/1.110 -> GigabitEthernet0/0/1."""
    return name.split(".")[0]


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


class CiscoRunner:
    """Resolve devices and run read-only show commands on them in parallel."""

    def __init__(self, timeout: int = 30, workers: int = 10):
        import vault_helper

        self.creds = vault_helper.get_secrets(interactive=False)
        self.timeout = timeout
        self.workers = workers
        self.transport = "auto"  # auto = NETCONF when TCP 830 is open and the command has a NETCONF version, else SSH
        self._nb = None

    @property
    def nb(self):
        if self._nb is None:
            import netbox_helper

            self._nb = netbox_helper.connect(self.creds["netbox_url"], self.creds["netbox_token"])
        return self._nb

    def resolve(self, names: list[str] | None = None, site: str | None = None, tag: str | None = None,
                name_contains: str | None = None, device_type: str = "cisco_ios") -> list[dict[str, Any]]:
        """Turn names, IPs and NetBox filters into a de-duplicated device list.

        IPs are used directly with device_type. Names are looked up in NetBox (exact name first,
        else every device whose name contains the text)."""
        import netbox_helper

        devices: list[dict[str, Any]] = []
        for value in names or []:
            value = value.strip()
            if is_ip(value):
                devices.append({"name": value, "host": value, "device_type": device_type, "site": "", "platform": None})
                continue
            found, _ = netbox_helper.get_devices(self.nb, tag=None, name_contains=value)
            exact = [d for d in found if d["name"].lower() == value.lower()]
            if not (exact or found):
                raise CiscoError(f"no NetBox device matches {value!r}")
            devices.extend(exact or found)
        if site or tag or name_contains:
            found, skipped = netbox_helper.get_devices(self.nb, tag=tag, site=site, name_contains=name_contains)
            for s in skipped:
                print(f"skipped {s['name']}: {s['reason']}", file=sys.stderr)
            devices.extend(found)
        unique = {d["host"]: d for d in devices}
        return sorted(unique.values(), key=lambda d: d["name"])

    def _resolve_route(self, conn: Any, detail: dict[str, Any], vrf: str | None, depth: int = 2) -> dict[str, Any]:
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
            out = conn.send_command(validate_show(route_command("cisco_xe", target, vrf)), read_timeout=self.timeout * 2)
            if classify_route(out) != "found":
                continue
            inner = self._resolve_route(conn, parse_route(out), vrf, depth - 1)
            first = next((h for h in inner["next_hops"] if h.get("interface")), None)
            if first:
                hop["interface"] = first["interface"]
                hop["resolved_via"] = f"{inner['prefix']} {inner['protocol']} -> {first['next_hop']}"
        return detail

    @staticmethod
    def _collect_ssid(conn: Any, ssid: str, timeout: int) -> str:
        """Gather every piece of config for one SSID on a Catalyst 9800 and return it as text.

        9800 config is split across the WLAN profile, the policy tags that map the WLAN to a policy
        profile, and the policy profiles themselves, so this runs several show commands."""
        def show(command: str) -> str:
            command = validate_show(command)
            return mask_secrets(conn.send_command(command, read_timeout=timeout * 4)).rstrip()

        parts: list[tuple[str, str]] = []
        summary = show("show wlan summary")
        # Rows look like: "ID   Profile Name   SSID   Status   Security".
        rows = re.findall(r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+(UP|DOWN)\b", summary, re.M | re.I)
        profiles = [prof for _, prof, wlan_ssid, _ in rows if ssid.lower() in (wlan_ssid.lower(), prof.lower())]
        if not profiles:
            return f"No WLAN with SSID or profile name {ssid!r} on this controller.\n\n== show wlan summary\n{summary}"
        matching = [line for line in summary.splitlines()
                    if any(re.search(rf"\s{re.escape(p)}\s", f" {line} ") for p in profiles)]
        parts.append(("show wlan summary (matching rows)", "\n".join(matching)))

        tags = show("show running-config | section wireless tag policy")
        for profile in profiles:
            parts.append((f"WLAN profile {profile}", show(f"show running-config | section ^wlan {profile} ")))
            # Policy tags that carry this WLAN, and the policy profile each one maps it to.
            mappings: list[tuple[str, str]] = []
            current_tag = None
            for line in tags.splitlines():
                if m := re.match(r"^wireless tag policy (\S+)", line):
                    current_tag = m.group(1)
                elif current_tag and (m := re.match(rf"^\s+wlan {re.escape(profile)} policy (\S+)", line)):
                    mappings.append((current_tag, m.group(1)))
            parts.append((f"Policy tags using {profile}",
                          "\n".join(f"policy tag {tag:<30} -> policy profile {pp}" for tag, pp in mappings)
                          or "(not in any policy tag)"))
            for pp in sorted({pp for _, pp in mappings}):
                parts.append((f"Policy profile {pp}",
                              show(f"show running-config | section wireless profile policy {pp}$")))
            parts.append((f"show wlan name {profile}", show(f"show wlan name {profile}")))
        return "\n\n".join(f"== {title}\n{body}" for title, body in parts)

    @staticmethod
    def _collect_ssid_auth(conn: Any, ssid: str, timeout: int) -> dict[str, Any]:
        """Count a 9800's clients on one SSID by EAP type: one 'show wireless client ... detail' per client."""
        def show(command: str) -> str:
            return conn.send_command(validate_show(command), read_timeout=timeout * 4)

        ids = wlan_ids_for_ssid(show("show wlan summary"), ssid)
        if not ids:
            return {"ssid": ssid, "wlan_ids": [], "clients": 0, "by_eap": {}}
        macs = clients_on_wlans(show("show wireless client summary"), ids)
        eap = Counter(parse_eap_type(show(f"show wireless client mac-address {mac} detail")) for mac in macs)
        return {"ssid": ssid, "wlan_ids": ids, "clients": len(macs), "by_eap": dict(eap.most_common())}

    @staticmethod
    def _collect_ssid_counts(conn: Any, timeout: int) -> list[dict[str, Any]]:
        """Clients per SSID on a Catalyst 9800 (an SSID on several WLAN profiles is summed), biggest first."""
        def show(command: str) -> str:
            return conn.send_command(validate_show(command), read_timeout=timeout * 4)

        wlans = wlan_rows(show("show wlan summary"))
        counts = client_counts_by_wlan(show("show wireless client summary"))
        by_ssid: dict[str, dict[str, Any]] = {}
        for wid in sorted(set(wlans) | set(counts), key=int):
            _, ssid, status = wlans.get(wid, ("", f"(unknown WLAN {wid})", ""))
            row = by_ssid.setdefault(ssid, {"ssid": ssid, "wlan_ids": [], "status": status, "clients": 0})
            row["wlan_ids"].append(wid)
            row["clients"] += counts.get(wid, 0)
        return sorted(by_ssid.values(), key=lambda r: -r["clients"])

    def connect(self, device: dict[str, Any]) -> Any:
        """Open an SSH session to a device (in enable mode when possible). Use it as a context manager."""
        from netmiko import ConnectHandler

        conn = ConnectHandler(
            device_type=device["device_type"], host=device["host"],
            username=self.creds["ansible_user"], password=self.creds["ansible_password"],
            secret=self.creds["ansible_become_password"],
            conn_timeout=self.timeout, auth_timeout=self.timeout, banner_timeout=self.timeout,
        )
        if device["device_type"] in ("cisco_ios", "cisco_xe"):
            try:
                if not conn.check_enable_mode():
                    conn.enable()
            except Exception:  # noqa: BLE001 - most show commands work unprivileged
                pass
        return conn

    def _try_netconf(self, device: dict[str, Any], command_name: str | None, raw_command: str | None,
                     arg: str | None, parse: bool, result: dict[str, Any]) -> str | None:
        """Check NETCONF (TCP 830) before SSH. Returns the command's output over NETCONF, or None to use SSH.
        Sets result['netconf_port'], and result['transport'] / result['netconf_error'] as it goes.
        With --transport netconf, a device that can't answer over NETCONF is an error instead of a fallback."""
        import netconf_helper

        if self.transport == "ssh" or device["device_type"] not in ("cisco_ios", "cisco_xe"):
            if self.transport == "netconf":
                raise CiscoError(f"NETCONF is not available on {device['device_type']} devices")
            return None
        result["netconf_port"] = netconf_helper.port_open(device["host"])
        reason = None
        if not result["netconf_port"]:
            reason = "TCP 830 closed"
        elif raw_command or parse or command_name not in netconf_helper.RENDERERS:
            reason = "no NETCONF version of this command"
        else:
            try:
                output = netconf_helper.query(device["host"], self.creds, command_name, arg, device, self.timeout)
                result["transport"] = "netconf"
                return output
            except Exception as exc:  # noqa: BLE001 - any NETCONF problem falls back to SSH
                reason = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
                result["netconf_error"] = reason
        if self.transport == "netconf":
            raise CiscoError(f"NETCONF failed: {reason}")
        return None

    @staticmethod
    def _netconf_label(command_name: str | None, arg: str | None) -> str:
        return f"NETCONF {command_name}" + (f" {arg}" if arg else "")

    def _run_one(self, device: dict[str, Any], command_name: str | None, raw_command: str | None,
                 arg: str | None, lines: int | None, parse: bool, vrf: str | None = None) -> dict[str, Any]:
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

        result: dict[str, Any] = {"device": device["name"], "host": device["host"], "site": device.get("site", ""),
                                  "command": None, "output": None, "error": None}
        try:
            if command_name == "ssid":
                if not arg:
                    raise CiscoError("'ssid' needs an SSID name")
                command = f"ssid {arg} (show wlan summary, running-config sections, show wlan name)"
            elif command_name == "ssid-auth":
                if not arg:
                    raise CiscoError("'ssid-auth' needs an SSID name")
                if device["device_type"] == "cisco_wlc_ssh":
                    raise CiscoError("AireOS WLC: ssid-auth supports Catalyst 9800 only")
                command = f"ssid-auth {arg} (show wlan summary, show wireless client summary, client detail per client)"
            elif command_name == "ssid-count":
                if device["device_type"] == "cisco_wlc_ssh":
                    raise CiscoError("AireOS WLC: ssid-count supports Catalyst 9800 only")
                command = "ssid-count (show wlan summary, show wireless client summary)"
            elif command_name == "wclient":
                mac = parse_mac(arg or "")
                if not mac:
                    raise CiscoError(f"'wclient' needs a MAC address, got {arg!r}")
                command = validate_show(f"show client detail {mac_formats(mac)['colon']}"
                                        if device["device_type"] == "cisco_wlc_ssh"
                                        else f"show wireless client mac-address {mac} detail")
            elif command_name == "route" and arg:
                if vrf is None:  # "" means the global table
                    vrf = default_vrf(device)
                result["vrf"] = vrf or ""
                command = validate_show(route_command(device["device_type"], parse_route_target(arg), vrf))
            else:
                command = validate_show(raw_command) if raw_command else build_command(command_name, device["device_type"], arg)
            result["command"] = command
            output = self._try_netconf(device, command_name, raw_command, arg, parse, result)
            if output is not None:
                result["command"] = self._netconf_label(command_name, arg)
            else:
                result["transport"] = "ssh"
                with self.connect(device) as conn:
                    if command_name == "ssid":
                        output = self._collect_ssid(conn, arg, self.timeout)
                    elif command_name == "ssid-count":
                        result["ssid_counts"] = self._collect_ssid_counts(conn, self.timeout)
                        output = table([{**r, "wlan_ids": ",".join(r["wlan_ids"])} for r in result["ssid_counts"]],
                                       ["SSID=ssid", "WLAN IDs=wlan_ids", "Status=status", "Clients=clients"])
                    elif command_name == "ssid-auth":
                        result["ssid_auth"] = self._collect_ssid_auth(conn, arg, self.timeout)
                        output = json.dumps(result["ssid_auth"])
                    else:
                        output = conn.send_command(command, read_timeout=self.timeout * 4, use_textfsm=parse)
                    if command_name == "route" and arg and isinstance(output, str) and classify_route(output) == "found":
                        result["route_detail"] = self._resolve_route(conn, parse_route(output), vrf)
            if isinstance(output, str):
                if CONFIG_WORDS.search(command):
                    output = mask_secrets(output)
                text_lines = output.rstrip().splitlines()
                if lines and command_name == "log":
                    output = "\n".join(text_lines[-lines:])
                elif command_name in TRIM_LINES:
                    output = "\n".join(text_lines[:TRIM_LINES[command_name]])
            result["output"] = output
            if isinstance(output, str) and re.search(r"^\s*% ?(Invalid input|Incomplete command|Ambiguous command)",
                                                     output, re.M):
                result["error"] = "device rejected the command"
            if command_name == "wclient" and isinstance(output, str):
                result["wclient"] = parse_wireless_client(output)
                if result["error"] == "device rejected the command" and not result["wclient"]:
                    result["error"] = None  # a WLC that doesn't know the MAC can answer with an error line
            if command_name == "route" and arg and isinstance(output, str):
                result["route_result"] = classify_route(output)
                if result["route_result"] == "error":
                    result["error"] = "device rejected the command"
        except CiscoError as exc:
            result["error"] = str(exc)
        except NetmikoAuthenticationException:
            result["error"] = "authentication failed"
        except NetmikoTimeoutException:
            result["error"] = "timed out / unreachable"
        except Exception as exc:  # noqa: BLE001 - one bad device must not stop the run
            result["error"] = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
        return result

    def run(self, devices: list[dict[str, Any]], command_name: str | None = None, arg: str | None = None,
            raw_command: str | None = None, lines: int | None = 50, parse: bool = False,
            vrf: str | None = None) -> list[dict[str, Any]]:
        """Run a built-in command (or a raw show command) on every device in parallel.
        For command_name='route' with an IP/prefix, each result also gets route_result:
        'found', 'not found' or 'error'."""
        with ThreadPoolExecutor(max_workers=max(1, self.workers)) as pool:
            futures = [pool.submit(self._run_one, d, command_name, raw_command, arg, lines, parse, vrf) for d in devices]
            results = [f.result() for f in as_completed(futures)]
        return sorted(results, key=lambda r: r["device"])

    # -- locate: IP -> gateway -> MAC -> access switchport ---------------------------

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


def locate_main(args: argparse.Namespace) -> int:
    """CLI for 'locate <ip|mac>'. Exit 0 = switchport found, 1 = not found, 2 = setup error."""
    mac = parse_mac(args.arg or "")
    if not args.arg or not (is_ip(args.arg) or mac):
        print("usage: cisco_helper.py locate <ip> [-d <first router>] [--vrf NAME]\n"
              "       cisco_helper.py locate <mac> -d <router or switch to start from>", file=sys.stderr)
        return 2

    def log(msg: str) -> None:
        print(f"... {msg}", file=sys.stderr)

    try:
        runner = CiscoRunner(timeout=args.timeout, workers=args.workers)
        start = runner.resolve(args.device, args.site, args.tag, args.name, args.device_type) \
            if (args.device or args.site or args.tag or args.name) else None
        if mac:
            if not start or len(start) != 1:
                raise CiscoError("locate <mac> needs exactly one starting device (-d), e.g. the gateway or core switch")
            result = runner.trace_mac(mac, start[0], log=log)
        else:
            result = runner.locate(args.arg, vrf=args.vrf, start=start, log=log)
    except (CiscoError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - Vault / NetBox problems
        print(f"setup error: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}", file=sys.stderr)
        return 2
    text = json.dumps(result, indent=2, default=str) if args.json else format_locate(result)
    print(text)
    if args.output:
        with open(args.output, "a" if args.append else "w", encoding="utf-8") as fh:
            fh.write(text.rstrip() + "\n\n")
        print(f"{'Appended to' if args.append else 'Wrote'} {args.output}", file=sys.stderr)
    return 0 if result["location"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run read-only show commands on Cisco devices.",
        epilog="Built-in commands: " + ", ".join(COMMANDS) + ", plus 'show \"<any show command>\"' and 'list'.")
    parser.add_argument("command", help="built-in command name, 'show', or 'list'")
    parser.add_argument("arg", nargs="?", help="argument for the command (interface, section, IP, MAC, or the full show command)")
    parser.add_argument("-d", "--device", action="append", default=[], help="device name or IP (repeatable)")
    parser.add_argument("--site", help="NetBox site name or slug")
    parser.add_argument("--tag", help="NetBox tag, e.g. wan_router")
    parser.add_argument("--name", help="NetBox device names containing this text")
    parser.add_argument("--device-type", default="cisco_ios", help="netmiko type for devices given by IP (default cisco_ios)")
    parser.add_argument("--vrf", help="route: look up the route in this VRF")
    parser.add_argument("--lines", type=int, default=50, help="log: number of most recent lines (default 50)")
    parser.add_argument("--parse", action="store_true", help="parse output with TextFSM (ntc-templates) when a template exists")
    parser.add_argument("--json", action="store_true", help="print JSON results")
    parser.add_argument("-o", "--output", help="also write the results to this file (text, or JSON with --json)")
    parser.add_argument("--append", action="store_true", help="with --output: append instead of overwriting")
    parser.add_argument("--workers", type=int, default=10, help="devices at once (default 10)")
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds (default 30)")
    parser.add_argument("--transport", choices=("auto", "netconf", "ssh"), default="auto",
                        help="auto (default): check TCP 830 first and use NETCONF for commands that have a NETCONF "
                             "version, else SSH; netconf: NETCONF only; ssh: skip the NETCONF check")
    parser.add_argument("--max-devices", type=int, default=25, help="refuse to run on more devices than this (default 25)")
    args = parser.parse_args()

    if args.command == "list":
        for name, (help_text, ios, _, arg_mode) in COMMANDS.items():
            usage = f"{name} <arg>" if arg_mode == "required" else (f"{name} [arg]" if arg_mode == "optional" else name)
            print(f"{usage:22} {help_text}")
        print(f"{'show \"<command>\"':22} any single read-only show command")
        print(f"{'locate <ip|mac>':22} trace an IP to its switchport: NetBox prefix, wan_router routes, gateway ARP, "
              "MAC table and CDP hop by hop (a MAC needs -d <start device>)")
        return 0

    if args.command == "locate":
        if args.vrf and args.vrf.lower() in ("global", "default"):
            args.vrf = ""
        return locate_main(args)

    raw_command = None
    if args.command == "show":
        if not args.arg:
            print("usage: cisco_helper.py show \"show ...\" -d <device>", file=sys.stderr)
            return 2
        raw_command = args.arg  # must already be a full "show ..." command; validate_show() refuses anything else
    elif args.command not in COMMANDS:
        print(f"unknown command {args.command!r}; run 'python cisco_helper.py list'", file=sys.stderr)
        return 2

    if args.vrf and args.vrf.lower() in ("global", "default"):
        args.vrf = ""  # the global routing table, even on cores that default to a VRF
    route_lookup = args.command == "route" and bool(args.arg)
    if route_lookup:
        try:
            parse_route_target(args.arg)
        except CiscoError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not (args.device or args.site or args.tag or args.name):
            args.tag = "wan_router"  # route lookups default to every WAN router
    wclient = args.command == "wclient"
    ssid_auth = args.command == "ssid-auth"
    default_wlcs = (wclient or ssid_auth or args.command == "ssid-count") and not (args.device or args.site or args.tag or args.name)
    if default_wlcs:
        args.name = "wlc"  # every NetBox device with "wlc" in its name
        args.max_devices = max(args.max_devices, 60)

    try:
        if raw_command:
            validate_show(raw_command)
        if not (args.device or args.site or args.tag or args.name):
            raise CiscoError("pick devices with -d <name|ip>, --site, --tag or --name")
        runner = CiscoRunner(timeout=args.timeout, workers=args.workers)
        runner.transport = args.transport
        devices = runner.resolve(args.device, args.site, args.tag, args.name, args.device_type)
        if default_wlcs:
            devices = [d for d in devices if is_ip(d["host"])]  # standby units have no management IP
            if ssid_auth or args.command == "ssid-count":
                devices = [d for d in devices if d["device_type"] != "cisco_wlc_ssh"]  # 9800 only
    except (CiscoError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - Vault / NetBox problems
        print(f"setup error: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}", file=sys.stderr)
        return 2

    if not devices:
        print("no devices matched", file=sys.stderr)
        return 2
    if len(devices) > args.max_devices:
        print(f"{len(devices)} devices matched, more than --max-devices {args.max_devices}. Narrow the filters or "
              "raise --max-devices.", file=sys.stderr)
        return 2

    results = runner.run(devices, None if raw_command else args.command, args.arg if not raw_command else None,
                         raw_command, args.lines, args.parse, args.vrf)

    if args.json:
        text = json.dumps(results, indent=2, default=str)
    elif wclient or ssid_auth:
        text = ""  # only the summary below; the raw output is in --json
    else:
        chunks = []
        for r in results:
            via = f"  [{r['transport']}]" if r.get("transport") else ""
            chunks.append(f"===== {r['device']} ({r['host']}){'  ' + r['site'] if r['site'] else ''}{via} : {r['command'] or ''}")
            if r["error"]:
                chunks.append(f"ERROR: {r['error']}")
            else:
                out = r["output"]
                chunks.append(out if isinstance(out, str) else json.dumps(out, indent=2, default=str))
            chunks.append("")
        text = "\n".join(chunks)
    print(text)
    if args.output:
        with open(args.output, "a" if args.append else "w", encoding="utf-8") as fh:
            fh.write(text.rstrip() + "\n\n")
        print(f"{'Appended to' if args.append else 'Wrote'} {args.output}", file=sys.stderr)
    if not args.json:
        if route_lookup:
            width = max(len(r["device"]) for r in results)
            print("Summary")
            for r in results:
                status = "error" if r["error"] and not r.get("route_result") else r.get("route_result", "error")
                d = r.get("route_detail") or {}
                hops = "; ".join(f"{h['next_hop']} via {h['interface'] or '?'}"
                                 + (f" ({h['resolved_via']})" if h.get("resolved_via") else "")
                                 for h in d.get("next_hops", []))
                route = f"{d.get('prefix', '')} {d.get('protocol', '')} [{d.get('distance', '')}/{d.get('metric', '')}] {hops}" if d else ""
                print(f"  {r['device']:<{width}}  {r['host']:<15}  {status:<9}  {route or r['error'] or ''}")
        if ssid_auth:
            total: Counter = Counter()
            for r in results:
                a = r.get("ssid_auth")
                if a and a["clients"]:
                    total.update(a["by_eap"])
                    print(f"  {r['device']} ({r['host']}): {a['clients']} clients  "
                          + "  ".join(f"{k} {v}" for k, v in a["by_eap"].items()))
            print(f"SSID {args.arg}: {sum(total.values())} clients  " + "  ".join(f"{k} {v}" for k, v in total.most_common()))
            errors = [r for r in results if r["error"]]
            if errors:
                print("  errors: " + "; ".join(f"{r['device']}: {r['error']}" for r in errors))
        if wclient:
            hits = [r for r in results if r.get("wclient")]
            print(f"Wireless client {args.arg}: found on {len(hits)} of {len(results)} WLCs")
            for r in hits:
                c = r["wclient"]
                if (c.get("mobility") or "").lower() == "anchor":
                    # On the anchor, "AP Name" holds the foreign controller's IP, not an AP.
                    ap = f"(anchored here; client is on foreign WLC {c.get('foreign_wlc') or c.get('ap', '?')})"
                elif (c.get("mobility") or "").lower() == "foreign":
                    ap = f"{c.get('ap', '?')} (foreign; anchored on {c.get('anchor_wlc', '?')})"
                else:
                    ap = c.get("ap", "?")
                print(f"  {r['device']} ({r['host']}): AP {ap}  SSID {c.get('ssid', '?')}  "
                      f"VLAN {c.get('vlan', '?')}  IP {c.get('ip', '?')}  state {c.get('state') or c.get('policy_state', '?')}"
                      + (f"  user {c['user']}" if c.get("user") else ""))
            errors = [r for r in results if r["error"]]
            if errors:
                print("  errors: " + "; ".join(f"{r['device']}: {r['error']}" for r in errors))
    if route_lookup:
        return 0 if any(r.get("route_result") == "found" for r in results) else 1
    if wclient:
        return 0 if any(r.get("wclient") for r in results) else 1
    return 1 if any(r["error"] for r in results) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
