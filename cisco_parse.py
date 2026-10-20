"""Parsers for the show output cisco_helper.py locate walks through: ARP, MAC table, port-channels, CDP."""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# IP -> switchport trace (locate): parsers for ARP, MAC table, port-channel and CDP output
# ---------------------------------------------------------------------------

CISCO_MAC = r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
# MAC table "ports" that aren't real ports.
NOT_A_PORT = re.compile(r"^(CPU|Router|Switch|Drop|sup-eth\d*|vPC Peer-Link|Sup)$", re.I)


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
