"""Wireless controller (Catalyst 9800 and AireOS) parsers and per-SSID collectors for cisco_helper.py.

The collectors take an open netmiko connection; AireOS differs only in the show commands (wlc_commands)."""
from __future__ import annotations

import re
from collections import Counter
from typing import Any

from cisco_common import mac_formats, mask_secrets, parse_mac, send, validate_show

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


def is_aireos(device: dict[str, Any]) -> bool:
    """AireOS WLC (5508, 5520, 8540, 3504...): NetBox platform airos, netmiko type cisco_wlc_ssh."""
    return device["device_type"] == "cisco_wlc_ssh"


def wlan_rows(wlan_summary: str) -> dict[str, tuple[str, str, str]]:
    """WLAN ID -> (profile, SSID, 'UP'/'DOWN') from 'show wlan summary' on a 9800 or an AireOS WLC."""
    rows = {i: (prof.strip(), name.strip(), st.upper()) for i, prof, name, st in re.findall(
        r"^\s*(\d+)\s+(.+?)\s{2,}(.+?)\s{2,}(UP|DOWN)\b", wlan_summary, re.M | re.I)}
    # AireOS rows: "1   LCMC-Guest / LCMC-Guest   Enabled   interface   none"
    for i, prof, name, st in re.findall(r"^\s*(\d+)\s+(.+?) / (.+?)\s{2,}(Enabled|Disabled)\b", wlan_summary, re.M):
        rows[i] = (prof.strip(), name.strip(), "UP" if st == "Enabled" else "DOWN")
    return rows


def wlan_ids_for_ssid(wlan_summary: str, ssid: str) -> list[str]:
    """WLAN IDs whose SSID or profile name equals ssid (case-insensitive)."""
    return [i for i, (prof, name, _) in wlan_rows(wlan_summary).items() if ssid.lower() in (prof.lower(), name.lower())]


def parse_client_summary(client_summary: str) -> list[tuple[str, str]]:
    """(MAC as aaaa.bbbb.cccc, WLAN ID) per client from 'show wireless client summary' (9800) or
    'show client summary' (AireOS: the row is MAC, AP, slot, status, WLAN, auth, ...)."""
    out = []
    for line in client_summary.splitlines():
        m = (re.match(r"^\s*([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s.*?\bWLAN\s+(\d+)\b", line, re.I)
             or re.match(r"^\s*([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+\S+\s+\S+\s+\S+\s+(\d+)\s+(?:Yes|No)\b", line, re.I))
        if m:
            out.append((parse_mac(m.group(1)), m.group(2)))
    return out


def client_counts_by_wlan(client_summary: str) -> Counter:
    """Clients per WLAN ID."""
    return Counter(wid for _, wid in parse_client_summary(client_summary))


def clients_on_wlans(client_summary: str, wlan_ids: list[str]) -> list[str]:
    """MACs (aaaa.bbbb.cccc) of clients on those WLAN IDs."""
    return [mac for mac, wid in parse_client_summary(client_summary) if wid in wlan_ids]


def parse_eap_type(detail: str) -> str:
    """'EAP Type' of one client's detail (9800 'EAP Type : PEAP', AireOS 'EAP Type.... PEAP'), else '(none)'."""
    m = re.search(r"^\s*EAP Type\s*(?::|\.{2,})\s*(\S.*?)\s*$", detail, re.M)
    return m.group(1) if m else "(none)"


def wlc_commands(device: dict[str, Any]) -> tuple[str, str, Any]:
    """(WLAN summary command, client summary command, client detail command for a dotted MAC)."""
    if is_aireos(device):
        return ("show wlan summary", "show client summary",
                lambda mac: f"show client detail {mac_formats(mac)['colon']}")
    return ("show wlan summary", "show wireless client summary",
            lambda mac: f"show wireless client mac-address {mac} detail")


def collect_ssid(conn: Any, ssid: str, timeout: int) -> str:
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

def collect_ssid_aireos(conn: Any, ssid: str, timeout: int) -> str:
    """Everything for one SSID on an AireOS WLC: the summary row and 'show wlan <id>' for each matching WLAN."""
    def show(command: str) -> str:
        return mask_secrets(conn.send_command(validate_show(command), read_timeout=timeout * 4)).rstrip()

    summary = show("show wlan summary")
    ids = wlan_ids_for_ssid(summary, ssid)
    if not ids:
        return f"No WLAN with SSID or profile name {ssid!r} on this controller.\n\n== show wlan summary\n{summary}"
    rows = [line for line in summary.splitlines() if re.match(rf"^\s*(?:{'|'.join(ids)})\s", line)]
    parts = [("show wlan summary (matching rows)", "\n".join(rows))]
    parts += [(f"show wlan {i}", show(f"show wlan {i}")) for i in ids]
    return "\n\n".join(f"== {title}\n{body}" for title, body in parts)

def collect_ssid_auth(conn: Any, ssid: str, timeout: int, device: dict[str, Any]) -> dict[str, Any]:
    """Count a WLC's clients on one SSID by EAP type: one client detail command per client."""
    def show(command: str) -> str:
        return send(conn, command, timeout)

    wlan_cmd, client_cmd, detail_cmd = wlc_commands(device)
    ids = wlan_ids_for_ssid(show(wlan_cmd), ssid)
    if not ids:
        return {"ssid": ssid, "wlan_ids": [], "clients": 0, "by_eap": {}}
    macs = clients_on_wlans(show(client_cmd), ids)
    eap = Counter(parse_eap_type(show(detail_cmd(mac))) for mac in macs)
    return {"ssid": ssid, "wlan_ids": ids, "clients": len(macs), "by_eap": dict(eap.most_common())}

def collect_ssid_clients(conn: Any, ssid: str, timeout: int, device: dict[str, Any]) -> list[str]:
    """MACs (aa:bb:cc:dd:ee:ff) of a WLC's clients on one SSID, or on every SSID when ssid is '*'."""
    wlan_cmd, client_cmd, _ = wlc_commands(device)
    if ssid == "*":
        summary = send(conn, client_cmd, timeout)
        return [mac_formats(mac)["colon"] for mac, _ in parse_client_summary(summary)]
    ids = wlan_ids_for_ssid(send(conn, wlan_cmd, timeout), ssid)
    summary = send(conn, client_cmd, timeout) if ids else ""
    return [mac_formats(m)["colon"] for m in clients_on_wlans(summary, ids)]


def collect_ssid_counts(conn: Any, timeout: int, device: dict[str, Any]) -> list[dict[str, Any]]:
    """Clients per SSID on a WLC (an SSID on several WLAN profiles is summed), biggest first."""
    def show(command: str) -> str:
        return send(conn, command, timeout)

    wlan_cmd, client_cmd, _ = wlc_commands(device)
    wlans = wlan_rows(show(wlan_cmd))
    counts = client_counts_by_wlan(show(client_cmd))
    by_ssid: dict[str, dict[str, Any]] = {}
    for wid in sorted(set(wlans) | set(counts), key=int):
        _, ssid, status = wlans.get(wid, ("", f"(unknown WLAN {wid})", ""))
        row = by_ssid.setdefault(ssid, {"ssid": ssid, "wlan_ids": [], "status": status, "clients": 0})
        row["wlan_ids"].append(wid)
        if status == "UP":  # an SSID on several WLAN IDs is UP when any of them is
            row["status"] = "UP"
        row["clients"] += counts.get(wid, 0)
    return sorted(by_ssid.values(), key=lambda r: -r["clients"])
