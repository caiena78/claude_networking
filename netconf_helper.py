"""Read-only NETCONF client for Cisco IOS-XE devices (port 830), used by cisco_helper.py before SSH.

Only <get>, <get-config> and <get-schema> are ever sent (never edit-config, commit, other RPCs, lock or delete).
Credentials are the same Vault SSH credentials cisco_helper.py uses. cisco_helper.py calls query() for the
commands in RENDERERS when port 830 is open, and falls back to SSH when NETCONF can't answer (no NETCONF
version of the command, module missing, login failed).

Usage:
    python netconf_helper.py probe -d tls-wan-rtr-01              # is 830 open, does NETCONF log in
    python netconf_helper.py caps -d tls-wan-rtr-01 [--filter oper]   # YANG modules the device advertises
    python netconf_helper.py get -d tls-wan-rtr-01 --xpath /interfaces-state/interface/name
    python netconf_helper.py get -d tls-wan-rtr-01 --xpath "<native xmlns='http://cisco.com/ns/yang/Cisco-IOS-XE-native'><version/></native>"
    python netconf_helper.py get -d tls-wan-rtr-01 --config --xpath /native/hostname
    python netconf_helper.py schema -d tls-wan-rtr-01 --module Cisco-IOS-XE-arp-oper
    python netconf_helper.py list                                 # commands that have a NETCONF version
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import sys
from datetime import datetime
from typing import Any

from helper_common import table

NETCONF_PORT = 830


class NetconfUnsupported(Exception):
    """This device has no NETCONF answer for the command; cisco_helper.py falls back to SSH."""


def port_open(host: str, port: int = NETCONF_PORT, timeout: float = 2.0) -> bool:
    """True when a TCP connection to host:port succeeds within timeout seconds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def connect(host: str, creds: dict[str, str], timeout: int = 30) -> Any:
    """Open a NETCONF session (use as a context manager). Raises ncclient errors on failure."""
    from ncclient import manager

    return manager.connect(
        host=host, port=NETCONF_PORT, username=creds["ansible_user"], password=creds["ansible_password"],
        hostkey_verify=False, allow_agent=False, look_for_keys=False, timeout=timeout,
        device_params={"name": "default"},
    )


SECRET_TAG = re.compile(r"(<([\w-]*(?:psk|password|secret|key-string|community|passphrase)[\w-]*)(?:\s[^>]*)?>)[^<]+(</\2>)",
                        re.I)


def mask_xml(xml: str) -> str:
    """Hide the value of secret-looking elements (the WLAN <psk>, passwords, communities) in reply XML."""
    return SECRET_TAG.sub(r"\1<removed>\3", xml)


def get_xml(session: Any, flt: str, config: bool = False) -> str:
    """<get> (operational + config) or <get-config running>, filtered by an XPath, or by a subtree filter when
    the argument starts with '<'. Returns the reply XML with secrets masked."""
    spec = ("subtree", flt) if flt.lstrip().startswith("<") else ("xpath", flt)
    reply = session.get_config("running", filter=spec) if config else session.get(filter=spec)
    return mask_xml(reply.xml)


# -- NETCONF versions of the cisco_helper.py built-in commands -----------------------------------

def _els(root: Any, tag: str) -> list[Any]:
    return [e for e in root.iter() if isinstance(e.tag, str) and e.tag.rsplit("}", 1)[-1] == tag]


def _v(el: Any, path: str) -> str:
    """Text of the descendant at a '/'-separated path of local names ('' when missing)."""
    for part in path.split("/"):
        el = next((c for c in el if isinstance(c.tag, str) and c.tag.rsplit("}", 1)[-1] == part), None)
        if el is None:
            return ""
    return (el.text or "").strip()


def _rows(root: Any, tag: str, fields: dict[str, str]) -> list[dict[str, str]]:
    return [{k: _v(e, p) for k, p in fields.items()} for e in _els(root, tag)]


def _system(root: Any) -> dict[str, str]:
    return _rows(root, "device-system-data", {"now": "current-time", "boot": "boot-time",
                                              "version": "software-version", "reason": "last-reboot-reason"})[0]


def _uptime(sysd: dict[str, str]) -> str:
    delta = datetime.fromisoformat(sysd["now"]) - datetime.fromisoformat(sysd["boot"])
    hours, rem = divmod(delta.seconds, 3600)
    return f"{delta.days} days, {hours} hours, {rem // 60} minutes (booted {sysd['boot']})"


def _version(root: Any, arg: str | None, device: dict) -> str:
    s = _system(root)
    return f"{s['version']}\nUptime: {_uptime(s)}\nLast reload reason: {s['reason']}"


def _interfaces(root: Any, arg: str | None, device: dict) -> str:
    rows = _rows(root, "interface", {"Interface": "name", "IP-Address": "ipv4", "Admin": "admin-status",
                                     "Oper": "oper-status", "Description": "description"})
    for r in rows:
        r["Admin"], r["Oper"] = r["Admin"].replace("if-state-", ""), r["Oper"].replace("if-oper-state-", "")
    return table(rows, ["Interface", "IP-Address", "Admin", "Oper", "Description"])


def _interface(root: Any, arg: str | None, device: dict) -> str:
    want = re.sub(r"\s+", "", arg or "").lower()
    rows = [r for r in _rows(root, "interface", {
        "name": "name", "admin": "admin-status", "oper": "oper-status", "ip": "ipv4", "mac": "phys-address",
        "mtu": "mtu", "speed": "speed", "in_errors": "statistics/in-errors", "in_crc": "statistics/in-crc-errors",
        "out_errors": "statistics/out-errors", "in_discards": "statistics/in-discards",
        "out_discards": "statistics/out-discards"}) if r["name"].lower() == want]
    if not rows:  # abbreviations like Te0/1/0 need the SSH path
        raise NetconfUnsupported(f"no interface named {arg!r} (NETCONF needs the full name)")
    return "\n".join(f"{k}: {v}" for k, v in rows[0].items())


def _errors(root: Any, arg: str | None, device: dict) -> str:
    cols = {"Interface": "name", "InErr": "statistics/in-errors", "CRC": "statistics/in-crc-errors",
            "InDisc": "statistics/in-discards", "OutErr": "statistics/out-errors",
            "OutDisc": "statistics/out-discards"}
    rows = [r for r in _rows(root, "interface", cols) if any(r[k] not in ("", "0") for k in cols if k != "Interface")]
    return table(rows, list(cols)) if rows else "(no interface has errors or discards)"


def _cpu(root: Any, arg: str | None, device: dict) -> str:
    c = _rows(root, "cpu-utilization", {"5s": "five-seconds", "1m": "one-minute", "5m": "five-minutes"})[0]
    return f"CPU utilization: five seconds: {c['5s']}%; one minute: {c['1m']}%; five minutes: {c['5m']}%"


def _memory(root: Any, arg: str | None, device: dict) -> str:
    return table(_rows(root, "memory-statistic", {"Pool": "name", "Total": "total-memory", "Used": "used-memory",
                                                  "Free": "free-memory"}), ["Pool", "Total", "Used", "Free"])


def _arp(root: Any, arg: str | None, device: dict) -> str:
    from cisco_route import default_vrf  # the cores' ARP is read in their routed VRF, like the SSH path

    vrf = default_vrf(device)
    rows = []
    for v in _els(root, "arp-vrf"):
        for r in _rows(v, "arp-oper", {"Address": "address", "Hardware": "hardware", "Interface": "interface"}):
            r["VRF"] = _v(v, "vrf")
            if (not vrf or r["VRF"].lower() == vrf.lower()) and (not arg or r["Address"] == arg):
                rows.append(r)
    return table(rows, ["VRF", "Address", "Hardware", "Interface"])


def _cdp(root: Any, arg: str | None, device: dict) -> str:
    return table(_rows(root, "cdp-neighbor-detail", {
        "Device": "device-name", "Local": "local-intf-name", "Port": "port-id", "Platform": "platform-name",
        "Capability": "capability"}), ["Device", "Local", "Port", "Platform", "Capability"])


def _lldp(root: Any, arg: str | None, device: dict) -> str:
    return table(_rows(root, "lldp-entry", {"Device": "device-id", "Local": "local-interface",
                                            "Port": "connecting-interface", "TTL": "ttl"}),
                 ["Device", "Local", "Port", "TTL"])


def _ntp(root: Any, arg: str | None, device: dict) -> str:
    st = _rows(root, "ntp-status-info", {"stratum": "stratum", "offset": "offset", "ref": "refid/ip-addr"})[0]
    peers = _rows(root, "ntp-associations", {
        "Peer": "ntp-address/ip-addr", "VRF": "ntp-address/vrf-name", "Stratum": "peer-stratum",
        "Reach": "peer-reach", "Delay": "delay", "Offset": "offset", "Status": "peer-selection-status"})
    return (f"stratum {st['stratum']}, offset {st['offset']} ms, ref {st['ref']}\n"
            + table(peers, ["Peer", "VRF", "Stratum", "Reach", "Delay", "Offset", "Status"]))


def _wlans(root: Any, arg: str | None, device: dict) -> str:
    rows = _rows(root, "wlan-cfg-entry", {"ID": "wlan-id", "Profile": "profile-name",
                                          "SSID": "apf-vap-id-data/ssid", "Status": "apf-vap-id-data/wlan-status"})
    for r in rows:
        r["Status"] = "UP" if r["Status"] == "true" else "DOWN"
    return table(rows, ["ID", "Profile", "SSID", "Status"])


_HW = ('<device-hardware-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-device-hardware-oper"><device-hardware>'
       '<device-system-data/></device-hardware></device-hardware-data>')
_IF = '<interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper"/>'
# name -> (help, subtree filter, render(root, arg, device) -> text)
RENDERERS: dict[str, tuple[str, str, Any]] = {
    "version": ("software version, uptime, last reload reason (device-hardware-oper)", _HW, _version),
    "uptime": ("uptime (device-hardware-oper)", _HW, lambda r, a, d: _uptime(_system(r))),
    "clock": ("device clock, UTC (device-hardware-oper)", _HW, lambda r, a, d: _system(r)["now"]),
    "interfaces": ("interface, IP, admin/oper status (interfaces-oper)", _IF, _interfaces),
    "interface": ("one interface by full name: status, IP, MAC, errors (interfaces-oper)", _IF, _interface),
    "errors": ("interfaces with input/output errors, CRCs or discards (interfaces-oper)", _IF, _errors),
    "cpu": ("CPU 5s/1m/5m (process-cpu-oper)",
            '<cpu-usage xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-process-cpu-oper"><cpu-utilization>'
            '<five-seconds/><one-minute/><five-minutes/></cpu-utilization></cpu-usage>', _cpu),
    "memory": ("memory pools (memory-oper)",
               '<memory-statistics xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-memory-oper"/>', _memory),
    "arp": ("ARP table, optionally one IP; cores show their routed VRF (arp-oper)",
            '<arp-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-arp-oper"/>', _arp),
    "cdp": ("CDP neighbors (cdp-oper)",
            '<cdp-neighbor-details xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-cdp-oper"/>', _cdp),
    "lldp": ("LLDP neighbors (lldp-oper)",
             '<lldp-entries xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-lldp-oper"/>', _lldp),
    "ntp": ("NTP status and peers (ntp-oper)",
            '<ntp-oper-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-ntp-oper"/>', _ntp),
    "wlans": ("WLAN / SSID summary on a 9800, never the keys (wireless-wlan-cfg)",
              '<wlan-cfg-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-wireless-wlan-cfg"><wlan-cfg-entries>'
              '<wlan-cfg-entry><profile-name/><wlan-id/><apf-vap-id-data><ssid/><wlan-status/></apf-vap-id-data>'
              '</wlan-cfg-entry></wlan-cfg-entries></wlan-cfg-data>', _wlans),
}


def query(host: str, creds: dict[str, str], command: str, arg: str | None, device: dict, timeout: int = 30) -> str:
    """Run a built-in command over NETCONF and return text like the CLI view. Raises NetconfUnsupported when
    there is no NETCONF version of it, and ncclient errors when the session or the query fails."""
    from lxml import etree

    if command not in RENDERERS:
        raise NetconfUnsupported(f"no NETCONF version of {command!r}")
    with connect(host, creds, timeout) as m:
        reply = m.get(filter=("subtree", RENDERERS[command][1]))
    data = _els(etree.fromstring(reply.xml.encode()), "data")
    if not data or not len(data[0]):
        raise NetconfUnsupported("empty NETCONF reply")
    try:
        return RENDERERS[command][2](data[0], arg, device)
    except (IndexError, KeyError, ValueError) as exc:  # a model that lacks the expected fields
        raise NetconfUnsupported(f"unexpected NETCONF data ({type(exc).__name__})") from exc


def main() -> int:
    ap = argparse.ArgumentParser(description="Read-only NETCONF probe/get for Cisco IOS-XE devices.")
    ap.add_argument("command", choices=("probe", "caps", "get", "schema", "list"))
    ap.add_argument("-d", "--device", action="append", default=[])
    ap.add_argument("--filter", help="caps: only modules containing this text")
    ap.add_argument("--xpath", help="get: XPath filter, or a subtree filter starting with '<'")
    ap.add_argument("--module", help="schema: YANG module name to print (get-schema, read-only)")
    ap.add_argument("--config", action="store_true", help="get: read the running config instead of operational data")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--max-chars", type=int, default=20000, help="get/schema: cut the printed XML here (0 = no limit)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.command == "list":
        for name, (help_text, _, _) in RENDERERS.items():
            print(f"{name:12} {help_text}")
        return 0
    if not args.device:
        print("pick devices with -d", file=sys.stderr)
        return 2
    if args.command == "schema" and not args.module:
        print("schema needs --module", file=sys.stderr)
        return 2
    if args.command == "get" and not args.xpath:
        print("get needs --xpath", file=sys.stderr)
        return 2

    from cisco_helper import CiscoRunner

    runner = CiscoRunner(timeout=args.timeout)
    devices = runner.resolve(args.device, None, None, None, "cisco_xe")
    rows, rc = [], 0
    for d in devices:
        row: dict[str, Any] = {"device": d["name"], "host": d["host"], "port_830": port_open(d["host"])}
        if row["port_830"]:
            try:
                with connect(d["host"], runner.creds, args.timeout) as m:
                    row["netconf"] = "ok"
                    if args.command == "caps":
                        row["capabilities"] = [c for c in sorted(m.server_capabilities)
                                               if not args.filter or args.filter in c]
                    elif args.command == "schema":
                        row["xml"] = m.get_schema(args.module).data
                    elif args.command == "get":
                        row["xml"] = get_xml(m, args.xpath, args.config)
            except Exception as exc:  # noqa: BLE001 - report per device, keep going
                row["netconf"] = f"{type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}"
                rc = 1
        else:
            row["netconf"] = "port closed"
        rows.append(row)
    for r in rows:
        xml = r.get("xml") or ""
        if args.max_chars and len(xml) > args.max_chars:
            r["xml"] = xml[:args.max_chars] + f"\n... cut at {args.max_chars} of {len(xml)} characters (--max-chars 0 for all)"
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            print(f"{r['device']} ({r['host']}): 830 {'open' if r['port_830'] else 'closed'}  netconf {r['netconf']}")
            for c in r.get("capabilities", []):
                print(f"    {c}")
            if r.get("xml"):
                print(r["xml"])
    return rc


if __name__ == "__main__":
    sys.exit(main())
