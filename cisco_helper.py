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
import json
import logging
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import cisco_common
from cisco_common import CiscoError, is_ip, mac_formats, mask_secrets, parse_mac, validate_show
from cisco_locate import LocateMixin
from cisco_route import classify_route, parse_route, parse_route_target, resolve_route, route_command
from cisco_wlc import (collect_ssid, collect_ssid_aireos, collect_ssid_auth, collect_ssid_clients,
                       collect_ssid_counts, is_aireos, parse_wireless_client, wlc_commands)
from helper_common import table

# The code lives in cisco_common / cisco_parse / cisco_route / cisco_locate / cisco_wlc. These names are
# re-exported because audit_helper.py and the tests use them as cisco_helper.<name>.
from cisco_locate import format_locate  # noqa: E402,F401
from cisco_parse import cdp_neighbor_kind, parse_arp, parse_cdp_detail, parse_mac_table, parse_port_channel_members  # noqa: E402,F401
from cisco_route import CORE_ISOLATED_VRFS, CORE_VRFS, default_vrf  # noqa: E402,F401
from cisco_wlc import (client_counts_by_wlan, clients_on_wlans, parse_eap_type, wlan_ids_for_ssid,  # noqa: E402,F401
                       wlan_rows)

logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)  # no "Socket exception" lines when a WLC drops the session

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
    "wlans":        ("WLAN / SSID summary (9800 and AireOS)", "show wlan summary", None, None),
    "ssid":         ("everything for one SSID: on a 9800 the WLAN profile, policy tags, policy profiles and show wlan; on AireOS show wlan <id>",
                     "show wlan summary", None, "required"),
    "ssid-auth":    ("clients on one SSID by EAP type (PEAP, EAP-TLS...) on 9800 and AireOS WLCs; defaults to every WLC in NetBox",
                     "show wlan summary", None, "required"),
    "ssid-count":   ("clients per SSID (one show wlan summary + one client summary); "
                     "defaults to every WLC in NetBox", "show wlan summary", None, None),
    "ssid-clients": ("MACs of the clients on one SSID, one per line (use -o FILE, then "
                     "ordr_helper.py devices --macs-file FILE --summary for manufacturers)", "show wlan summary", None, "required"),
    "wclient":      ("wireless client by MAC on the WLCs (9800 and AireOS): AP, SSID, VLAN, IP, state, user; "
                     "defaults to every WLC in NetBox", "show wireless client mac-address {arg} detail", None, "required"),
}
# IOS-XE has better resource views than classic IOS.
XE_OVERRIDES = {"memory": "show platform resources"}
# Built-in commands on AireOS WLCs (platform airos, netmiko cisco_wlc_ssh). Any command not listed here has no
# AireOS equivalent and is refused. {arg} as above.
AIREOS_COMMANDS = {
    "version": "show sysinfo", "uptime": "show sysinfo",  # sysinfo has the version and "System Up Time"
    "interfaces": "show interface summary", "interface": "show interface detailed {arg}",
    "inventory": "show inventory", "cdp": "show cdp neighbors", "cdp-detail": "show cdp neighbors detail",
    "cpu": "show cpu", "memory": "show memory statistics", "clock": "show time", "ntp": "show time",
    "license": "show license summary", "users": "show loginsession", "wlans": "show wlan summary",
    "run": "show run-config",
}

# Output of these commands can include config, so secrets are masked.
CONFIG_WORDS = re.compile(r"\b(run|running-config|startup-config|config|tech)", re.I)
TRIM_LINES = {"cpu": 30}


def build_command(name: str, device_type: str, arg: str | None = None) -> str:
    """Return the show command for a built-in command name on a platform."""
    if name not in COMMANDS:
        raise CiscoError(f"unknown command {name!r}; run 'python cisco_helper.py list'")
    _, ios, nxos, arg_mode = COMMANDS[name]
    template = nxos if (device_type == "cisco_nxos" and nxos) else ios
    if device_type == "cisco_wlc_ssh":
        if name not in AIREOS_COMMANDS:
            raise CiscoError(f"'{name}' has no AireOS equivalent (supported: {', '.join(AIREOS_COMMANDS)}, "
                             "wclient, ssid, ssid-count, ssid-clients, ssid-auth, show \"...\")")
        template = AIREOS_COMMANDS[name]
    if device_type == "cisco_xe" and name in XE_OVERRIDES:
        template = XE_OVERRIDES[name]
    if arg_mode == "required" and not arg:
        raise CiscoError(f"'{name}' needs an argument")
    if arg_mode == "optional":
        with_arg, without_arg = template.split("||")
        template = with_arg if arg else without_arg
    return validate_show(template.format(arg=arg or ""))


class CiscoRunner(LocateMixin):
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
                command = (f"ssid {arg} (show wlan summary, show wlan <id>)" if is_aireos(device) else
                           f"ssid {arg} (show wlan summary, running-config sections, show wlan name)")
            elif command_name == "ssid-auth":
                if not arg:
                    raise CiscoError("'ssid-auth' needs an SSID name")
                command = f"ssid-auth {arg} ({wlc_commands(device)[0]}, {wlc_commands(device)[1]}, client detail per client)"
            elif command_name == "ssid-clients":
                if not arg:
                    raise CiscoError("'ssid-clients' needs an SSID name")
                command = f"ssid-clients {arg} ({wlc_commands(device)[0]}, {wlc_commands(device)[1]})"
            elif command_name == "ssid-count":
                command = f"ssid-count ({wlc_commands(device)[0]}, {wlc_commands(device)[1]})"
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
                        collect = collect_ssid_aireos if is_aireos(device) else collect_ssid
                        output = collect(conn, arg, self.timeout)
                    elif command_name == "ssid-clients":
                        result["ssid_clients"] = collect_ssid_clients(conn, arg, self.timeout, device)
                        output = "\n".join(result["ssid_clients"]) or f"(no clients on {arg})"
                    elif command_name == "ssid-count":
                        result["ssid_counts"] = collect_ssid_counts(conn, self.timeout, device)
                        output = table([{**r, "wlan_ids": ",".join(r["wlan_ids"])} for r in result["ssid_counts"]],
                                       ["SSID=ssid", "WLAN IDs=wlan_ids", "Status=status", "Clients=clients"])
                    elif command_name == "ssid-auth":
                        result["ssid_auth"] = collect_ssid_auth(conn, arg, self.timeout, device)
                        output = json.dumps(result["ssid_auth"])
                    else:
                        output = conn.send_command(command, read_timeout=self.timeout * 4, use_textfsm=parse)
                    if command_name == "route" and arg and isinstance(output, str) and classify_route(output) == "found":
                        result["route_detail"] = resolve_route(conn, parse_route(output), vrf, self.timeout)
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
    parser.add_argument("--raw", action="store_true",
                        help="with --json: keep the raw device output even for commands that also return parsed data "
                             "(wclient, ssid-count, ssid-clients, ssid-auth), which are slimmed by default")
    parser.add_argument("--cache", type=int, default=0, metavar="SECONDS",
                        help="ssid-count/ssid-clients/ssid-auth: reuse WLC output fetched less than this many seconds ago "
                             "(.cache/, default 0 = always live)")
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
    default_wlcs = (wclient or ssid_auth or args.command in ("ssid-count", "ssid-clients")) and not (args.device or args.site or args.tag or args.name)
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
        cisco_common.CACHE_TTL = args.cache
        devices = runner.resolve(args.device, args.site, args.tag, args.name, args.device_type)
        if default_wlcs:
            devices = [d for d in devices if is_ip(d["host"])]  # standby units have no management IP
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
        if not args.raw:  # the parsed fields already carry the answer; the raw output is the bulk of the JSON
            for r in results:
                if any(r.get(k) for k in ("wclient", "ssid_counts", "ssid_clients", "ssid_auth")):
                    r.pop("output", None)
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
