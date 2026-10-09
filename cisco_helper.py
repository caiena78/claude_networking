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
    python cisco_helper.py list                         # list the built-in commands

As a module:
    from cisco_helper import CiscoRunner
    runner = CiscoRunner()
    devices = runner.resolve(names=["tls-wan-rtr-01"])
    results = runner.run(devices, "uptime")

Exit codes: 0 = every device answered, 1 = at least one device failed, 2 = setup error.
For `route <ip>`: 0 = at least one device has the route, 1 = none has it, 2 = setup error.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

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
        # "* 10.143.100.1, from 10.143.1.22, 1w0d ago, via TenGigabitEthernet0/1/0"
        if m := re.match(r"^\*?\s*(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+:[0-9a-fA-F:]*), from \S+,.*?(?:via (\S+))?$", line):
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

    def _run_one(self, device: dict[str, Any], command_name: str | None, raw_command: str | None,
                 arg: str | None, lines: int | None, parse: bool, vrf: str | None = None) -> dict[str, Any]:
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

        result: dict[str, Any] = {"device": device["name"], "host": device["host"], "site": device.get("site", ""),
                                  "command": None, "output": None, "error": None}
        try:
            if command_name == "ssid":
                if not arg:
                    raise CiscoError("'ssid' needs an SSID name")
                command = f"ssid {arg} (show wlan summary, running-config sections, show wlan name)"
            elif command_name == "route" and arg:
                command = validate_show(route_command(device["device_type"], parse_route_target(arg), vrf))
            else:
                command = validate_show(raw_command) if raw_command else build_command(command_name, device["device_type"], arg)
            result["command"] = command
            with ConnectHandler(
                device_type=device["device_type"], host=device["host"],
                username=self.creds["ansible_user"], password=self.creds["ansible_password"],
                secret=self.creds["ansible_become_password"],
                conn_timeout=self.timeout, auth_timeout=self.timeout, banner_timeout=self.timeout,
            ) as conn:
                if device["device_type"] in ("cisco_ios", "cisco_xe"):
                    try:
                        if not conn.check_enable_mode():
                            conn.enable()
                    except Exception:  # noqa: BLE001 - most show commands work unprivileged
                        pass
                if command_name == "ssid":
                    output = self._collect_ssid(conn, arg, self.timeout)
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
    parser.add_argument("--max-devices", type=int, default=25, help="refuse to run on more devices than this (default 25)")
    args = parser.parse_args()

    if args.command == "list":
        for name, (help_text, ios, _, arg_mode) in COMMANDS.items():
            usage = f"{name} <arg>" if arg_mode == "required" else (f"{name} [arg]" if arg_mode == "optional" else name)
            print(f"{usage:22} {help_text}")
        print(f"{'show \"<command>\"':22} any single read-only show command")
        return 0

    raw_command = None
    if args.command == "show":
        if not args.arg:
            print("usage: cisco_helper.py show \"show ...\" -d <device>", file=sys.stderr)
            return 2
        raw_command = args.arg  # must already be a full "show ..." command; validate_show() refuses anything else
    elif args.command not in COMMANDS:
        print(f"unknown command {args.command!r}; run 'python cisco_helper.py list'", file=sys.stderr)
        return 2

    route_lookup = args.command == "route" and bool(args.arg)
    if route_lookup:
        try:
            parse_route_target(args.arg)
        except CiscoError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not (args.device or args.site or args.tag or args.name):
            args.tag = "wan_router"  # route lookups default to every WAN router

    try:
        if raw_command:
            validate_show(raw_command)
        if not (args.device or args.site or args.tag or args.name):
            raise CiscoError("pick devices with -d <name|ip>, --site, --tag or --name")
        runner = CiscoRunner(timeout=args.timeout, workers=args.workers)
        devices = runner.resolve(args.device, args.site, args.tag, args.name, args.device_type)
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
    else:
        chunks = []
        for r in results:
            chunks.append(f"===== {r['device']} ({r['host']}){'  ' + r['site'] if r['site'] else ''} : {r['command'] or ''}")
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
    if route_lookup:
        return 0 if any(r.get("route_result") == "found" for r in results) else 1
    return 1 if any(r["error"] for r in results) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
