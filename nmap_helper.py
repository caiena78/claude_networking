"""Ping sweeps and port scans with nmap, limited to internal (private) addresses and polite by default.

This is deliberately not a general nmap wrapper: only host discovery (-sn) and TCP/UDP port scans are
available. No NSE scripts, no OS or version detection, no spoofing, decoys, fragmentation or other evasion
options, and only RFC 1918 style private IPv4 targets (an IP, a CIDR, a range, or a NetBox device name).
Scans are capped in size and rate (--max-targets, --rate, -T3 at most), and every run is logged to
scans/audit.log (git-ignored): UTC time, local user, mode, targets and the exact nmap command line.

Targets: 10.158.8.21   10.158.8.0/24   10.158.8.10-50   10.158.8.10-10.158.9.20   lakeview-wlc-ha01 (NetBox name)

Usage:
    python nmap_helper.py sweep 10.158.8.0/24                       # which addresses answer
    python nmap_helper.py sweep 10.158.8.0/24 --netbox              # and which of them NetBox doesn't know
    python nmap_helper.py sweep 10.158.8.0/24 --tcp-ping 22,443     # also probe these TCP ports (hosts that drop ICMP)
    python nmap_helper.py ports 10.158.8.21 --ports 22,80,443,8443  # TCP connect scan of chosen ports
    python nmap_helper.py ports 10.158.8.0/28 --top 100             # the 100 most common ports
    python nmap_helper.py ports lakeview-wlc-ha01 --ports all       # all 65535 TCP ports (16 addresses at most)
    python nmap_helper.py ports 10.158.8.21 --ports 161,514 --udp   # UDP (needs admin rights; 64 addresses, 100 ports at most)
    python nmap_helper.py sweep 10.158.8.0/24 --dry-run             # show what would run, scan nothing
Add --json, -o FILE [--append].
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from helper_common import Out, table, to_json

HERE = Path(__file__).resolve().parent
AUDIT_LOG = HERE / "scans" / "audit.log"
DEFAULT_MAX_TARGETS = 1024  # addresses per scan; --max-targets raises it up to HARD_MAX_TARGETS
HARD_MAX_TARGETS = 4096
DEFAULT_RATE = 300  # packets per second
MAX_RATE = 1000
MAX_TIMING = 3  # nmap -T3 is its normal speed; -T4 and -T5 are not offered
ALL_TCP_MAX_ADDRESSES = 16
UDP_MAX_ADDRESSES = 64
UDP_MAX_PORTS = 100


class ScanError(Exception):
    """A request the helper refuses or nmap could not run (never contains credentials)."""


# -- targets -----------------------------------------------------------------------------------------------

def _check_address(ip: ipaddress.IPv4Address) -> None:
    if not ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_unspecified:
        raise ScanError(f"{ip} is not an internal private address; this helper only scans private IPv4 ranges")


def parse_target(token: str, resolve_name: Callable[[str], str] | None = None) -> list[ipaddress.IPv4Network]:
    """One target (IP, CIDR, range, or NetBox device name) as IPv4 networks, all private."""
    token = token.strip()
    if re.fullmatch(r"[0-9.]+(/\d+)?", token):
        try:
            net = ipaddress.IPv4Network(token, strict=False)
        except ValueError as exc:
            raise ScanError(f"bad target {token!r}: {exc}") from exc
        nets = [net]
    elif m := re.fullmatch(r"([0-9.]+)-([0-9.]+|\d{1,3})", token):
        try:
            first = ipaddress.IPv4Address(m.group(1))
            end = m.group(2)
            last = ipaddress.IPv4Address(end if "." in end else ".".join(m.group(1).split(".")[:3] + [end]))
            nets = list(ipaddress.summarize_address_range(first, last))
        except ValueError as exc:
            raise ScanError(f"bad range {token!r}: {exc}") from exc
    elif resolve_name:
        nets = [ipaddress.IPv4Network(resolve_name(token))]
    else:
        raise ScanError(f"{token!r} is not an IP, CIDR or range, and no NetBox lookup is available")
    for net in nets:
        _check_address(net.network_address)
        _check_address(net.broadcast_address)
    return nets


def parse_targets(tokens: list[str], resolve_name: Callable[[str], str] | None = None) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for token in tokens:
        nets += parse_target(token, resolve_name)
    return nets


def count_addresses(nets: list[ipaddress.IPv4Network]) -> int:
    return sum(n.num_addresses for n in nets)


def netbox_resolver(creds: dict[str, str] | None = None) -> Callable[[str], str]:
    """Resolve a NetBox device name (exact) to its management IP. Connects to NetBox on first use."""
    state: dict[str, Any] = {}

    def resolve(name: str) -> str:
        import netbox_helper

        if "nb" not in state:
            import vault_helper

            secrets = creds or vault_helper.get_secrets(interactive=False)
            state["nb"] = netbox_helper.connect(secrets["netbox_url"], secrets["netbox_token"])
        found, _ = netbox_helper.get_devices(state["nb"], tag=None, name_contains=name)
        exact = [d for d in found if d["name"].lower() == name.lower()]
        if not exact:
            raise ScanError(f"{name!r} is not a NetBox device name (use an IP, CIDR or range, or an exact device name)")
        return str(ipaddress.IPv4Address(exact[0]["host"]))

    return resolve


# -- ports and limits --------------------------------------------------------------------------------------

def validate_ports(spec: str) -> tuple[str, int]:
    """(nmap -p value, number of ports) for '22,80,8000-8100' or 'all'."""
    if spec.lower() == "all":
        return "1-65535", 65535
    if not re.fullmatch(r"\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*", spec):
        raise ScanError(f"bad port list {spec!r}: use numbers and ranges like 22,80,8000-8100, or 'all'")
    total = 0
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        lo_n, hi_n = int(lo), int(hi or lo)
        if not 1 <= lo_n <= hi_n <= 65535:
            raise ScanError(f"bad port range {part!r}: ports are 1-65535 and a range runs low to high")
        total += hi_n - lo_n + 1
    return spec, total


def check_limits(mode: str, count: int, max_targets: int, ports: int = 0, udp: bool = False) -> None:
    if not 1 <= max_targets <= HARD_MAX_TARGETS:
        raise ScanError(f"--max-targets must be 1-{HARD_MAX_TARGETS}")
    if count > max_targets:
        raise ScanError(f"{count} addresses is more than --max-targets {max_targets} (hard limit {HARD_MAX_TARGETS}). "
                        "Scan a smaller range, or raise --max-targets if you really mean it.")
    if mode == "ports":
        if ports > 1024 and count > ALL_TCP_MAX_ADDRESSES:
            raise ScanError(f"{ports} ports on {count} addresses is too much: scans of more than 1024 ports are "
                            f"limited to {ALL_TCP_MAX_ADDRESSES} addresses")
        if udp and (count > UDP_MAX_ADDRESSES or ports > UDP_MAX_PORTS):
            raise ScanError(f"UDP scans are limited to {UDP_MAX_ADDRESSES} addresses and {UDP_MAX_PORTS} ports")


def build_command(nmap: str, mode: str, nets: list[ipaddress.IPv4Network], exclude: list[ipaddress.IPv4Network],
                  *, ports: str | None = None, top: int | None = None, udp: bool = False, syn: bool = False,
                  no_ping: bool = False, tcp_ping: str | None = None, dns: bool = False, all_states: bool = False,
                  timing: int = MAX_TIMING, rate: int = DEFAULT_RATE) -> list[str]:
    """The nmap argument list. Every value in it was validated above, and it is run without a shell."""
    if not 1 <= timing <= MAX_TIMING:
        raise ScanError(f"--timing must be 1-{MAX_TIMING}")
    if not 1 <= rate <= MAX_RATE:
        raise ScanError(f"--rate must be 1-{MAX_RATE} packets per second")
    cmd = [nmap, "-oX", "-", f"-T{timing}", "--max-rate", str(rate), "--max-retries", "1", "--host-timeout", "120s"]
    if not dns:
        cmd.append("-n")
    if mode == "sweep":
        cmd.append("-sn")
        if tcp_ping:
            cmd.append(f"-PS{validate_ports(tcp_ping)[0]}")
    else:
        cmd.append("-sU" if udp else ("-sS" if syn else "-sT"))
        if ports:
            cmd += ["-p", validate_ports(ports)[0]]
        else:
            cmd += ["--top-ports", str(top or 100)]
        if no_ping:
            cmd.append("-Pn")
        if not all_states:
            cmd.append("--open")
    if exclude:
        cmd += ["--exclude", ",".join(str(n) for n in exclude)]
    return cmd + [str(n) for n in nets]


def find_nmap() -> str:
    """The nmap executable found on PATH, else a ScanError saying nmap was not found."""
    path = shutil.which("nmap")
    if not path:
        raise ScanError("nmap not found. Install it (https://nmap.org/download) and make sure its folder is on your PATH.")
    return path


# -- running and reading results ---------------------------------------------------------------------------

def audit(mode: str, targets: list[str], cmd: list[str]) -> None:
    """Append every scan to scans/audit.log (git-ignored, local to each person) before it runs."""
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    who = os.environ.get("USERNAME") or os.environ.get("USER") or "?"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
        fh.write(f"{stamp}\tuser={who}\t{mode}\ttargets={' '.join(targets)}\t{' '.join(cmd)}\n")


def parse_xml(xml_text: str) -> dict[str, Any]:
    """Hosts that answered, with MAC/vendor, hostnames and ports, plus nmap's own totals."""
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is None or status.get("state") != "up":
            continue
        row: dict[str, Any] = {"ip": "", "mac": "", "vendor": "", "hostname": "", "ports": [], "reason": status.get("reason", "")}
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                row["ip"] = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                row["mac"], row["vendor"] = a.get("addr", "").lower(), a.get("vendor", "")
        name = h.find("hostnames/hostname")
        row["hostname"] = name.get("name", "") if name is not None else ""
        for p in h.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            row["ports"].append({"port": int(p.get("portid", 0)), "protocol": p.get("protocol", ""),
                                 "state": state.get("state", "") if state is not None else "",
                                 "service": svc.get("name", "") if svc is not None else ""})
        hosts.append(row)
    stats = root.find("runstats/hosts")
    finished = root.find("runstats/finished")
    return {"hosts": hosts, "up": int(stats.get("up", len(hosts))) if stats is not None else len(hosts),
            "total": int(stats.get("total", 0)) if stats is not None else 0,
            "seconds": float(finished.get("elapsed", 0)) if finished is not None else 0.0}


def run_nmap(cmd: list[str], timeout: int) -> dict[str, Any]:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"nmap did not finish within {timeout} seconds (--timeout); try fewer addresses or ports") from exc
    if done.returncode != 0 or "<nmaprun" not in done.stdout:
        err = (done.stderr or done.stdout).strip().splitlines()
        raise ScanError("nmap failed: " + (" ".join(err[-3:]) if err else f"exit code {done.returncode}"))
    return parse_xml(done.stdout)


def annotate_netbox(hosts: list[dict[str, Any]], limit: int = 256) -> None:
    """Add 'netbox' to each host: the NetBox device/interface that has the IP, or '-' when NetBox doesn't know it."""
    import netbox_helper
    import vault_helper

    secrets = vault_helper.get_secrets(interactive=False)
    nb = netbox_helper.connect(secrets["netbox_url"], secrets["netbox_token"])
    for h in hosts[:limit]:
        rows = netbox_helper.ip_lookup(nb, h["ip"])
        h["netbox"] = ", ".join(f"{r['device'] or r['dns_name'] or 'unassigned'}" + (f" {r['interface']}" if r["interface"] else "")
                                for r in rows) or "-"
    for h in hosts[limit:]:
        h["netbox"] = "(not checked)"


def format_result(mode: str, result: dict[str, Any], count: int) -> str:
    hosts = result["hosts"]
    if mode == "sweep":
        cols = ["IP=ip", "Hostname=hostname", "MAC=mac", "Vendor=vendor"] + (["NetBox=netbox"] if hosts and "netbox" in hosts[0] else [])
        body = table(hosts, cols)
    else:
        rows = [{**h, "open": ", ".join(f"{p['port']}/{p['protocol']} {p['service']}".strip() for p in h["ports"]) or "-"}
                for h in hosts]
        cols = ["IP=ip", "Hostname=hostname", "Open ports=open"]
        body = table(rows, cols, width=200)
    return f"{body}\n\n{result['up']} of {result['total'] or count} addresses up, {result['seconds']:.1f}s"


def main() -> int:
    parser = argparse.ArgumentParser(description="Ping sweeps and port scans (private IPv4 only, polite by default).")
    sub = parser.add_subparsers(dest="mode", required=True)
    for name, text in (("sweep", "Ping sweep: which addresses answer"), ("ports", "Port scan the targets")):
        p = sub.add_parser(name, help=text)
        p.add_argument("targets", nargs="+", help="IP, CIDR, range (10.1.1.10-50) or NetBox device name")
        p.add_argument("--exclude", action="append", default=[], metavar="TARGET", help="leave these out (repeatable)")
        p.add_argument("--max-targets", type=int, default=DEFAULT_MAX_TARGETS,
                       help=f"most addresses in one scan (default {DEFAULT_MAX_TARGETS}, hard limit {HARD_MAX_TARGETS})")
        p.add_argument("--rate", type=int, default=DEFAULT_RATE, help=f"packets per second (default {DEFAULT_RATE}, max {MAX_RATE})")
        p.add_argument("--timing", type=int, default=MAX_TIMING, help=f"nmap -T level 1-{MAX_TIMING} (default {MAX_TIMING})")
        p.add_argument("--dns", action="store_true", help="resolve names for hosts that answer (default: no DNS)")
        p.add_argument("--timeout", type=int, default=900, help="stop nmap after this many seconds (default 900)")
        p.add_argument("--dry-run", action="store_true", help="show the targets and the nmap command, scan nothing")
        p.add_argument("--json", action="store_true")
        p.add_argument("-o", "--output")
        p.add_argument("--append", action="store_true")
    sw = sub.choices["sweep"]
    sw.add_argument("--tcp-ping", metavar="PORTS", help="also probe these TCP ports to find hosts that drop ICMP, e.g. 22,443")
    sw.add_argument("--netbox", action="store_true", help="show which NetBox device has each address that answers")
    pt = sub.choices["ports"]
    group = pt.add_mutually_exclusive_group()
    group.add_argument("--ports", help="ports like 22,80,8000-8100, or 'all' (default: --top 100)")
    group.add_argument("--top", type=int, choices=[10, 20, 50, 100, 200, 500, 1000], help="the N most common ports")
    pt.add_argument("--udp", action="store_true", help="UDP scan (admin rights; 64 addresses and 100 ports at most)")
    pt.add_argument("--syn", action="store_true", help="SYN scan instead of connect (admin rights)")
    pt.add_argument("--no-ping", action="store_true", help="scan even if the host doesn't answer discovery (-Pn)")
    pt.add_argument("--all-states", action="store_true", help="also list closed and filtered ports")
    args = parser.parse_args()
    out = Out()

    try:
        nmap = find_nmap()  # first, so a missing nmap is reported before anything else (including NetBox) is touched
        resolver = netbox_resolver()
        nets = parse_targets(args.targets, resolver)
        exclude = parse_targets(args.exclude, resolver)
        count = count_addresses(nets)
        port_spec, n_ports = (validate_ports(args.ports) if args.mode == "ports" and args.ports
                              else (None, getattr(args, "top", None) or 100))
        check_limits(args.mode, count, args.max_targets, n_ports if args.mode == "ports" else 0,
                     args.mode == "ports" and args.udp)
        cmd = build_command(nmap, args.mode, nets, exclude, ports=port_spec,
                            top=getattr(args, "top", None), udp=getattr(args, "udp", False),
                            syn=getattr(args, "syn", False), no_ping=getattr(args, "no_ping", False),
                            tcp_ping=getattr(args, "tcp_ping", None), dns=args.dns,
                            all_states=getattr(args, "all_states", False), timing=args.timing, rate=args.rate)
        if args.dry_run:
            out.add(f"{count} addresses in {', '.join(str(n) for n in nets)}\n" + " ".join(cmd))
            out.save(args.output, args.append)
            return 0
        audit(args.mode, args.targets, cmd)
        print(f"... {args.mode} of {count} addresses", file=sys.stderr)
        result = run_nmap(cmd, args.timeout)
        if args.mode == "sweep" and args.netbox:
            annotate_netbox(result["hosts"])
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - Vault / NetBox problems
        print(f"setup error: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}", file=sys.stderr)
        return 2
    out.add(to_json({"mode": args.mode, "addresses": count, **result}) if args.json else format_result(args.mode, result, count))
    out.save(args.output, args.append)
    return 0


if __name__ == "__main__":
    sys.exit(main())
