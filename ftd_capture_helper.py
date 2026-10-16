"""Packet captures on Cisco FTD firewalls over SSH - on the ACTIVE unit of an HA pair only.

This is the only helper in the repo that changes anything on a device: it creates, starts, stops and
removes packet captures. It never sends anything else (no config, clear, failover, reload or copy).

Which firewalls: every NetBox device with platform ftd (no separate allow list). The two units of an HA
pair are grouped by name (-01/-02). Pick a firewall with --fw <ip or name>.
vpn: read-only RA VPN summary and live sessions (the FTD keeps only live sessions and counters since boot).

Credentials: CISCO_SRV_ACCOUNT / CISCO_SRV_PWD environment variables (never printed or logged).

Usage:
    python ftd_capture_helper.py status                      # failover state of the units
    python ftd_capture_helper.py list                        # captures on the active unit
    python ftd_capture_helper.py interfaces [--src IP --dst IP] [--refresh]   # cached interface list

    # Session workflow: start a capture, check it later, then stop it
    python ftd_capture_helper.py start --src 10.1.1.1 --dst 10.9.9.9 --proto udp --port 53 --ingress Inside1 --egress EPIC_DMZ
    python ftd_capture_helper.py start ... --yes             # create / reuse the captures and leave them running
    python ftd_capture_helper.py check [--name DESC]         # was the traffic allowed or denied, and by which rule?
    python ftd_capture_helper.py stop  [--name DESC] [--stop-only]   # remove (or just stop) the captures
    python ftd_capture_helper.py sessions                    # list open capture sessions

    # One-shot: create, wait --duration seconds, check, then remove
    python ftd_capture_helper.py capture --src ... --dst ... --port ... --ingress ... --egress ... [--yes]

    python ftd_capture_helper.py cleanup [--yes]             # remove leftover CLAUDE_* captures

Names: new captures are CLAUDE_<DESC>_IN (trace), _OUT and _DROP (asp-drop). DESC defaults to the
protocol/port and destination, e.g. CLAUDE_UDP53_10-9-9-9_IN; override it with --name. Open sessions are
kept in captures/sessions.json, and interface lists are cached per firewall in ftd_interfaces.json
(refreshed after 7 days or with --refresh). Both are git-ignored.

If an existing capture (anyone's) already has the required settings - same interface, trace for ingress,
asp-drop for drops, and a match that covers the flow - it is REUSED instead of creating a new one: started
with "no capture <name> stop" if it was stopped, and stopped again by "stop". Reused captures are never
removed or reconfigured, and only packets captured since "start" are analysed. Capture names are used in
full, including any %intf=<nameif>% suffix the FTD adds.

packet-tracer is not used: it doesn't evaluate prefilter rules, so verdicts come only from live trace
captures. Only show, capture CLAUDE_*, no capture CLAUDE_*, and "capture <name> stop" /
"no capture <name> stop" are ever sent.
"""
import argparse
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")

PREFIX = "CLAUDE_"
MAX_BUFFER = 33554432
MAX_TRACE = 100
CAPNAME = r"[A-Za-z0-9_.-]+(?:%intf=[A-Za-z0-9_./-]+%)?"  # FTD may append %intf=<nameif>% to the name
ALLOWED = re.compile(rf"^(show |capture CLAUDE_[A-Za-z0-9_-]+ |no capture CLAUDE_{CAPNAME}$"
                     rf"|capture {CAPNAME} stop$|no capture {CAPNAME} stop$)")
IP = r"\d+\.\d+\.\d+\.\d+"
CACHE = str(HERE / "ftd_interfaces.json")
CACHE_DAYS = 7
SESSIONS = str(HERE / "captures" / "sessions.json")
MAX_DESC = 20


# ---------------------------------------------------------------- configured firewalls

def netbox_groups():
    """Every NetBox device with platform 'ftd', one group per name once a trailing -01/-02 is stripped."""
    import netbox_helper
    import vault_helper

    c = vault_helper.get_secrets(interactive=False)
    nb = netbox_helper.connect(c["netbox_url"], c["netbox_token"])
    by_name = {}
    for d in nb.dcim.devices.filter(platform="ftd"):
        ip = d.primary_ip4 or d.primary_ip
        if ip:
            by_name.setdefault(re.sub(r"-0?\d$", "", d.name.lower()), {})[str(ip.address).split("/")[0]] = d.name
    return list(by_name.values())


GROUPS = None
ALL_HOSTS = {}


def init_hosts():
    global GROUPS
    if GROUPS is None:
        GROUPS = netbox_groups()
        for g in GROUPS:
            ALL_HOSTS.update(g)
    return GROUPS


def group_key(group):
    return ",".join(group)


def describe_group(group):
    return ", ".join(f"{ip}{' (' + lbl + ')' if lbl else ''}" for ip, lbl in group.items())


def select_group(fw):
    """The firewall to work on: --fw <ip or label>, or the only one configured."""
    groups = init_hosts()
    if fw:
        hits = [g for g in groups if fw in g or any(lbl and fw.lower() in lbl.lower() for lbl in g.values())]
        if len(hits) == 1:
            return hits[0]
        sys.exit(f"--fw {fw!r} matches {len(hits)} configured firewalls. Configured: "
                 + "; ".join(describe_group(g) for g in groups))
    if len(groups) == 1:
        return groups[0]
    sys.exit("Several firewalls found in NetBox; pick one with --fw <ip or label>: "
             + "; ".join(describe_group(g) for g in groups))


def group_for_hosts(hosts):
    """The configured group that contains these hosts (used by sessions)."""
    for g in init_hosts():
        if set(hosts) <= set(g):
            return g
    sys.exit(f"Units {', '.join(hosts)} are no longer ftd devices in NetBox")


AUDIT_LOG = HERE / "captures" / "audit.log"


def audit(host, unit, cmd):
    """Append every command that changes a device (capture / no capture / start / stop) to captures/audit.log
    (git-ignored, local to each person): UTC time, local user, FTD account, unit and the exact command.
    Written before the command is sent, so an attempt that fails is still recorded."""
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    who = os.environ.get("USERNAME") or os.environ.get("USER") or "?"
    account = os.environ.get("CISCO_SRV_ACCOUNT") or "?"
    stamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
        fh.write(f"{stamp}\tuser={who}\taccount={account}\tunit={unit} ({host})\t{cmd}\n")


def GetCreds():
    user = os.environ.get("CISCO_SRV_ACCOUNT")
    pwd = os.environ.get("CISCO_SRV_PWD")
    if not user or not pwd:
        print("CISCO_SRV_ACCOUNT / CISCO_SRV_PWD NOT SET")
        sys.exit(1)
    return user, pwd


class FTD:
    def __init__(self, host):
        from netmiko import ConnectHandler

        init_hosts()
        if host not in ALL_HOSTS:
            sys.exit(f"Refusing to connect to {host}: not an ftd device in NetBox")
        user, pwd = GetCreds()
        self.host = host
        # .99-class units are slow to show the prompt; generous timeouts. No session_log (it would record the login).
        self.conn = ConnectHandler(device_type="cisco_ftd", host=host, username=user, password=pwd,
                                   timeout=60, conn_timeout=30, auth_timeout=60, banner_timeout=60,
                                   fast_cli=False, global_delay_factor=4)
        self.name = ALL_HOSTS[host] or self._hostname() or host

    def _hostname(self):
        """FTD 'show version' starts with '---[ <hostname> ]---'."""
        try:
            m = re.search(r"\[\s*(\S+)\s*\]", self.run("show version"))
            return m.group(1) if m else None
        except Exception:
            return None

    def run(self, cmd):
        if not ALLOWED.match(cmd):
            sys.exit(f"Refusing to send command not on the allowlist: {cmd}")
        # Long capture commands wrap on the FTD terminal, so netmiko can't match their echo.
        verify = not cmd.startswith(("capture ", "no capture "))
        if not cmd.startswith("show "):
            audit(self.host, self.name, cmd)
        out = self.conn.send_command(cmd, read_timeout=120, cmd_verify=verify)
        if re.search(r"Syntax error|^ERROR", out, re.M):
            # CLISH keeps a rejected command on the line, and the next command would be appended
            # to it. Clear the line (Ctrl+U) before doing anything else, then stop.
            self.conn.write_channel("\x15")
            time.sleep(1)
            self.conn.clear_buffer()
            raise RuntimeError(f"FTD rejected '{cmd}': {out.strip()}")
        return out

    def close(self):
        self.conn.disconnect()


# ---------------------------------------------------------------- failover

def failover_status(group):
    """Connect to every unit of a group. Returns {host: (FTD|None, role, state, output)}."""
    units = {}
    for host in group:
        try:
            dev = FTD(host)
            out = dev.run("show failover")
        except SystemExit:
            raise
        except Exception as e:
            units[host] = (None, None, f"unreachable ({type(e).__name__})", "")
            continue
        m = re.search(r"This host:\s+(Primary|Secondary)\s+-\s+(.+?)\s*$", out, re.M)
        on = re.search(r"^Failover On", out, re.M) is not None
        role, state = (m.group(1), m.group(2)) if m else (None, "unknown")
        if not on:
            state = "failover not On"
        units[host] = (dev, role, state, out)
    return units


def print_status(units):
    for host, (dev, role, state, _) in units.items():
        name = dev.name if dev else (ALL_HOSTS.get(host) or "")
        print(f"  {host:15} {name:24} {role or '?':10} {state}")


def get_active(group):
    """Return an FTD connection to the active unit of a group, or exit if the state is unclear.

    HA pair: exactly one unit Active and the other Standby Ready. Standalone (one IP in the group):
    the unit must report failover Off; if failover is On, its peer is missing from NetBox (platform ftd)."""
    units = failover_status(group)
    print("Failover state:")
    print_status(units)

    def close_all():
        for dev, *_ in units.values():
            if dev:
                dev.close()

    if len(group) == 1:
        (host, (dev, _, state, _)), = units.items()
        if dev is None or state != "failover not On":
            close_all()
            sys.exit("STOP: standalone unit is unreachable or reports failover On (add its peer to "
                     "NetBox with platform ftd). No capture run.")
        print(f"Standalone unit: {dev.name} ({dev.host})\n")
        return dev
    active = [h for h, u in units.items() if u[2] == "Active"]
    standby = [h for h, u in units.items() if u[2] == "Standby Ready"]
    if len(active) != 1 or len(standby) != 1:
        close_all()
        sys.exit("STOP: failover state is unclear (need exactly one Active and one Standby Ready). No capture run.")
    units[standby[0]][0].close()
    dev = units[active[0]][0]
    print(f"Active unit: {dev.name} ({dev.host})\n")
    return dev


# ---------------------------------------------------------------- helpers

def parse_net(s):
    try:
        return ipaddress.ip_network(s.strip(), strict=False)
    except ValueError:
        sys.exit(f"Invalid IP or CIDR: {s} (ranges are not supported for captures)")


def acl_addr(net):
    return f"host {net.network_address}" if net.prefixlen == 32 else f"{net.network_address} {net.netmask}"


def sample_ip(net):
    return net.network_address if net.prefixlen >= 31 else net.network_address + 1


def match_clause(args):
    m = f"match {args.proto} {acl_addr(args.src)} {acl_addr(args.dst)}"
    if args.proto in ("tcp", "udp") and args.port:
        lo, _, hi = args.port.partition("-")
        m += f" range {lo} {hi}" if hi else f" eq {lo}"
    return m


def fetch_interfaces(dev):
    """nameif / physical interface / security level / IP from the device."""
    ips = {}
    for line in dev.run("show interface ip brief").splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(IP, parts[1]):
            ips[parts[0]] = parts[1]
    ifaces = []
    for line in dev.run("show nameif").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-1].isdigit() and parts[0] != "Interface":
            ifaces.append({"nameif": parts[1], "interface": parts[0],
                           "security": int(parts[-1]), "ip": ips.get(parts[0], "")})
    return ifaces


def _read_cache():
    if os.path.exists(CACHE):
        with open(CACHE, encoding="utf-8") as f:
            return json.load(f)
    return {}


def load_interfaces(group, dev=None, refresh=False):
    """Cached interface list for a firewall; fetched from dev when missing, stale or refresh=True."""
    cache = _read_cache()
    entry = cache.get(group_key(group))
    if not refresh and entry:
        age = (datetime.now() - datetime.fromisoformat(entry["fetched"])).days
        if age < CACHE_DAYS and entry.get("interfaces"):
            return entry["interfaces"]
    if dev is None:
        return None
    ifaces = fetch_interfaces(dev)
    cache[group_key(group)] = {"fetched": datetime.now().isoformat(timespec="seconds"),
                               "unit": dev.name, "interfaces": ifaces}
    with open(CACHE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=4)
    return ifaces


def print_interfaces(ifaces, marks=None):
    marks = marks or {}
    print(f"  {'#':>2}  {'nameif':16} {'interface':16} {'ip':16} sec")
    for i, it in enumerate(ifaces, 1):
        tag = marks.get(it["nameif"], "")
        print(f"  {i:>2}  {it['nameif']:16} {it['interface']:16} {it['ip'] or '-':16} {it['security']:>3}  {tag}")


def pick_interface(ifaces, label, suggested):
    """Prompt for an interface by number or name (Enter = suggested)."""
    names = [it["nameif"] for it in ifaces]
    while True:
        hint = f" [Enter = {suggested}]" if suggested else ""
        try:
            ans = input(f"{label} interface (number or nameif){hint}: ").strip()
        except EOFError:
            sys.exit("\nNo interactive input. Re-run with --ingress <nameif> --egress <nameif>.")
        if not ans and suggested:
            return suggested
        if ans.isdigit() and 1 <= int(ans) <= len(names):
            return names[int(ans) - 1]
        if ans in names:
            return ans
        print("  Not a valid choice.")


def route_iface(dev, ip):
    """Interface the firewall uses to reach ip (falls back to the default route)."""
    for target in (str(ip), "0.0.0.0"):
        out = dev.run(f"show route {target}")
        m = re.search(r"via ([A-Za-z0-9_./-]+)\s*$", out, re.M)
        if m and "not in table" not in out.lower():
            return m.group(1)
    return None


def parse_captures(text):
    """Parse 'show capture' into a list of capture settings."""
    caps = []
    for line in text.splitlines():
        if line.startswith("capture "):
            hdr = line
            m = re.search(r"\[(Capturing|Stopped|Buffer Full)", hdr)
            caps.append({
                "name": hdr.split()[1],
                "type": (re.search(r"\btype (\S+)", hdr) or [None, "raw-data"])[1],
                "trace": re.search(r"\btrace\b", hdr) is not None,
                "interfaces": re.findall(r"\binterface (\S+)", hdr),
                "circular": "circular-buffer" in hdr,
                "acl": "access-list" in hdr,
                "state": m.group(1) if m else "unknown",
                "matches": [],
                "header": hdr.strip(),
            })
        elif caps and line.strip().startswith("match "):
            caps[-1]["matches"].append(line.strip())
    return caps


def existing_captures(dev):
    return [c["name"] for c in parse_captures(dev.run("show capture"))]


def _addr(tok, i):
    if i >= len(tok):
        return None, i
    if tok[i] in ("any", "any4"):
        return ipaddress.ip_network("0.0.0.0/0"), i + 1
    if tok[i] == "host" and i + 1 < len(tok):
        return ipaddress.ip_network(f"{tok[i + 1]}/32"), i + 2
    if i + 1 < len(tok) and re.fullmatch(IP, tok[i]) and re.fullmatch(IP, tok[i + 1]):
        return ipaddress.ip_network(f"{tok[i]}/{tok[i + 1]}", strict=False), i + 2
    return None, i


def _port(tok, i):
    """(lo, hi) port range, None for any, or 'unknown' for operators/names we can't evaluate."""
    if i >= len(tok) or tok[i] not in ("eq", "range", "gt", "lt", "neq"):
        return None, i
    op = tok[i]
    try:
        if op == "eq":
            return (int(tok[i + 1]), int(tok[i + 1])), i + 2
        if op == "range":
            return (int(tok[i + 1]), int(tok[i + 2])), i + 3
        if op == "gt":
            return (int(tok[i + 1]) + 1, 65535), i + 2
        if op == "lt":
            return (0, int(tok[i + 1]) - 1), i + 2
    except (ValueError, IndexError):
        pass
    return "unknown", len(tok)


def parse_match(line):
    tok = line.split()[1:]
    if not tok:
        return None
    a, i = _addr(tok, 1)
    pa, i = _port(tok, i)
    b, i = _addr(tok, i)
    pb, i = _port(tok, i)
    if a is None or b is None or i != len(tok):
        return None
    return {"proto": tok[0], "a": a, "pa": pa, "b": b, "pb": pb}


def covers(cap, args):
    """True if one of the capture's match lines covers the requested flow (either direction)."""
    want = None
    if args.port:
        lo, _, hi = args.port.partition("-")
        want = (int(lo), int(hi or lo))

    def port_ok(p):
        return p is None or (want is not None and p != "unknown" and p[0] <= want[0] and want[1] <= p[1])

    for line in cap["matches"]:
        m = parse_match(line)
        if not m or m["proto"] not in ("ip", args.proto):
            continue
        fwd = args.src.subnet_of(m["a"]) and args.dst.subnet_of(m["b"]) and m["pa"] is None and port_ok(m["pb"])
        rev = args.dst.subnet_of(m["a"]) and args.src.subnet_of(m["b"]) and m["pb"] is None and port_ok(m["pa"])
        if fwd or rev:
            return True
    return False


def find_reusable(caps, role, iface, args):
    """Best existing capture for a role ('IN', 'OUT', 'DROP'), or None."""
    ok = []
    for c in caps:
        if c["acl"] or c["state"] == "unknown" or (c["state"] == "Buffer Full" and not c["circular"]):
            continue
        if role == "DROP":
            if c["type"] != "asp-drop":
                continue
        else:
            if c["type"] != "raw-data" or c["interfaces"] != [iface] or (role == "IN" and not c["trace"]):
                continue
        if covers(c, args):
            ok.append(c)
    ok.sort(key=lambda c: (c["state"] != "Capturing", not c["name"].startswith(PREFIX)))
    return ok[0] if ok else None


def actual_name(names, n):
    """Full device name for capture n (the FTD may have appended %intf=<nameif>%)."""
    if n in names:
        return n
    return next((x for x in names if x.startswith(n + "%")), None)


def baselines(dev, plan, created):
    """Total packets already captured per capture, so later checks only look at new packets."""
    return {pl["name"]: 0 if pl["name"] in created else capture_count(dev.run(f"show capture {pl['name']}"))
            for pl in plan.values()}


def window_packets(out, start, end):
    """[(number, text)] of packets whose timestamp falls between start and end (HH:MM:SS)."""
    pkts = []
    for num, ts, text in re.findall(r"^\s*(\d+):\s+(\d\d:\d\d:\d\d)\.\d+\s+(.*)$", out, re.M):
        if start is None or end is None:
            inside = True
        elif start <= end:
            inside = start <= ts <= end
        else:  # crossed midnight
            inside = ts >= start or ts <= end
        if inside:
            pkts.append((int(num), text))
    return pkts


def capture_count(out):
    m = re.search(r"(\d+) packets? captured", out)
    return int(m.group(1)) if m else 0


def parse_trace(out):
    actions = re.findall(r"^Action:\s*(\w+)", out, re.M)
    rules = []
    for r in re.findall(r"remark rule-id \d+: ((?:PREFILTER POLICY|ACCESS POLICY|RULE|L4 RULE|L7 RULE)[^\n]*)", out):
        if r.strip() not in rules:
            rules.append(r.strip())

    def g(pat):
        m = re.search(pat, out, re.M)
        return m.group(1) if m else None

    return {
        "action": actions[-1].lower() if actions else None,
        "drop": g(r"Drop-reason:\s*(.+)$"),
        "in": g(r"input-interface:\s*(\S+)"),
        "out": g(r"output-interface:\s*(\S+)"),
        "rules": rules,
    }


def print_trace(t, label):
    print(f"  {label}: Action={t['action'] or '?'}  in={t['in'] or '?'}  out={t['out'] or '?'}")
    if t["drop"]:
        print(f"    Drop-reason: {t['drop']}")
    for r in t["rules"]:
        print(f"    {r}")


def directions(pkts, src, dst):
    """Split packets into forward (src->dst) and reply (dst->src) packet numbers."""
    fwd, rep = [], []
    for num, text in pkts:
        m = re.search(rf"({IP})(?:\.\d+)? > ({IP})(?:\.\d+)?[: ]", text)
        if not m:
            continue
        a, b = ipaddress.ip_address(m.group(1)), ipaddress.ip_address(m.group(2))
        if a in src and b in dst:
            fwd.append(num)
        elif a in dst and b in src:
            rep.append(num)
    return fwd, rep


def safe(name):
    return re.sub(r"[%=]", "_", name)


def save(outdir, fname, text):
    with open(os.path.join(outdir, fname), "w", encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------- commands

def cmd_status(args):
    groups = [select_group(args.fw)] if args.fw else init_hosts()
    for g in groups:
        if len(groups) > 1:
            print(f"Firewall {describe_group(g)}:")
        units = failover_status(g)
        print_status(units)
        for dev, *_ in units.values():
            if dev:
                dev.close()


def cmd_vpn(args):
    """Read-only RA VPN view from the active unit. The FTD keeps only live sessions plus counters since boot."""
    dev = get_active(select_group(args.fw))
    try:
        print(dev.run("show version system"))
        print(dev.run("show vpn-sessiondb summary"))
        print(dev.run("show vpn-sessiondb anyconnect") if args.sessions else "")
    finally:
        dev.close()


def cmd_list(args):
    dev = get_active(select_group(args.fw))
    try:
        print(dev.run("show capture") or "(no captures)")
    finally:
        dev.close()


def route_marks(dev, args):
    """Mark the nameifs the routing table suggests for the source and destination."""
    marks = {}
    for label, net in (("source (route)", args.src), ("destination (route)", args.dst)):
        iface = route_iface(dev, sample_ip(net))
        if iface:
            marks[iface] = (marks[iface] + ", " if iface in marks else "<- ") + label
    return marks


def resolve_path(dev, group, args):
    ifaces = load_interfaces(group, dev, args.refresh)
    names = [it["nameif"] for it in ifaces]
    if not (args.ingress and args.egress):
        marks = route_marks(dev, args)
        sug = {lbl: next((n for n, m in marks.items() if lbl in m), None) for lbl in ("source", "destination")}
        print("Interfaces:")
        print_interfaces(ifaces, marks)
        print()
        if not sys.stdin.isatty():
            dev.close()
            sys.exit("Choose the source (ingress) and destination (egress) interfaces, then re-run with "
                     "--ingress <nameif> --egress <nameif>.")
        args.ingress = args.ingress or pick_interface(ifaces, "Source (ingress)", sug["source"])
        args.egress = args.egress or pick_interface(ifaces, "Destination (egress)", sug["destination"])
        print()
    for label, iface in (("ingress", args.ingress), ("egress", args.egress)):
        if iface not in names:
            dev.close()
            sys.exit(f"Unknown {label} interface {iface}. Known nameifs: {', '.join(names)} "
                     f"(use --refresh if interfaces changed)")
    return args.ingress, args.egress


def cmd_interfaces(args):
    group = select_group(args.fw)
    want_marks = args.src and args.dst
    ifaces = None if args.refresh or want_marks else load_interfaces(group)
    if ifaces is not None:
        print(f"Cached {_read_cache()[group_key(group)]['fetched']} ({CACHE})")
        print_interfaces(ifaces)
        return
    dev = get_active(group)
    try:
        ifaces = load_interfaces(group, dev, args.refresh)
        print_interfaces(ifaces, route_marks(dev, args) if want_marks else {})
    finally:
        dev.close()


def auto_desc(args):
    """Readable description from the flow, e.g. UDP53_10-9-9-9."""
    dst = str(args.dst.network_address).replace(".", "-") + (f"-{args.dst.prefixlen}" if args.dst.prefixlen < 32 else "")
    port = args.port.replace("-", "TO") if args.port else ""
    desc = f"{args.proto.upper()}{port}_{dst}"
    if len(desc) > MAX_DESC:
        desc = f"{port or args.proto.upper()}_{dst}"
    if len(desc) > MAX_DESC and args.port:
        desc = f"{args.port.split('-')[0]}_{dst}"
    return desc[:MAX_DESC]


def capture_base(args):
    desc = re.sub(r"[^A-Za-z0-9_-]", "", args.name or auto_desc(args)).upper().strip("_-")
    if not desc or len(desc) > MAX_DESC:
        sys.exit(f"--name must be 1-{MAX_DESC} letters/digits/_/-")
    return PREFIX + desc


def check_limits(args):
    if not 0 < args.buffer <= MAX_BUFFER:
        sys.exit(f"--buffer must be 1..{MAX_BUFFER}")
    if not 0 < args.trace_count <= MAX_TRACE:
        sys.exit(f"--trace-count must be 1..{MAX_TRACE}")


def build_plan(dev, group, args, base):
    """Decide, per role, whether to reuse an existing capture or create a new one."""
    ingress, egress = resolve_path(dev, group, args)
    match = match_clause(args)
    roles = {"IN": f"capture {base}_IN buffer {args.buffer} interface {ingress} "
                   f"trace trace-count {args.trace_count} {match}"}
    if egress != ingress:
        roles["OUT"] = f"capture {base}_OUT buffer {args.buffer} interface {egress} {match}"
    roles["DROP"] = f"capture {base}_DROP type asp-drop all buffer {args.buffer} {match}"

    existing = parse_captures(dev.run("show capture"))
    names_in_use = {c["name"] for c in existing}
    plan = {}
    for role, cmd in roles.items():
        reuse = find_reusable(existing, role, ingress if role == "IN" else egress, args)
        name = reuse["name"] if reuse else f"{base}_{role}"
        if not reuse and name in names_in_use:
            dev.close()
            sys.exit(f"Capture name {name} is already in use. Run 'ftd_capture_helper.py check/stop --name "
                     f"{base[len(PREFIX):]}' if it's an open session, or pick another --name.")
        plan[role] = {"name": name, "reuse": reuse, "cmd": cmd}
    return ingress, egress, match, plan


def print_plan(dev, args, ingress, egress, match, plan, extra=""):
    print("PLAN")
    print(f"  Unit:     {dev.name} ({dev.host}) - Active")
    print(f"  Ingress:  {ingress}   Egress: {egress}")
    print(f"  Filter:   {match}")
    print(f"  Buffer:   {args.buffer} bytes (new captures)   Trace count: {args.trace_count}{extra}")
    for role, pl in plan.items():
        r = pl["reuse"]
        if r:
            action = ("already capturing" if r["state"] == "Capturing"
                      else f"{r['state'].lower()} - will start it, and stop it again when finished")
            print(f"  {role:4} USING EXISTING CAPTURE {r['name']} ({action})")
            print(f"         {r['header']}")
            for m in r["matches"]:
                print(f"           {m}")
        else:
            print(f"  {role:4} CREATE  {pl['cmd']}")
    print()


def start_plan(dev, plan):
    """Create new captures and start stopped reused ones. Returns (created, started)."""
    created, started = [], []
    try:
        for pl in plan.values():
            r = pl["reuse"]
            if r:
                if r["state"] != "Capturing":
                    dev.run(f"no capture {r['name']} stop")
                    started.append(r["name"])
                    print(f"USING EXISTING CAPTURE {r['name']} - started it")
                else:
                    print(f"USING EXISTING CAPTURE {r['name']} - already capturing")
                continue
            created.append(pl["name"])  # recorded first, so cleanup covers a half-finished command
            out = dev.run(pl["cmd"])
            if re.search(r"^(ERROR|%|Invalid|Incomplete)", out, re.M | re.I):
                raise RuntimeError(f"{pl['name']} failed: {out.strip()}")
        names = existing_captures(dev)
        missing = [n for n in created if not actual_name(names, n)]
        if missing:
            raise RuntimeError(f"capture(s) not present after creating: {', '.join(missing)}")
        created[:] = [actual_name(names, n) for n in created]
        for pl in plan.values():
            if not pl["reuse"]:
                pl["name"] = actual_name(names, pl["name"])
        for n in created:
            print(f"Created {n}")
    except BaseException:
        try:
            names = existing_captures(dev)
            created[:] = [actual_name(names, n) for n in created if actual_name(names, n)]
        except Exception:
            pass
        finish(dev, created, started)
        raise
    return created, started


def finish(dev, created, started, stop_only=False):
    """Stop reused captures we started; remove (or just stop) captures we created."""
    for n in started:
        dev.run(f"capture {n} stop")
        print(f"  Stopped existing capture {n} again (it was stopped before)")
    for n in created:
        dev.run(f"capture {n} stop" if stop_only else f"no capture {n}")
    if created:
        if stop_only:
            print(f"  Stopped (kept on the device): {', '.join(created)}")
        else:
            left = [n for n in existing_captures(dev) if n in created]
            print("  Removed " + ", ".join(created) if not left else f"  WARNING: still present: {', '.join(left)}")


def analyze(dev, plan, src, dst, ingress, egress, base_counts, outdir):
    """Report what the captures saw for this flow since the baseline counts. Returns the verdict."""
    os.makedirs(outdir, exist_ok=True)
    res = {}
    present = set(existing_captures(dev))
    for role, pl in plan.items():
        if pl["name"] not in present:
            print(f"  WARNING: capture {pl['name']} no longer exists on the device")
            res[role] = []
            continue
        out = dev.run(f"show capture {pl['name']}")
        save(outdir, f"{safe(pl['name'])}.txt", out)
        pkts = window_packets(out, None, None)
        delta = capture_count(out) - base_counts.get(pl["name"], 0)
        if delta > len(pkts):
            print(f"  NOTE: {pl['name']} captured {delta} new packets but only holds the last {len(pkts)}")
        res[role] = pkts[-delta:] if delta > 0 else []
    in_fwd, in_rep = directions(res["IN"], src, dst)
    out_fwd, out_rep = directions(res["OUT"], src, dst) if "OUT" in res else (in_fwd, in_rep)
    drop_fwd, drop_rep = directions(res["DROP"], src, dst)
    drop_nums = set(drop_fwd + drop_rep)
    drop_reasons = sorted(set(
        r.strip(" ,") for num, text in res["DROP"] if num in drop_nums
        for r in re.findall(r"Drop-reason:\s*(\([^)]+\)[^,\n]*)", text)))

    traces = []
    if plan["IN"]["name"] in present:
        for num in in_fwd[:3]:
            out = dev.run(f"show capture {plan['IN']['name']} packet-number {num} trace")
            save(outdir, f"{safe(plan['IN']['name'])}_trace_{num}.txt", out)
            traces.append((num, parse_trace(out)))

    print("RESULTS (packets for this flow captured since the session started)")
    for role, pl in plan.items():
        tag = " [existing capture]" if pl["reuse"] else ""
        if role == "IN":
            print(f"  IN   {pl['name']} ({ingress}){tag}: {len(in_fwd)} src->dst, {len(in_rep)} replies")
        elif role == "OUT":
            print(f"  OUT  {pl['name']} ({egress}){tag}: {len(out_fwd)} src->dst, {len(out_rep)} replies")
        else:
            print(f"  DROP {pl['name']} (asp-drop){tag}: {len(drop_nums)} dropped")
    for r in drop_reasons:
        print(f"    Drop-reason: {r}")
    rules = []
    for num, t in traces:
        if t["action"]:
            print_trace(t, f"live trace packet {num}")
            rules += [r for r in t["rules"] if r not in rules]
        else:
            print(f"  live trace packet {num}: no trace data (the capture's trace-count may be used up)")

    replies = in_rep or out_rep
    if not in_fwd:
        verdict = f"NOT SEEN - no matching traffic reached {ingress} since the capture started (traffic never hit the firewall, or wasn't generated)"
    elif drop_nums or any(t["action"] == "drop" for _, t in traces):
        verdict = "DENIED - the firewall dropped the traffic" + (f" ({'; '.join(drop_reasons)})" if drop_reasons else "")
    elif out_fwd and replies:
        verdict = "ALLOWED - traffic passed the firewall and the destination replied"
    elif out_fwd:
        verdict = "ALLOWED by the firewall - but no reply seen (check the server, host firewall or return routing)"
    else:
        verdict = f"UNCLEAR - seen on {ingress} but not on {egress} and no drops recorded; review the saved output"
    reused = [pl["name"] for pl in plan.values() if pl["reuse"]]
    if reused:
        print(f"\nNOTE: using existing capture(s) {', '.join(reused)}.")
    print(f"\nVERDICT (live): {verdict}")
    print("RULE: " + ("; ".join(rules) if rules else "not available (no trace data)"))
    save(outdir, "summary.txt", f"{verdict}\nRule: {'; '.join(rules) or 'n/a'}\n"
                                f"Existing captures used: {', '.join(reused) or 'none'}\n")
    print(f"Output saved to {outdir}")
    return verdict


# ---------------------------------------------------------------- sessions

def load_sessions():
    if os.path.exists(SESSIONS):
        with open(SESSIONS, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_sessions(sessions):
    os.makedirs(os.path.dirname(SESSIONS), exist_ok=True)
    with open(SESSIONS, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=4)


def pick_session(sessions, name):
    if name:
        key = name if name.upper().startswith(PREFIX) else PREFIX + name.upper()
        if key not in sessions:
            sys.exit(f"No open session {key}. Open sessions: {', '.join(sessions) or 'none'}")
        return key
    if len(sessions) != 1:
        sys.exit(f"Pass --name. Open sessions: {', '.join(sessions) or 'none'}")
    return next(iter(sessions))


def session_args(sess):
    return argparse.Namespace(src=parse_net(sess["src"]), dst=parse_net(sess["dst"]))


def active_for_session(sess):
    dev = get_active(group_for_hosts(sess["group"]))
    if dev.host != sess["unit_host"]:
        dev.close()
        sys.exit(f"STOP: the active unit changed since the capture started (was {sess['unit']} "
                 f"{sess['unit_host']}). A failover happened, so the captures are on the other unit. "
                 f"Tell the user before doing anything else.")
    return dev


def cmd_start(args):
    check_limits(args)
    base = capture_base(args)
    sessions = load_sessions()
    if base in sessions:
        sys.exit(f"Session {base} is already open. Use 'check' or 'stop' with --name {base[len(PREFIX):]}, "
                 f"or pick another --name.")
    group = select_group(args.fw)
    dev = get_active(group)
    try:
        ingress, egress, match, plan = build_plan(dev, group, args, base)
        print_plan(dev, args, ingress, egress, match, plan)
        if not args.yes:
            print("Nothing was created or started. Re-run with --yes to start the capture.")
            return
        created, started = start_plan(dev, plan)
        base_counts = baselines(dev, plan, created)
        sessions[base] = {
            "group": list(group), "unit": dev.name, "unit_host": dev.host,
            "src": str(args.src), "dst": str(args.dst), "proto": args.proto, "port": args.port,
            "ingress": ingress, "egress": egress, "match": match,
            "baseline": base_counts, "local_start": datetime.now().isoformat(timespec="seconds"),
            "plan": {role: {"name": pl["name"], "reuse": pl["reuse"]} for role, pl in plan.items()},
            "created": created, "started": started,
        }
        save_sessions(sessions)
        print(f"\nCapture session {base} is running.")
        print(f"Check it with:  python ftd_capture_helper.py check --name {base[len(PREFIX):]}")
        print(f"Stop it with:   python ftd_capture_helper.py stop --name {base[len(PREFIX):]}")
    finally:
        dev.close()


def cmd_check(args):
    sessions = load_sessions()
    key = pick_session(sessions, args.name)
    sess = sessions[key]
    dev = active_for_session(sess)
    try:
        sa = session_args(sess)
        outdir = os.path.join(os.path.dirname(SESSIONS), f"{key}_{datetime.now():%Y%m%d_%H%M%S}")
        print(f"Session {key}: {sess['match']}  ({sess['ingress']} -> {sess['egress']})\n")
        analyze(dev, sess["plan"], sa.src, sa.dst, sess["ingress"], sess["egress"], sess["baseline"], outdir)
    finally:
        dev.close()


def cmd_stop(args):
    sessions = load_sessions()
    key = pick_session(sessions, args.name)
    sess = sessions[key]
    dev = active_for_session(sess)
    try:
        print(f"Stopping session {key}:")
        finish(dev, sess["created"], sess["started"], stop_only=args.stop_only)
        if args.stop_only:
            sess["started"] = []
            sess["stopped"] = True
        else:
            del sessions[key]
        save_sessions(sessions)
    finally:
        dev.close()


def cmd_sessions(_):
    sessions = load_sessions()
    if not sessions:
        print("No open capture sessions.")
    for key, s_ in sessions.items():
        state = "stopped" if s_.get("stopped") else "running"
        names = ", ".join(pl["name"] + (" (existing)" if pl["reuse"] else "") for pl in s_["plan"].values())
        print(f"{key}  [{state}] since {s_['local_start']}  on {s_['unit']}  {s_['match']}  "
              f"{s_['ingress']} -> {s_['egress']}")
        print(f"    captures: {names}")


def cmd_capture(args):
    """One-shot: start, wait --duration, analyse, then stop/remove."""
    check_limits(args)
    base = capture_base(args)
    group = select_group(args.fw)
    dev = get_active(group)
    created, started = [], []
    try:
        ingress, egress, match, plan = build_plan(dev, group, args, base)
        print_plan(dev, args, ingress, egress, match, plan, f"   Duration: {args.duration}s")
        if not args.yes:
            print("Nothing was created or started. Re-run with --yes to start the capture.")
            return
        created, started = start_plan(dev, plan)
        base_counts = baselines(dev, plan, created)
        print(f"\nCapturing for up to {args.duration}s (Ctrl+C to stop early)...")
        start = time.time()
        try:
            while time.time() - start < args.duration:
                time.sleep(max(1, min(10, args.duration - (time.time() - start))))
                counts = {role: capture_count(dev.run(f"show capture {pl['name']}")) for role, pl in plan.items()}
                print("  " + "  ".join(f"{role}={c}" for role, c in counts.items()) + "  (total in buffer)")
                if not plan["IN"]["reuse"] and counts["IN"] >= args.trace_count:
                    print("  Trace count reached, stopping.")
                    break
        except KeyboardInterrupt:
            print("  Stopped early.")
        print()
        outdir = os.path.join(args.out, f"{base}_{datetime.now():%Y%m%d_%H%M%S}")
        analyze(dev, plan, args.src, args.dst, ingress, egress, base_counts, outdir)
    finally:
        if created or started:
            print("\nCleanup:")
            if args.keep:
                for n in started:
                    dev.run(f"capture {n} stop")
                print(f"  Captures kept (--keep): {', '.join(created)}. "
                      "Remove later with: python ftd_capture_helper.py cleanup --yes")
            else:
                finish(dev, created, started)
        dev.close()


def cmd_cleanup(args):
    group = select_group(args.fw)
    dev = get_active(group)
    try:
        mine = [n for n in existing_captures(dev) if n.startswith(PREFIX)]
        sessions = load_sessions()
        here = {k: s for k, s in sessions.items() if set(s.get("group", [])) <= set(group)}
        restop = [(k, n) for k, s in here.items() for n in s["started"]]
        if not mine and not restop:
            print("No CLAUDE_* captures on the active unit.")
            return
        if mine:
            print("CLAUDE_* captures found: " + ", ".join(mine))
        if restop:
            print("Reused captures to stop again: " + ", ".join(n for _, n in restop))
        if not args.yes:
            print("Re-run with --yes to remove them.")
            return
        for n in mine:
            dev.run(f"no capture {n}")
            print(f"  Removed {n}")
        for key, n in restop:
            dev.run(f"capture {n} stop")
            print(f"  Stopped existing capture {n} again (session {key})")
        for key in here:
            del sessions[key]
        save_sessions(sessions)
    finally:
        dev.close()


def main():
    ap = argparse.ArgumentParser(description="Packet captures on FTD firewalls listed in NetBox (active unit only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def fw_arg(p):
        p.add_argument("--fw", help="firewall to use (IP or NetBox name); "
                                    "needed only when more than one is configured")

    p = sub.add_parser("status", help="failover state of the units")
    fw_arg(p)
    p = sub.add_parser("list", help="show captures on the active unit")
    fw_arg(p)
    p = sub.add_parser("vpn", help="RA VPN summary (live sessions, cumulative and peak since boot); read-only")
    p.add_argument("--sessions", action="store_true", help="also list each live AnyConnect session")
    fw_arg(p)
    cl = sub.add_parser("cleanup", help="remove leftover CLAUDE_* captures")
    cl.add_argument("--yes", action="store_true", help="actually remove them")
    fw_arg(cl)

    ip = sub.add_parser("interfaces", help="list (cached) interfaces, optionally marking the route-suggested ones")
    ip.add_argument("--src", type=parse_net, help="source IP/CIDR to mark the suggested ingress")
    ip.add_argument("--dst", type=parse_net, help="destination IP/CIDR to mark the suggested egress")
    ip.add_argument("--refresh", action="store_true", help="re-download the interface list")
    fw_arg(ip)

    def flow_args(p):
        p.add_argument("--src", required=True, type=parse_net, help="source IP or CIDR")
        p.add_argument("--dst", required=True, type=parse_net, help="destination IP or CIDR")
        p.add_argument("--proto", default="tcp", choices=["tcp", "udp", "icmp", "ip"], help="default tcp")
        p.add_argument("--port", help="destination port or range (e.g. 443 or 8000-8010)")
        p.add_argument("--ingress", help="source (ingress) nameif; prompted for if omitted")
        p.add_argument("--egress", help="destination (egress) nameif; prompted for if omitted")
        p.add_argument("--refresh", action="store_true", help="re-download the interface list")
        p.add_argument("--name", help=f"description after CLAUDE_ (max {MAX_DESC}); default e.g. UDP53_10-9-9-9")
        p.add_argument("--buffer", type=int, default=1048576, help="bytes per new capture (default 1 MB, max 32 MB)")
        p.add_argument("--trace-count", type=int, default=20, help="packets to trace (default 20, max 100)")
        p.add_argument("--yes", action="store_true", help="actually create/start the captures")
        fw_arg(p)

    st = sub.add_parser("start", help="create/reuse captures and leave them running")
    flow_args(st)
    ck = sub.add_parser("check", help="analyse an open session: allowed or denied, and by which rule")
    ck.add_argument("--name", help="session description (optional if only one is open)")
    sp = sub.add_parser("stop", help="end an open session: remove new captures, re-stop reused ones")
    sp.add_argument("--name", help="session description (optional if only one is open)")
    sp.add_argument("--stop-only", action="store_true", help="stop new captures but keep them on the device")
    sub.add_parser("sessions", help="list open capture sessions")

    p = sub.add_parser("capture", help="one-shot: create, wait, analyse, then remove")
    flow_args(p)
    p.add_argument("--duration", type=int, default=60, help="seconds to capture (default 60)")
    p.add_argument("--out", default=str(HERE / "captures"), help="output folder (default ./captures)")
    p.add_argument("--keep", action="store_true", help="don't remove the new captures afterwards")
    args = ap.parse_args()
    if getattr(args, "port", None) and not re.fullmatch(r"\d+(-\d+)?", args.port):
        sys.exit("--port must be a number or range like 8000-8010")
    {"status": cmd_status, "list": cmd_list, "vpn": cmd_vpn, "cleanup": cmd_cleanup, "interfaces": cmd_interfaces,
     "start": cmd_start, "check": cmd_check, "stop": cmd_stop, "sessions": cmd_sessions,
     "capture": cmd_capture}[args.cmd](args)


if __name__ == "__main__":
    main()
