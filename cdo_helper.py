"""Read-only access to the Cisco Security Cloud Control (CDO) cloud-delivered FMC REST API.

Settings:
    CDO_URL   tenant URL, e.g. https://<tenant>.app.us.cdo.cisco.com   (.env; not a secret)
    CDO_UUID  FMC domain UUID                                         (environment variable)
    CDO_API   API bearer token                                        (environment variable; never printed)

Only GET requests are sent, so nothing in the firewall config can change.

From the command line:
    python cdo_helper.py devices                                # managed devices (FTDs)
    python cdo_helper.py ha                                     # FTD HA pairs
    python cdo_helper.py interfaces <device>                    # all interfaces of one device
    python cdo_helper.py routes <device>                        # IPv4 static routes of one device
    python cdo_helper.py objects <name-or-value>                # network objects by name or value
    python cdo_helper.py prefilter-rules [--policy NAME]        # rules of a prefilter policy
    python cdo_helper.py prefilter-check --src 10.1.1.10 --dst 170.133.208.5 --ports 443,tcp/22,udp/1194,8000-8010,icmp
    python cdo_helper.py prefilter-check --input request.csv [--summary]
    python cdo_helper.py get object/networkgroups -p expanded=true      # any GET path under the domain

prefilter-check answers "does an enabled rule of Vendor-Prefilter-Policy already allow source -> destination
on these ports?". Ports: "443" (TCP), "tcp/443", "udp/53", "any/443", "8000-8010" (TCP), "icmp".
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from helper_common import table, to_json

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")  # CDO_URL; environment variables win

POLICY_NAME = "Vendor-Prefilter-Policy"
ALLOW_ACTIONS = {"FASTPATH", "ANALYZE"}
PROTO_NAMES = {"6": "TCP", "17": "UDP", "1": "ICMP", "TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP"}

OBJECT_ENDPOINTS = {
    "Host": "object/hosts",
    "Network": "object/networks",
    "Range": "object/ranges",
    "NetworkGroup": "object/networkgroups",
    "FQDN": "object/fqdns",
    "ProtocolPortObject": "object/protocolportobjects",
    "PortObjectGroup": "object/portobjectgroups",
    "ICMPV4Object": "object/icmpv4objects",
}


class CDOError(Exception):
    """A CDO setting is missing or an API call failed (never contains the token)."""


class CDO:
    """Minimal read-only cdFMC client: GET only, limit/offset paging, retry on 429."""

    def __init__(self, timeout: int = 60):
        base = (os.environ.get("CDO_URL") or "").rstrip("/")
        uuid = os.environ.get("CDO_UUID")
        token = os.environ.get("CDO_API")
        missing = [n for n, v in (("CDO_URL (in .env)", base), ("CDO_UUID", uuid), ("CDO_API", token)) if not v]
        if missing:
            raise CDOError(f"not set: {', '.join(missing)}")
        self.base = base
        self.api = f"{base}/api/fmc_config/v1/domain/{uuid}"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "Authorization": f"Bearer {token}"})

    def get(self, path: str, **params: Any) -> Any:
        """GET one page. FMC allows about 120 requests a minute, so 429 is retried with backoff."""
        url = path if path.startswith("http") else f"{self.api}/{path.lstrip('/')}"
        for attempt in range(6):
            r = self.session.get(url, params=params or None, timeout=self.timeout)
            if r.status_code == 429:
                time.sleep(5 * (attempt + 1))
                continue
            if r.status_code >= 400:
                detail = r.text[:300].replace("\n", " ")
                raise CDOError(f"{r.status_code} on {url.replace(self.api, '')}: {detail}")
            return r.json()
        raise CDOError(f"rate limited too many times on {url.replace(self.api, '')}")

    def get_all(self, path: str, **params: Any) -> list:
        """GET every page of a collection (limit 1000, offset)."""
        items, offset = [], 0
        while True:
            data = self.get(path, limit=1000, offset=offset, **params)
            items.extend(data.get("items", []))
            pages = data.get("paging", {}).get("pages", 1)
            offset += 1000
            if offset // 1000 >= pages:
                return items

    # -- lookups -------------------------------------------------------------

    def devices(self) -> list[dict]:
        return self.get_all("devices/devicerecords", expanded="true")

    def device(self, text: str) -> dict:
        """A device record by exact name (any case), else a unique name substring, else its id."""
        devs = self.devices()
        exact = [d for d in devs if d.get("name", "").lower() == text.lower() or d.get("id") == text]
        if exact:
            return exact[0]
        partial = [d for d in devs if text.lower() in d.get("name", "").lower()]
        if len(partial) == 1:
            return partial[0]
        if not partial:
            raise CDOError(f"no device matches {text!r}")
        raise CDOError(f"{text!r} matches {len(partial)} devices: {', '.join(d['name'] for d in partial)}")

    def interfaces(self, device_id: str) -> list[dict]:
        return self.get_all(f"devices/devicerecords/{device_id}/ftdallinterfaces", expanded="true")

    def static_routes(self, device_id: str) -> list[dict]:
        return self.get_all(f"devices/devicerecords/{device_id}/routing/ipv4staticroutes", expanded="true")

    def ha_pairs(self) -> list[dict]:
        return self.get_all("devicehapairs/ftddevicehapairs", expanded="true")

    def network_objects(self, name_or_value: str) -> list[dict]:
        return self.get_all("object/networks", nameOrValue=name_or_value, expanded="true")

    def prefilter_policy(self, name: str = POLICY_NAME) -> dict:
        policy = next((p for p in self.get_all("policy/prefilterpolicies") if p["name"] == name), None)
        if not policy:
            raise CDOError(f"prefilter policy {name!r} not found")
        return policy

    def prefilter_rules(self, policy_id: str) -> list[dict]:
        rules = self.get_all(f"policy/prefilterpolicies/{policy_id}/prefilterrules", expanded="true")
        return sorted(rules, key=lambda r: r["metadata"]["ruleIndex"])

    def access_policy(self, name: str) -> dict:
        """Full access control policy (with defaultAction and prefilterPolicySetting) by name."""
        pol = next((p for p in self.get_all("policy/accesspolicies") if p["name"] == name), None)
        if not pol:
            raise CDOError(f"access policy {name!r} not found")
        return self.get(f"policy/accesspolicies/{pol['id']}")

    def access_rules(self, policy_id: str) -> list[dict]:
        rules = self.get_all(f"policy/accesspolicies/{policy_id}/accessrules", expanded="true")
        return sorted(rules, key=lambda r: r["metadata"]["ruleIndex"])

    def nat_policy(self, name: str) -> dict:
        pol = next((p for p in self.get_all("policy/ftdnatpolicies") if p["name"] == name), None)
        if not pol:
            raise CDOError(f"NAT policy {name!r} not found")
        return pol

    def nat_rules(self, policy_id: str) -> list[dict]:
        """Manual and auto NAT rules of a policy, each tagged with kind = manual | auto."""
        rules = [{**r, "kind": "manual"} for r in
                 self.get_all(f"policy/ftdnatpolicies/{policy_id}/manualnatrules", expanded="true")]
        rules += [{**r, "kind": "auto"} for r in
                  self.get_all(f"policy/ftdnatpolicies/{policy_id}/autonatrules", expanded="true")]
        return rules

    def policies_for_device(self, device_name: str) -> dict[str, str]:
        """Policies assigned to a device, its HA pair or its device group: {policy type: policy name}.

        Also adds 'PrefilterPolicy' from the access policy's prefilter setting."""
        dev = self.device(device_name)
        names = {dev["name"]}
        if (dev.get("deviceGroup") or {}).get("name"):
            names.add(dev["deviceGroup"]["name"])
        for ha in self.ha_pairs():
            if dev["name"] in ((ha.get("primary") or {}).get("name"), (ha.get("secondary") or {}).get("name")):
                names.add(ha["name"])
        found: dict[str, str] = {"device": dev["name"], "targets": ", ".join(sorted(names))}
        for a in self.get_all("assignment/policyassignments", expanded="true"):
            if any(t.get("name") in names for t in a.get("targets", [])):
                found[a["policy"]["type"]] = a["policy"]["name"]
        if found.get("AccessPolicy"):
            pre = (self.access_policy(found["AccessPolicy"]).get("prefilterPolicySetting") or {}).get("name")
            if pre:
                found["PrefilterPolicy"] = pre
        return found


# ---------------------------------------------------------------------------
# Prefilter rule check (from cdo_epic/check-prefilter.py)
# ---------------------------------------------------------------------------

_client: CDO | None = None
_cache: dict = {}


def client() -> CDO:
    global _client
    if _client is None:
        _client = CDO()
    return _client


def preload_objects():
    """Bulk-load every object type (expanded) so rules resolve without per-object GETs."""
    for obj_type, endpoint in OBJECT_ENDPOINTS.items():
        try:
            for item in client().get_all(endpoint, expanded="true"):
                _cache[(obj_type, item["id"])] = item
        except CDOError as e:
            print(f"  (could not bulk-load {endpoint}: {e}; will fetch individually)")


def get_object(obj):
    key = (obj["type"], obj["id"])
    if key not in _cache:
        endpoint = OBJECT_ENDPOINTS.get(obj["type"])
        _cache[key] = client().get(f"{endpoint}/{obj['id']}") if endpoint else None
    return _cache[key]


# ---------- networks ----------
# A network element is (version, lo_int, hi_int, label). "unverifiable" entries
# (FQDN, unknown types) are returned separately.

def parse_net_value(value):
    value = value.strip()
    if "-" in value:
        lo, hi = (ipaddress.ip_address(v.strip()) for v in value.split("-", 1))
        return lo.version, int(lo), int(hi)
    net = ipaddress.ip_network(value, strict=False)
    return net.version, int(net.network_address), int(net.broadcast_address)


def resolve_network(obj, path, seen=None):
    """Flatten a network object/group into (elements, unverifiable)."""
    seen = seen or set()
    elements, unverifiable = [], []
    label = f"{path} > {obj.get('name')}" if path else obj.get("name")
    if obj["type"] == "FQDN":
        return [], [f"{label} (FQDN)"]
    if obj["id"] in seen:
        return [], []
    seen.add(obj["id"])
    data = get_object(obj)
    if data is None:
        return [], [f"{label} (unsupported type {obj['type']})"]
    if obj["type"] == "NetworkGroup":
        for child in data.get("objects", []):
            e, u = resolve_network(child, label, seen)
            elements += e
            unverifiable += u
        for lit in data.get("literals", []):
            elements.append((*parse_net_value(lit["value"]), f"{label} > literal {lit['value']}"))
    else:
        elements.append((*parse_net_value(data["value"]), f"{label} = {data['value']}"))
    return elements, unverifiable


def rule_networks(field):
    """Return (elements, unverifiable, top_level_names); elements None means any."""
    if not field or (not field.get("objects") and not field.get("literals")):
        return None, [], []
    elements, unverifiable, names = [], [], []
    for obj in field.get("objects", []):
        names.append(f"{obj.get('name')} ({obj['type']})")
        e, u = resolve_network(obj, "")
        elements += e
        unverifiable += u
    for lit in field.get("literals", []):
        names.append(f"literal {lit['value']}")
        elements.append((*parse_net_value(lit["value"]), f"literal {lit['value']}"))
    return elements, unverifiable, names


class Target:
    """User-supplied source/destination: an IP, a CIDR network, or a range a-b."""

    def __init__(self, text):
        self.text = text.strip()
        self.version, self.lo, self.hi = parse_net_value(self.text)

    def __str__(self):
        return self.text


def net_match(target, elements):
    """Labels of elements that fully contain the target."""
    if elements is None:
        return ["any"]
    return [label for ver, lo, hi, label in elements
            if ver == target.version and lo <= target.lo and target.hi <= hi]


def net_overlap(target, elements):
    """Labels of elements that overlap the target but don't fully contain it."""
    if elements is None:
        return []
    return [label for ver, lo, hi, label in elements
            if ver == target.version and lo <= target.hi and target.lo <= hi
            and not (lo <= target.lo and target.hi <= hi)]


def print_overlaps(overlaps):
    if not overlaps:
        return
    print("\nPARTIAL IP OVERLAP - these enabled allow rules cover only PART of the requested range:")
    for rule, src_side, dst_side, ports in overlaps:
        print(f"  Rule #{rule['metadata']['ruleIndex']}: {rule['name']} ({rule.get('action')})")
        print(f"    Source: {src_side}")
        print(f"    Destination: {dst_side}")
        if ports:
            print(f"    Ports covered: {', '.join(ports)}")
    print("  The rest of the range is not covered by these rules. Widen the object or add a rule.")


def overlap_entry(target, elements, full_hits):
    """Describe one side for the overlap report, or None if it doesn't touch the target."""
    if full_hits:
        return "fully covered by " + "; ".join(full_hits)
    partial = net_overlap(target, elements)
    return "PARTIAL - " + "; ".join(partial) if partial else None


# ---------- ports ----------
# A port element is (proto, lo, hi, label); proto None = any protocol,
# lo/hi None = any port of that protocol.

def parse_port_range(port):
    if port in (None, "", "any"):
        return None, None
    if "-" in str(port):
        lo, hi = str(port).split("-", 1)
        return int(lo), int(hi)
    return int(port), int(port)


def resolve_port(obj, path, seen=None):
    seen = seen or set()
    label = f"{path} > {obj.get('name')}" if path else obj.get("name")
    if obj["id"] in seen:
        return []
    seen.add(obj["id"])
    data = get_object(obj)
    if data is None:
        return [(None, -1, -1, f"{label} (unsupported type {obj['type']}, not checked)")]
    if obj["type"] == "PortObjectGroup":
        elements = []
        for child in data.get("objects", []):
            elements += resolve_port(child, label, seen)
        return elements
    if obj["type"] == "ICMPV4Object":
        return [("ICMP", None, None, f"{label} (ICMP {data.get('icmpType', 'any')})")]
    proto = PROTO_NAMES.get(str(data.get("protocol", "")).upper(), data.get("protocol"))
    lo, hi = parse_port_range(data.get("port"))
    return [(proto, lo, hi, f"{label} = {proto}/{data.get('port', 'any')}")]


def rule_ports(field):
    """Return (elements, objects_on_rule); elements None means any."""
    if not field or (not field.get("objects") and not field.get("literals")):
        return None, []
    elements, objects = [], []
    for obj in field.get("objects", []):
        resolved = resolve_port(obj, "")
        objects.append((obj, resolved))
        elements += resolved
    for lit in field.get("literals", []):
        proto = PROTO_NAMES.get(str(lit.get("protocol", "")), lit.get("protocol"))
        if proto == "ICMP":
            elements.append(("ICMP", None, None, f"literal ICMP {lit.get('icmpType', 'any')}"))
        else:
            lo, hi = parse_port_range(lit.get("port"))
            elements.append((proto, lo, hi, f"literal {proto}/{lit.get('port', 'any')}"))
    return elements, objects


def parse_requested_ports(spec):
    ports = []
    for item in spec.split(","):
        item = item.strip().lower()
        if not item:
            continue
        if item == "icmp":
            ports.append(("ICMP", None, None, "ICMP"))
            continue
        proto = "TCP"  # no protocol given -> TCP; "any/443" matches any protocol
        if "/" in item:
            proto, item = item.split("/", 1)
            proto = proto.upper()
            if proto == "ANY":
                proto = None
        lo, hi = parse_port_range(item)
        ports.append((proto, lo, hi, f"{proto or 'any'}/{item}"))
    return ports


def port_match(req, elements):
    if elements is None:
        return ["any"]
    rproto, rlo, rhi, _ = req
    hits = []
    for proto, lo, hi, label in elements:
        if lo == -1:  # unsupported object
            continue
        if rproto == "ICMP":
            if proto in ("ICMP", None) and lo is None:
                hits.append(label)
            continue
        if proto == "ICMP" or (rproto and proto and proto != rproto):
            continue
        if lo is None or (lo <= rlo and rhi <= hi):
            hits.append(label)
    return hits


def describe_ports_on_rule(objects, literals):
    lines = []
    for obj, resolved in objects:
        if obj["type"] != "PortObjectGroup" and resolved:
            lines.append(f"      - {resolved[0][3]} ({obj['type']})")
        else:
            lines.append(f"      - {obj.get('name')} ({obj['type']})")
        if obj["type"] == "PortObjectGroup":
            for r in resolved:
                lines.append(f"          {r[3]}")
    for lit in literals:
        proto = PROTO_NAMES.get(str(lit.get("protocol", "")), lit.get("protocol"))
        lines.append(f"      - literal {proto}/{lit.get('port', lit.get('icmpType', 'any'))}")
    return lines


def print_rule_header(rule):
    src_if = ", ".join(o["name"] for o in rule.get("sourceInterfaces", {}).get("objects", [])) or "any"
    dst_if = ", ".join(o["name"] for o in rule.get("destinationInterfaces", {}).get("objects", [])) or "any"
    print(f"  Rule #{rule['metadata']['ruleIndex']}: {rule['name']}")
    print(f"    Action: {rule.get('action')}   Enabled: {rule.get('enabled')}")
    print(f"    Interfaces: {src_if} -> {dst_if}")
    if rule.get("sourcePorts"):
        print("    NOTE: rule restricts SOURCE ports - verify client source port matches.")


def ip_only(rules, src, dst, policy_name=POLICY_NAME):
    """No ports given: list every rule whose source and destination match, with its ports."""
    print(f"Checking {src} -> {dst} (any port) against {policy_name} ({len(rules)} rules)\n")
    matches, unverifiable, overlaps = [], [], []
    for rule in rules:
        if rule.get("ruleType") != "PREFILTER":
            continue
        src_el, src_unv, _ = rule_networks(rule.get("sourceNetworks"))
        dst_el, dst_unv, _ = rule_networks(rule.get("destinationNetworks"))
        if src_unv or dst_unv:
            unverifiable.append((rule, src_unv + dst_unv))
        src_hit, dst_hit = net_match(src, src_el), net_match(dst, dst_el)
        if src_hit and dst_hit:
            matches.append((rule, src_hit, dst_hit))
        elif rule.get("enabled") and rule.get("action") in ALLOW_ACTIONS:
            s, d = overlap_entry(src, src_el, src_hit), overlap_entry(dst, dst_el, dst_hit)
            if s and d:
                overlaps.append((rule, s, d, None))

    enabled_allow = [m for m in matches if m[0].get("enabled") and m[0].get("action") in ALLOW_ACTIONS]
    print("=" * 70)
    if enabled_allow:
        print(f"RESULT: {len(enabled_allow)} enabled allow rule(s) match this source and destination.")
    else:
        print("RESULT: NO MATCH - no enabled allow rule has this source and destination. "
              "A NEW RULE needs to be created.")
    print("=" * 70)

    for rule, src_hit, dst_hit in matches:
        print()
        print_rule_header(rule)
        if not rule.get("enabled"):
            print("    *** DISABLED ***")
        elif rule.get("action") not in ALLOW_ACTIONS:
            print(f"    *** {rule.get('action')} - this rule DENIES matching traffic ***")
        print(f"    Source matched by: {'; '.join(src_hit)}")
        print(f"    Destination matched by: {'; '.join(dst_hit)}")
        _, port_objs = rule_ports(rule.get("destinationPorts"))
        lits = (rule.get("destinationPorts") or {}).get("literals", [])
        if not port_objs and not lits:
            print("    Destination ports: any")
        else:
            print("    Destination ports:")
            for line in describe_ports_on_rule(port_objs, lits):
                print(line)

    print_overlaps(overlaps)

    if unverifiable:
        print("\nRules with objects that could not be verified (FQDN/unsupported):")
        for rule, items in unverifiable:
            print(f"  Rule #{rule['metadata']['ruleIndex']}: {rule['name']} - {', '.join(items)}")

    return matches


def check_ports(rules, src, dst, req_ports, policy_name=POLICY_NAME):
    print(f"Checking {src} -> {dst} ports [{', '.join(p[3] for p in req_ports)}] "
          f"against {policy_name} ({len(rules)} rules)\n")

    first_hit = {p[3]: None for p in req_ports}   # first enabled rule matching each port
    partial, candidates, disabled_hits, unverifiable, overlaps = [], [], [], [], []

    for rule in rules:
        if rule.get("ruleType") != "PREFILTER":
            continue
        src_el, src_unv, src_names = rule_networks(rule.get("sourceNetworks"))
        dst_el, dst_unv, dst_names = rule_networks(rule.get("destinationNetworks"))
        port_el, port_objs = rule_ports(rule.get("destinationPorts"))
        if src_unv or dst_unv:
            unverifiable.append((rule, src_unv + dst_unv))

        src_hit = net_match(src, src_el)
        dst_hit = net_match(dst, dst_el)
        port_hits = {p[3]: port_match(p, port_el) for p in req_ports}
        covered = [p for p, h in port_hits.items() if h]
        missing = [p for p, h in port_hits.items() if not h]

        if src_hit and dst_hit:
            if not rule.get("enabled"):
                if covered:
                    disabled_hits.append((rule, covered))
                continue
            for p in covered:
                if first_hit[p] is None:
                    first_hit[p] = (rule, src_hit, dst_hit, port_hits[p])
            if missing and rule.get("action") in ALLOW_ACTIONS:
                partial.append((rule, covered, missing, port_objs,
                                rule.get("destinationPorts", {}).get("literals", [])))
        elif rule.get("enabled") and rule.get("action") in ALLOW_ACTIONS and covered:
            s, d = overlap_entry(src, src_el, src_hit), overlap_entry(dst, dst_el, dst_hit)
            if s and d:
                overlaps.append((rule, s, d, covered))
            elif src_hit and not dst_hit:
                candidates.append((rule, "destination", dst_names, covered))
            elif dst_hit and not src_hit:
                candidates.append((rule, "source", src_names, covered))

    allowed = {p: h for p, h in first_hit.items() if h and h[0].get("action") in ALLOW_ACTIONS}
    blocked = {p: h for p, h in first_hit.items() if h and h[0].get("action") not in ALLOW_ACTIONS}
    not_covered = [p for p, h in first_hit.items() if h is None]

    # ---- summary ----
    print("=" * 70)
    if len(allowed) == len(req_ports):
        print("RESULT: ALLOWED - existing enabled rule(s) already cover all requested ports.")
    elif allowed:
        print("RESULT: PARTIAL - some ports are allowed, others are not.")
    elif blocked:
        print("RESULT: BLOCKED - the first matching rule blocks this traffic.")
    elif partial:
        print("RESULT: PORT MISSING - a rule matches source/destination but not the port(s).")
    else:
        print("RESULT: NO MATCH - no existing enabled rule allows this. A NEW RULE needs to be created.")
    print("=" * 70)

    seen_rules = {}
    for p, h in first_hit.items():
        if h:
            seen_rules.setdefault(h[0]["id"], (h, []))[1].append(p)
    if seen_rules:
        print("\nMatching enabled rules (first match per port):")
        for (rule, src_hit, dst_hit, _), ports in seen_rules.values():
            print_rule_header(rule)
            print(f"    Ports matched: {', '.join(ports)}")
            print(f"    Source matched by: {'; '.join(src_hit)}")
            print(f"    Destination matched by: {'; '.join(dst_hit)}")
            for p in ports:
                print(f"    {p} matched by: {'; '.join(first_hit[p][3])}")
            if rule.get("action") not in ALLOW_ACTIONS:
                print(f"    *** {rule.get('action')} - this rule DENIES {', '.join(ports)} ***")
            print()

    port_missing = [x for x in partial if any(p in not_covered for p in x[2])]
    if port_missing:
        print("Rules matching source AND destination but MISSING port(s):")
        for rule, covered, missing, objs, lits in port_missing:
            print_rule_header(rule)
            print(f"    Covered ports: {', '.join(covered) or 'none'}")
            print(f"    MISSING ports: {', '.join(m for m in missing if m in not_covered)}")
            print("    Port objects on this rule (update one of these, or add a port):")
            for line in describe_ports_on_rule(objs, lits):
                print(line)
            if objs:
                print("    WARNING: port objects/groups may be shared by other rules.")
            print()

    close = [c for c in candidates if any(p in not_covered for p in c[3])]
    if close:
        print("Close candidates (ports match, one side of the IP pair does not):")
        for rule, side, names, covered in close:
            print(f"  Rule #{rule['metadata']['ruleIndex']}: {rule['name']} ({rule.get('action')}) "
                  f"- {side} {dst if side == 'destination' else src} not in: {', '.join(names)}")
        print()

    overlaps = [o for o in overlaps if any(p in not_covered for p in o[3])]
    if overlaps:
        print_overlaps(overlaps)
        print()

    if disabled_hits:
        print("DISABLED rules that would have matched:")
        for rule, covered in disabled_hits:
            print(f"  Rule #{rule['metadata']['ruleIndex']}: {rule['name']} ({rule.get('action')}) "
                  f"- ports {', '.join(covered)}")
        print()

    if unverifiable:
        print("Rules with objects that could not be verified (FQDN/unsupported):")
        for rule, items in unverifiable:
            print(f"  Rule #{rule['metadata']['ruleIndex']}: {rule['name']} - {', '.join(items)}")
        print()

    if not_covered and not port_missing:
        print(f"Ports with no matching rule: {', '.join(not_covered)} -> a new rule (or rule update) is needed.")

    return first_hit


# ---------- access control policy ----------

ACP_ALLOW = {"ALLOW", "TRUST"}
# Conditions on an ACP rule that IPs and ports alone can't evaluate.
ACP_EXTRA_CONDITIONS = ("applications", "urls", "users", "vlanTags", "sourceDynamicObjects",
                        "destinationDynamicObjects", "sourcePorts", "sourceSecurityGroupTags",
                        "destinationSecurityGroupTags")


def _has_values(field) -> bool:
    if isinstance(field, dict):
        return any(_has_values(v) for k, v in field.items() if k not in ("type", "id", "name"))
    if isinstance(field, list):
        return bool(field)
    return bool(field)


def acp_evaluate(rules, default_action, src, dst, req_ports):
    """First-match evaluation of an access control policy for each requested port.

    Returns {port label: {"verdict", "action", "rule", "src_hit", "dst_hit", "port_hit", "skipped"}}.
    MONITOR rules don't end evaluation. Rules with application / URL / user / other conditions that IPs and
    ports can't decide are listed in "skipped" and evaluation continues past them."""
    results = {}
    for req in req_ports:
        label, skipped, decided = req[3], [], None
        for rule in rules:
            if not rule.get("enabled"):
                continue
            src_el, _, _ = rule_networks(rule.get("sourceNetworks"))
            dst_el, _, _ = rule_networks(rule.get("destinationNetworks"))
            port_el, _ = rule_ports(rule.get("destinationPorts"))
            s, d, p = net_match(src, src_el), net_match(dst, dst_el), port_match(req, port_el)
            if not (s and d and p):
                continue
            extra = [c for c in ACP_EXTRA_CONDITIONS if _has_values(rule.get(c))]
            if extra or rule.get("action") == "MONITOR":
                skipped.append((rule, extra or ["MONITOR (logs only, evaluation continues)"]))
                continue
            decided = {"rule": rule, "src_hit": s, "dst_hit": d, "port_hit": p}
            break
        if decided:
            action = decided["rule"].get("action")
            verdict = "ALLOWED" if action in ACP_ALLOW else "DENIED"
            results[label] = {"verdict": verdict, "action": action, "skipped": skipped, **decided}
        else:
            results[label] = {"verdict": "ALLOWED" if default_action in ACP_ALLOW else "DENIED",
                              "action": f"DEFAULT {default_action}", "rule": None, "skipped": skipped}
    return results


def print_acp(results, policy_name, src, dst):
    print(f"Access control policy {policy_name}: {src} -> {dst}\n")
    for label, r in results.items():
        rule = r["rule"]
        where = (f"rule #{rule['metadata']['ruleIndex']} {rule['name']} "
                 f"[{rule['metadata'].get('section', '')}/{rule['metadata'].get('category', '')}]"
                 if rule else "no rule matched -> default action")
        print(f"  {label:12} {r['verdict']:8} {r['action']:16} {where}")
        if rule:
            zones = lambda f: ", ".join(o["name"] for o in (rule.get(f) or {}).get("objects", [])) or "any"
            print(f"               zones {zones('sourceZones')} -> {zones('destinationZones')}")
            print(f"               source matched by: {'; '.join(r['src_hit'])}")
            print(f"               destination matched by: {'; '.join(r['dst_hit'])}")
            print(f"               port matched by: {'; '.join(r['port_hit'])}")
        for srule, why in r["skipped"]:
            print(f"               passed over #{srule['metadata']['ruleIndex']} {srule['name']} "
                  f"({srule.get('action')}): also needs {', '.join(why)} - may match first in practice")
    print()
    print("NOTE: the prefilter policy is evaluated BEFORE this policy. Traffic a prefilter rule FASTPATHs or BLOCKs")
    print("      never reaches the access control policy - check it with prefilter-check (or use endpoint_helper.py path).")
    print()


# ---------- NAT ----------

NAT_FIELDS = {"manual": ("originalSource", "translatedSource", "originalDestination", "translatedDestination"),
              "auto": ("originalNetwork", "translatedNetwork")}


def nat_matches(rules, target, include_any=False):
    """NAT rules where the IP/network falls inside any original or translated object. Catch-all objects
    (0.0.0.0/0, e.g. any-ipv4) are ignored unless include_any, since they match every address."""
    hits = []
    for rule in rules:
        matched, fields = [], {}
        for f in NAT_FIELDS[rule["kind"]]:
            obj = rule.get(f)
            if not obj or not obj.get("id"):
                continue
            fields[f] = obj.get("name")
            elements, _ = resolve_network(obj, "")
            if not include_any:
                elements = [e for e in elements if not (e[1] == 0 and e[2] >= 2 ** 32 - 1)]
            if net_match(target, elements):
                matched.append(f)
        if matched:
            hits.append({"rule": rule, "matched": matched, "fields": fields})
    return hits


def print_nat(hits, policy_name, target):
    print(f"NAT policy {policy_name}: rules involving {target}\n")
    if not hits:
        print("  (no NAT rule references this address)")
    for h in hits:
        r = h["rule"]
        intf = lambda f: (r.get(f) or {}).get("name", "any")
        print(f"  {r['kind']:6} {r.get('natType', '')}  enabled={r.get('enabled')}  "
              f"{intf('sourceInterface')} -> {intf('destinationInterface')}"
              + (f"  section {r['metadata'].get('section')}" if (r.get("metadata") or {}).get("section") else ""))
        for f, name in h["fields"].items():
            print(f"    {'*' if f in h['matched'] else ' '} {f:22} {name}")
    print()


# ---------- pasted CSV / spreadsheet input ----------

IP_TOKEN = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2}|\s*-\s*\d{1,3}(?:\.\d{1,3}){3}|\s*-\s*\d{1,3}\b)?")


def parse_ip_cell(cell):
    """Pull every IP / CIDR / range out of free text. Labels like 'XenApp:' are ignored.
    Shorthand ranges like 10.194.23.197-200 are expanded to 10.194.23.197-10.194.23.200."""
    targets = []
    for tok in IP_TOKEN.findall(cell):
        tok = re.sub(r"\s+", "", tok)
        if "-" in tok:
            lo, hi = tok.split("-", 1)
            if "." not in hi:
                hi = lo.rsplit(".", 1)[0] + "." + hi
            tok = f"{lo}-{hi}"
        targets.append(Target(tok))
    return targets


def parse_port_cell(cell):
    """Turn lines like '80, 443, 1494 - TCP' / '16500-16509 - UDP' / 'ICMP' into a --ports string."""
    specs = []
    for line in re.split(r"[\n;]+", cell):
        low = line.lower()
        proto = next((p for p in ("tcp", "udp") if re.search(rf"\b{p}\b", low)), None)
        nums = re.findall(r"\d+\s*-\s*\d+|\d+", line)
        if not nums and "icmp" in low:
            specs.append("icmp")
        for n in nums:
            n = re.sub(r"\s+", "", n)
            specs.append(f"{proto}/{n}" if proto else n)
    return ",".join(specs)


PROTO_CELL = re.compile(r"\s*(TCP|UDP|ICMP|TCP\s*/\s*UDP)\s*", re.I)


def apply_proto(ports, proto):
    """Add a protocol column ('TCP', 'UDP', 'TCP/UDP') to each ports line that has none."""
    protos = re.findall(r"tcp|udp|icmp", proto, re.I)
    lines = []
    for line in ports.splitlines() or [""]:
        if not line.strip() or re.search(r"\b(tcp|udp|icmp)\b", line, re.I):
            lines.append(line)
        else:
            lines += [f"{line} - {p.upper()}" if p.lower() != "icmp" else "ICMP" for p in protos]
    return "\n".join(lines)


def read_rows(text):
    """Rows of [source, destination, ports] from pasted CSV/TSV (cells may span lines).
    An optional 4th protocol column (TCP / UDP / TCP/UDP) is folded into the ports cell."""
    rows = None
    for delim in ("\t", ","):
        found = [r for r in csv.reader(io.StringIO(text), delimiter=delim) if any(c.strip() for c in r)]
        if found and all(len(r) >= 2 for r in found):
            rows = found
            break
    if rows is None:
        # Delimiters lost in the paste: fall back to cells taken three at a time. A cell is
        # either quoted, or an unquoted run of text (single spaces allowed inside it).
        # A protocol cell is folded into the ports cell before it.
        cells = []
        for q, u in re.findall(r'"((?:[^"]|"")*)"|((?:[^"\s]| (?=[^\s"]))+)', text):
            cell = q.replace('""', '"') if q else u
            if cells and len(cells) % 3 == 0 and PROTO_CELL.fullmatch(cell):
                cells[-1] = apply_proto(cells[-1], cell)
            else:
                cells.append(cell)
        return [cells[i:i + 3] for i in range(0, len(cells), 3)]
    out = []
    for r in rows:
        if len(r) >= 4 and PROTO_CELL.fullmatch(r[3]):
            r = [r[0], r[1], apply_proto(r[2], r[3])]
        out.append(r)
    return out


def prefilter_check(args) -> int:
    # Build the list of (src, dst, ports-string) checks to run.
    jobs = []
    if args.input:
        text = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8-sig").read()
        for row in read_rows(text):
            if len(row) < 2:
                continue
            srcs, dsts = parse_ip_cell(row[0]), parse_ip_cell(row[1])
            ports = parse_port_cell(row[2]) if len(row) > 2 else ""
            if not srcs or not dsts:
                continue  # header row or row without IPs
            jobs += [(s, d, ports) for s in srcs for d in dsts]
        if not jobs:
            print("No source/destination IPs found in input")
            return 1
    elif args.src and args.dst:
        jobs = [(Target(args.src), Target(args.dst), args.ports or "")]
    else:
        raise CDOError("give --src and --dst, or --input")

    policy = client().prefilter_policy(args.policy)
    rules = client().prefilter_rules(policy["id"])
    print("Loading objects...")
    preload_objects()

    summary = []
    for src, dst, ports in jobs:
        out = io.StringIO() if args.summary else sys.stdout
        with contextlib.redirect_stdout(out):
            if len(jobs) > 1:
                print("\n" + "#" * 70 + f"\n# {src} -> {dst}\n" + "#" * 70)
            if not ports:
                matches = ip_only(rules, src, dst, args.policy)
                names = [f"#{r['metadata']['ruleIndex']} {r['name']}" for r, _, _ in matches
                         if r.get("enabled") and r.get("action") in ALLOW_ACTIONS]
                summary.append((src, dst, "(any)", "; ".join(names) or "NO MATCH - new rule needed"))
            else:
                for port, hit in check_ports(rules, src, dst, parse_requested_ports(ports), args.policy).items():
                    if hit is None:
                        result = "MISSING"
                    elif hit[0].get("action") in ALLOW_ACTIONS:
                        result = f"#{hit[0]['metadata']['ruleIndex']} {hit[0]['name']}"
                    else:
                        result = f"{hit[0].get('action')} by #{hit[0]['metadata']['ruleIndex']} {hit[0]['name']}"
                    summary.append((src, dst, port, result))

    if len(summary) > 1:
        print("\n" + "=" * 70 + "\nSUMMARY\n" + "=" * 70)
        widths = [max(len(str(r[i])) for r in summary + [("Source", "Destination", "Port", "")])
                  for i in range(3)]
        print(f"{'Source':<{widths[0]}}  {'Destination':<{widths[1]}}  {'Port':<{widths[2]}}  Result")
        for s, d, p, r in summary:
            print(f"{str(s):<{widths[0]}}  {str(d):<{widths[1]}}  {p:<{widths[2]}}  {r}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Cisco CDO / cdFMC helper (GET only).")
    parser.add_argument("--json", action="store_true", help="print JSON")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("devices", help="managed devices (FTDs)")
    sub.add_parser("ha", help="FTD HA pairs")
    p = sub.add_parser("interfaces", help="all interfaces of one device")
    p.add_argument("device", help="device name (exact, else unique substring) or id")
    p = sub.add_parser("routes", help="IPv4 static routes of one device")
    p.add_argument("device")
    p = sub.add_parser("objects", help="network objects whose name or value matches")
    p.add_argument("text")
    p = sub.add_parser("prefilter-rules", help="rules of a prefilter policy, in order")
    p.add_argument("--policy", default=POLICY_NAME, help=f"policy name (default {POLICY_NAME})")
    p = sub.add_parser("prefilter-check", help="does an enabled prefilter rule allow src -> dst on these ports?")
    p.add_argument("--src", help="source IP, network (10.194.0.0/24) or range (a-b)")
    p.add_argument("--dst", help="destination IP, network or range")
    p.add_argument("--ports", help="comma list: 443,tcp/22,udp/53,8000-8010,icmp "
                                   "(omit to list every rule matching source and destination)")
    p.add_argument("--input", help="CSV/TSV file of source,destination,ports rows ('-' for stdin)")
    p.add_argument("--summary", action="store_true", help="only print the summary table")
    p.add_argument("--policy", default=POLICY_NAME, help=f"policy name (default {POLICY_NAME})")
    p = sub.add_parser("policies", help="policies assigned to a device (access, NAT, prefilter, platform, VPN...)")
    p.add_argument("device")
    p = sub.add_parser("acp-check", help="access control policy verdict for src -> dst on ports (first match wins)")
    p.add_argument("--src", required=True, help="source IP, network or range")
    p.add_argument("--dst", required=True, help="destination IP, network or range")
    p.add_argument("--ports", required=True, help="comma list: 443,tcp/22,udp/53,8000-8010,icmp")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--device", help="use the access policy assigned to this device")
    g.add_argument("--policy", help="access policy name")
    p = sub.add_parser("nat-check", help="NAT rules whose original or translated objects contain an IP")
    p.add_argument("ip", help="IP, network or range")
    p.add_argument("--include-any", action="store_true", help="also show rules that match only via any/0.0.0.0/0")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--device", help="use the NAT policy assigned to this device")
    g.add_argument("--policy", help="NAT policy name")
    p = sub.add_parser("get", help="GET any path under the FMC domain, e.g. object/networkgroups")
    p.add_argument("path")
    p.add_argument("-p", "--param", action="append", default=[], metavar="KEY=VALUE")
    p.add_argument("--one-page", action="store_true", help="don't follow paging")
    for subparser in sub.choices.values():
        subparser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="print JSON")
    args = parser.parse_args()

    if args.cmd == "prefilter-check":
        return prefilter_check(args)
    cdo = client()
    if args.cmd == "policies":
        found = cdo.policies_for_device(args.device)
        print(to_json(found) if args.json else "\n".join(f"{k:28} {v}" for k, v in found.items()))
        return 0
    if args.cmd == "acp-check":
        name = args.policy or cdo.policies_for_device(args.device).get("AccessPolicy")
        if not name:
            raise CDOError(f"no access policy is assigned to {args.device}")
        pol = cdo.access_policy(name)
        rules = cdo.access_rules(pol["id"])
        print("Loading objects...", file=sys.stderr)
        preload_objects()
        res = acp_evaluate(rules, (pol.get("defaultAction") or {}).get("action"),
                           Target(args.src), Target(args.dst), parse_requested_ports(args.ports))
        if args.json:
            print(to_json({k: {**v, "rule": (v["rule"] or {}).get("name"),
                               "skipped": [s[0]["name"] for s in v["skipped"]]} for k, v in res.items()}))
        else:
            print_acp(res, name, args.src, args.dst)
        return 0 if all(v["verdict"] == "ALLOWED" for v in res.values()) else 1
    if args.cmd == "nat-check":
        name = args.policy or cdo.policies_for_device(args.device).get("FTDNatPolicy")
        if not name:
            raise CDOError(f"no NAT policy is assigned to {args.device}")
        rules = cdo.nat_rules(cdo.nat_policy(name)["id"])
        hits = nat_matches(rules, Target(args.ip), args.include_any)
        if args.json:
            print(to_json([{"kind": h["rule"]["kind"], "natType": h["rule"].get("natType"), "matched": h["matched"],
                            "fields": h["fields"], "enabled": h["rule"].get("enabled")} for h in hits]))
        else:
            print_nat(hits, name, args.ip)
        return 0
    if args.cmd == "devices":
        rows, cols = cdo.devices(), ["name", "model", "sw_version=sw_version", "hostName", "healthStatus", "deviceGroup.name", "id"]
    elif args.cmd == "ha":
        rows, cols = cdo.ha_pairs(), ["name", "primary=primary.name", "secondary=secondary.name", "id"]
    elif args.cmd == "interfaces":
        rows = cdo.interfaces(cdo.device(args.device)["id"])
        cols = ["name", "type", "ifname", "enabled", "ipv4.static.address", "ipv4.static.netmask", "securityZone.name", "description"]
    elif args.cmd == "routes":
        rows = cdo.static_routes(cdo.device(args.device)["id"])
        cols = ["interfaceName", "networks=selectedNetworks", "gateway=gateway.object.name", "gw_literal=gateway.literal.value", "metricValue", "isTunneled"]
        for r in rows:
            r["selectedNetworks"] = [n.get("name") for n in r.get("selectedNetworks") or []]
    elif args.cmd == "objects":
        rows, cols = cdo.network_objects(args.text), ["name", "type", "value", "description"]
    elif args.cmd == "prefilter-rules":
        rows = cdo.prefilter_rules(cdo.prefilter_policy(args.policy)["id"])
        for r in rows:
            r["src"] = [o.get("name") for o in (r.get("sourceNetworks") or {}).get("objects", [])] + \
                       [lit.get("value") for lit in (r.get("sourceNetworks") or {}).get("literals", [])]
            r["dst"] = [o.get("name") for o in (r.get("destinationNetworks") or {}).get("objects", [])] + \
                       [lit.get("value") for lit in (r.get("destinationNetworks") or {}).get("literals", [])]
            r["ports"] = [o.get("name") for o in (r.get("destinationPorts") or {}).get("objects", [])]
        cols = ["index=metadata.ruleIndex", "name", "action", "enabled", "ruleType", "src", "dst", "ports"]
    elif args.cmd == "get":
        params = dict(kv.split("=", 1) for kv in args.param)
        print(json.dumps(cdo.get(args.path, **params) if args.one_page else cdo.get_all(args.path, **params), indent=2))
        return 0
    print(to_json(rows) if args.json else table(rows, cols))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CDOError as exc:
        sys.exit(f"CDO error: {exc}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
