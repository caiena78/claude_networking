"""Read-only access to the Cisco Meraki Dashboard API.

The API key is the Vault secret `meraki_api` (see vault_helper.py). The client only issues
GET requests, so it can't change live Meraki config. Secrets in API answers (PSKs, RADIUS and
VPN shared secrets, SNMP communities, passwords) are masked in everything the CLI prints.

As a module:
    from meraki_helper import Meraki
    m = Meraki()
    nets = m.networks()
    devs = m.devices(productTypes=["appliance"])
    clients = m.clients(m.network_by_name("PUC_Kenner")["id"], timespan=86400)

From the command line (python meraki_helper.py <command> --help for options):
    sites, devices, aps, offline, device          inventory and status
    clients, client, top                          clients and usage
    ssids, ssid, rf-profiles, wifi-health, air-marshal, ap-ports      wireless
    uplinks, vpn, vlans, routes, firewall, security, sdwan, appliance MX / Z3
    ports, switch                                 MS switches
    neighbors, events, alerts, changes, availability, firmware, licenses, inventory, admins, settings
    get <path>                                    any GET path, e.g. organizations/{org}/networks
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import time
from typing import Any

import requests

BASE_URL = "https://api.meraki.com/api/v1"
DEFAULT_ORG_ID = "793109"  # LCMC Health, the only org the key can access
MAX_RETRIES = 5

# Keys whose values are masked in output (PSKs, RADIUS/VPN secrets, SNMP communities, passwords).
SECRET_KEY = re.compile(r"psk|secret|password|passphrase|community|presharedkey|apikey|authkey|privkey|^key$", re.I)
MASK = "*****"


class MerakiError(Exception):
    """A Meraki API call failed (status, path and Meraki's error text; never the API key)."""


def mask(obj: Any) -> Any:
    """Return a copy of obj with the values of secret-looking keys replaced by *****."""
    if isinstance(obj, dict):
        return {k: (MASK if SECRET_KEY.search(str(k)) and obj[k] not in (None, "", [], {}) and not isinstance(obj[k], bool)
                    else mask(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask(v) for v in obj]
    return obj


def normalize_mac(text: str) -> str | None:
    """aa:bb:cc:dd:ee:ff for a MAC in any common format, else None."""
    hexes = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(hexes) != 12 or not re.fullmatch(r"[0-9a-fA-F:.\-]+", text.strip()):
        return None
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).lower()


class Meraki:
    """Minimal read-only Meraki Dashboard API client with pagination and 429 retry."""

    def __init__(self, api_key: str | None = None, org_id: str = DEFAULT_ORG_ID, timeout: int = 60):
        if api_key is None:
            import vault_helper

            api_key = vault_helper.get_secret("meraki_api", interactive=False)
        self.org_id = org_id
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_key}", "Accept": "application/json"})
        self._networks: list[dict] | None = None
        self._devices: list[dict] | None = None

    # -- core ---------------------------------------------------------------

    def _url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        path = path.replace("{org}", self.org_id).replace("{orgId}", self.org_id)
        return f"{BASE_URL}/{path.lstrip('/')}"

    def _request(self, url: str, params: dict | None) -> requests.Response:
        for attempt in range(MAX_RETRIES):
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 429 or (resp.status_code in (502, 503, 504) and attempt < MAX_RETRIES - 1):
                time.sleep(float(resp.headers.get("Retry-After", 2 ** attempt)))
                continue
            if resp.status_code >= 400:
                try:
                    detail = "; ".join(resp.json().get("errors", [])) or resp.text[:200]
                except ValueError:
                    detail = resp.text[:200]
                raise MerakiError(f"{resp.status_code} on {url.replace(BASE_URL, '')}: {detail}")
            return resp
        raise MerakiError(f"rate limited or unavailable too many times on {url.replace(BASE_URL, '')}")

    def get(self, path: str, **params: Any) -> Any:
        """GET one page and return the decoded JSON."""
        return self._request(self._url(path), params or None).json()

    def try_get(self, path: str, **params: Any) -> Any:
        """GET, but return {"error": "..."} instead of raising (for optional sections of a report)."""
        try:
            return self.get(path, **params)
        except MerakiError as exc:
            return {"error": str(exc)}

    def get_all(self, path: str, **params: Any) -> list:
        """GET every page of a list endpoint by following the Link: rel=next header."""
        url: str | None = self._url(path)
        query: dict | None = {"perPage": 1000, **params}
        try:
            resp = self._request(url, query)
        except MerakiError as exc:
            # perPage limits differ per endpoint; retry with the maximum the error message reports.
            limit = re.search(r"perPage parameter must be between \d+ and (\d+)", str(exc))
            if not limit or "perPage" in params:
                raise
            query["perPage"] = int(limit.group(1))
            resp = self._request(url, query)

        items: list = []
        seen: set[str] = set()
        while True:
            data = resp.json()
            if not isinstance(data, list):
                return data
            items.extend(data)
            url = resp.links.get("next", {}).get("url")
            if not url or not data or url in seen:  # some endpoints keep sending a next link after the last page
                return items
            seen.add(url)
            resp = self._request(url, None)  # the next URL already carries the query string

    # -- organization and inventory ----------------------------------------

    def organizations(self) -> list[dict]:
        return self.get_all("/organizations")

    def networks(self, **params: Any) -> list[dict]:
        if params:
            return self.get_all(f"/organizations/{self.org_id}/networks", **params)
        if self._networks is None:
            self._networks = self.get_all(f"/organizations/{self.org_id}/networks")
        return self._networks

    def network_names(self) -> dict[str, str]:
        return {n["id"]: n["name"] for n in self.networks()}

    def network_by_name(self, name: str) -> dict:
        """Find a network by exact name, else by case-insensitive substring (must be unique)."""
        nets = self.networks()
        exact = [n for n in nets if n["name"] == name or n["id"] == name]
        if exact:
            return exact[0]
        partial = [n for n in nets if name.lower() in n["name"].lower()]
        if len(partial) == 1:
            return partial[0]
        if not partial:
            raise MerakiError(f"no network matches {name!r}")
        raise MerakiError(f"{name!r} matches {len(partial)} networks: {', '.join(n['name'] for n in partial)}")

    def networks_matching(self, text: str | None = None, product: str | None = None) -> list[dict]:
        """Networks whose name equals, else contains, text (all if None), optionally only those with a product type."""
        nets = self.networks()
        if product:
            nets = [n for n in nets if product in n.get("productTypes", [])]
        if text:
            exact = [n for n in nets if n["name"].lower() == text.lower() or n["id"] == text]
            nets = exact or [n for n in nets if text.lower() in n["name"].lower()]
            if not nets:
                raise MerakiError(f"no {product + ' ' if product else ''}network matches {text!r}")
        return sorted(nets, key=lambda n: n["name"].lower())

    def devices(self, **params: Any) -> list[dict]:
        """Org inventory of devices in networks. Filters: networkIds, productTypes, serial, model, tags..."""
        if params:
            return self.get_all(f"/organizations/{self.org_id}/devices", **params)
        if self._devices is None:
            self._devices = self.get_all(f"/organizations/{self.org_id}/devices")
        return self._devices

    def device_by_name(self, text: str) -> dict:
        """Find a device by serial, MAC, exact name (any case), else a unique name substring."""
        devs = self.devices()
        mac = normalize_mac(text)
        for d in devs:
            if d.get("serial", "").upper() == text.upper() or (mac and (d.get("mac") or "").lower() == mac):
                return d
        exact = [d for d in devs if (d.get("name") or "").lower() == text.lower()]
        if exact:
            return exact[0]
        partial = [d for d in devs if text.lower() in (d.get("name") or "").lower()]
        if len(partial) == 1:
            return partial[0]
        if not partial:
            raise MerakiError(f"no device matches {text!r}")
        raise MerakiError(f"{text!r} matches {len(partial)} devices: {', '.join(d.get('name') or d['serial'] for d in partial)}")

    def device_statuses(self, **params: Any) -> list[dict]:
        """status is one of online, alerting, offline, dormant."""
        return self.get_all(f"/organizations/{self.org_id}/devices/statuses", **params)

    def inventory(self, **params: Any) -> list[dict]:
        """Every claimed device, including ones not in a network (usedState=unused)."""
        return self.get_all(f"/organizations/{self.org_id}/inventory/devices", **params)

    def subscriptions(self) -> list[dict]:
        """Subscription licenses (this org uses subscription licensing, so licenses/overview returns 400)."""
        return self.get_all("administered/licensing/subscription/subscriptions", **{"organizationIds[]": self.org_id})

    def firmware_upgrades(self, **params: Any) -> list[dict]:
        return self.get_all(f"/organizations/{self.org_id}/firmware/upgrades", **params)

    def availability_changes(self, timespan: int = 86400, **params: Any) -> list[dict]:
        return self.get_all(f"/organizations/{self.org_id}/devices/availabilities/changeHistory",
                            timespan=timespan, **params)

    def admins(self) -> list[dict]:
        return self.get_all(f"/organizations/{self.org_id}/admins")

    def config_changes(self, timespan: int = 86400, **params: Any) -> list[dict]:
        # One page of up to 5000 (newest first). Its next link points at newer changes, not older ones.
        return self.get(f"/organizations/{self.org_id}/configurationChanges", timespan=timespan, perPage=5000, **params)

    def assurance_alerts(self, **params: Any) -> list[dict]:
        return self.get_all(f"/organizations/{self.org_id}/assurance/alerts", **params)

    def top(self, kind: str, timespan: int = 86400, **params: Any) -> list[dict]:
        """kind is a path under summary/top, e.g. clients/byUsage, applications/byUsage."""
        return self.get(f"/organizations/{self.org_id}/summary/top/{kind}", timespan=timespan, **params)

    # -- clients -------------------------------------------------------------

    def clients(self, network_id: str, timespan: int = 86400, **params: Any) -> list[dict]:
        return self.get_all(f"/networks/{network_id}/clients", timespan=timespan, **params)

    def client_search(self, mac: str) -> dict:
        """Where a MAC has been seen across the org: {mac, clientId, manufacturer, records: [per network]}."""
        return self.get(f"/organizations/{self.org_id}/clients/search", mac=mac)

    # -- appliance, WAN and VPN ------------------------------------------------

    def uplink_statuses(self, **params: Any) -> list[dict]:
        return self.get_all(f"/organizations/{self.org_id}/uplinks/statuses", **params)

    def uplink_loss_latency(self, **params: Any) -> list[dict]:
        """WAN loss and latency for the last 5 minutes (per device and uplink)."""
        return self.get(f"/organizations/{self.org_id}/devices/uplinksLossAndLatency", **params)

    def vpn_statuses(self, **params: Any) -> list[dict]:
        return self.get_all(f"/organizations/{self.org_id}/appliance/vpn/statuses", **params)

    def third_party_vpn_peers(self) -> list[dict]:
        return self.get(f"/organizations/{self.org_id}/appliance/vpn/thirdPartyVPNPeers").get("peers", [])

    def vlans(self, network_id: str) -> list[dict]:
        return self.get_all(f"/networks/{network_id}/appliance/vlans")

    def static_routes(self, network_id: str) -> list[dict]:
        return self.get(f"/networks/{network_id}/appliance/staticRoutes")

    def security_events(self, timespan: int = 86400, network_id: str | None = None, **params: Any) -> list[dict]:
        path = (f"/networks/{network_id}/appliance/security/events" if network_id
                else f"/organizations/{self.org_id}/appliance/security/events")
        return self.get_all(path, timespan=timespan, **params)

    # -- wireless -------------------------------------------------------------

    def ssids(self, network_id: str) -> list[dict]:
        """The 15 SSID slots of one wireless network (enabled or not)."""
        return self.get(f"networks/{network_id}/wireless/ssids")

    def ssid_usage(self) -> list[dict]:
        """Every enabled SSID in every wireless network, with how many APs broadcast it.

        An enabled SSID is on every AP in its network, unless availableOnAllAps is false; then only
        APs whose tags match one of its availabilityTags broadcast it."""
        status = {d["serial"]: d.get("status") for d in self.device_statuses(**{"productTypes[]": "wireless"})}
        aps_by_net: dict[str, list[dict]] = collections.defaultdict(list)
        for d in self.devices(**{"productTypes[]": "wireless"}):
            aps_by_net[d.get("networkId")].append(d)
        rows = []
        for net in self.networks():
            if "wireless" not in net.get("productTypes", []):
                continue
            aps = aps_by_net.get(net["id"], [])
            for s in self.ssids(net["id"]):
                if not s.get("enabled"):
                    continue
                if s.get("availableOnAllAps", True):
                    using = aps
                else:
                    wanted = set(s.get("availabilityTags") or [])
                    using = [a for a in aps if wanted & set(a.get("tags") or [])]
                rows.append({
                    "network": net["name"], "networkId": net["id"], "number": s.get("number"), "ssid": s.get("name"),
                    "authMode": s.get("authMode"), "encryptionMode": s.get("encryptionMode") or s.get("wpaEncryptionMode"),
                    "visible": s.get("visible", True), "availableOnAllAps": s.get("availableOnAllAps", True),
                    "aps": len(using), "aps_online": sum(1 for a in using if status.get(a["serial"]) == "online"),
                })
        return sorted(rows, key=lambda r: (r["ssid"].lower(), r["network"].lower()))

    # -- switches and neighbors -------------------------------------------------

    def switch_ports(self, serial: str) -> list[dict]:
        return self.get(f"/devices/{serial}/switch/ports")

    def switch_port_statuses(self, serial: str, timespan: int = 3600) -> list[dict]:
        return self.get(f"/devices/{serial}/switch/ports/statuses", timespan=timespan)

    def lldp_cdp(self, serial: str) -> dict:
        return self.get(f"/devices/{serial}/lldpCdp")

    def events(self, network_id: str, product_type: str | None = None, per_page: int = 100, **params: Any) -> list[dict]:
        """The newest events of a network (one page; per_page max 1000)."""
        if product_type:
            params["productType"] = product_type
        return self.get(f"/networks/{network_id}/events", perPage=per_page, **params).get("events", [])

    # -- summaries ----------------------------------------------------------------

    def sites(self) -> list[dict]:
        """Every network with device counts by product type and how many devices are online."""
        status = {d["serial"]: d.get("status") for d in self.device_statuses()}
        by_type: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        online: collections.Counter = collections.Counter()
        for d in self.devices():
            by_type[d.get("networkId")][d.get("productType") or "other"] += 1
            if status.get(d["serial"]) == "online":
                online[d.get("networkId")] += 1
        return [
            {
                "name": n["name"],
                "id": n["id"],
                "tags": n.get("tags", []),
                "timeZone": n.get("timeZone", ""),
                "devices": sum(by_type[n["id"]].values()),
                "online": online[n["id"]],
                "by_type": dict(by_type[n["id"]]),
            }
            for n in sorted(self.networks(), key=lambda n: n["name"].lower())
        ]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _dig(item: Any, path: str) -> Any:
    """item["a"]["b"] for path "a.b"; None when any step is missing."""
    for part in path.split("."):
        if not isinstance(item, dict):
            return None
        item = item.get(part)
    return item


def _iso(value: Any) -> Any:
    """ISO 8601 UTC for epoch seconds; anything else unchanged."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))
    return value


def _natural(text: str) -> list:
    """Sort key that orders port 2 before port 10."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", str(text))]


def _cell(value: Any, width: int) -> str:
    if value is None:
        text = ""
    elif isinstance(value, list):
        text = " ".join(json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v) for v in value)
    elif isinstance(value, dict):
        text = " ".join(f"{k}:{v}" for k, v in sorted(value.items()))
    elif isinstance(value, float):
        text = f"{value:.2f}".rstrip("0").rstrip(".")
    else:
        text = str(value)
    text = text.replace("\n", " ")
    return text if len(text) <= width else text[:width - 3] + "..."


def table(data: list[dict], columns: list[str], width: int = 60) -> str:
    """A text table. A column is a dotted path into each row, optionally named "label=path"."""
    if not data:
        return "(none)"
    specs = [c.split("=", 1) if "=" in c else [c, c] for c in columns]
    rows = [[_cell(_dig(mask(item), path), width) for _, path in specs] for item in data]
    labels = [label for label, _ in specs]
    widths = [max(len(x) for x in col) for col in zip(labels, *rows)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*labels).rstrip(), fmt.format(*("-" * w for w in widths))]
    lines += [fmt.format(*row).rstrip() for row in rows]
    return "\n".join(lines)


def to_json(data: Any) -> str:
    return json.dumps(mask(data), indent=2, default=str)


class Out:
    """Collects what a command prints so -o FILE can also save it."""

    def __init__(self) -> None:
        self.chunks: list[str] = []

    def add(self, text: str) -> None:
        print(text)
        self.chunks.append(text)

    def section(self, title: str, body: str) -> None:
        self.add(f"===== {title}\n{body}\n")

    def save(self, path: str | None, append: bool) -> None:
        if not path:
            return
        with open(path, "a" if append else "w", encoding="utf-8") as fh:
            fh.write("\n".join(self.chunks) + "\n")
        print(f"{'Appended to' if append else 'Wrote'} {path}", file=sys.stderr)


def _emit(out: Out, args: argparse.Namespace, data: Any, columns: list[str] | None = None, width: int = 60) -> None:
    if args.json or not columns or not isinstance(data, list):
        out.add(to_json(data))
    else:
        out.add(table(data, columns, width))


def _timespan(args: argparse.Namespace, default_hours: float) -> int:
    return int((getattr(args, "hours", None) or default_hours) * 3600)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

DEVICE_COLUMNS = ["network", "name", "model", "serial", "status", "lanIp", "publicIp", "lastReportedAt"]


def cmd_devices(m: Meraki, args, out: Out) -> None:
    params: dict[str, Any] = {}
    names = m.network_names()
    if args.network:
        params["networkIds[]"] = m.network_by_name(args.network)["id"]
    product = "wireless" if args.cmd == "aps" else getattr(args, "product_type", None)
    if product:
        params["productTypes[]"] = product
    rows = m.device_statuses(**params)
    if args.cmd == "offline":
        rows = [d for d in rows if d.get("status") != "online"]
    if args.cmd == "aps":
        tags = {d["serial"]: d.get("tags", []) for d in m.devices()}
        for d in rows:
            d["tags"] = tags.get(d["serial"], [])
    for d in rows:
        d["network"] = names.get(d.get("networkId"), d.get("networkId"))
    rows.sort(key=lambda d: (d["network"] or "", d.get("name") or ""))
    _emit(out, args, rows, DEVICE_COLUMNS + (["tags"] if args.cmd == "aps" else []))


def cmd_device(m: Meraki, args, out: Out) -> None:
    d = m.device_by_name(args.device)
    serial = d["serial"]
    detail = {**d, **m.get(f"/devices/{serial}")}
    status = m.device_statuses(**{"serials[]": serial})
    detail["network"] = m.network_names().get(detail.get("networkId"))
    detail["status"] = status[0] if status else None
    detail["managementInterface"] = m.try_get(f"/devices/{serial}/managementInterface")
    if args.json:
        out.add(to_json(detail))
        return
    st = detail["status"] or {}
    fields = [("name", detail.get("name")), ("serial", serial), ("model", detail.get("model")),
              ("productType", detail.get("productType")), ("network", detail.get("network")),
              ("status", st.get("status")), ("lanIp", st.get("lanIp") or detail.get("lanIp")),
              ("publicIp", st.get("publicIp")), ("gateway", st.get("gateway")), ("mac", detail.get("mac")),
              ("firmware", detail.get("firmware")), ("tags", " ".join(detail.get("tags") or [])),
              ("address", detail.get("address")), ("notes", detail.get("notes")),
              ("lastReportedAt", st.get("lastReportedAt"))]
    mgmt = detail["managementInterface"]
    if isinstance(mgmt, dict) and "error" not in mgmt:
        for wan in ("wan1", "wan2"):
            if mgmt.get(wan):
                w = mgmt[wan]
                fields.append((f"mgmt {wan}", f"{w.get('usingStaticIp') and 'static' or 'dhcp'} "
                                             f"{w.get('staticIp') or ''}" + (f" vlan {w['vlan']}" if w.get("vlan") else "")))
    out.add("\n".join(f"{k:<15} {' / '.join(l.strip() for l in str(v).splitlines() if l.strip()) if v is not None else ''}"
                      for k, v in fields))


CLIENT_COLUMNS = ["network", "description", "mac", "ip", "vlan", "ssid", "device=recentDeviceName", "switchport",
                  "status", "user", "os", "manufacturer", "lastSeen"]


def _client_rows(m: Meraki, net: dict, timespan: int) -> list[dict]:
    rows = m.clients(net["id"], timespan=timespan)
    for c in rows:
        c["network"] = net["name"]
        u = c.get("usage") or {}
        c["usageMB"] = round(((u.get("sent") or 0) + (u.get("recv") or 0)) / 1024, 1)  # usage is in KB
    return rows


def cmd_clients(m: Meraki, args, out: Out) -> None:
    net = m.network_by_name(args.network)
    rows = _client_rows(m, net, _timespan(args, 24))
    if args.ssid:
        rows = [c for c in rows if args.ssid.lower() in (c.get("ssid") or "").lower()]
    if args.vlan:
        rows = [c for c in rows if str(c.get("vlan")) == str(args.vlan)]
    if args.search:
        s = args.search.lower()
        rows = [c for c in rows if any(s in str(c.get(k) or "").lower() for k in ("description", "mac", "ip", "user", "manufacturer", "os"))]
    rows.sort(key=lambda c: (-c["usageMB"]) if args.sort == "usage" else (c.get("description") or c.get("mac") or "").lower())
    _emit(out, args, rows, CLIENT_COLUMNS[1:] + ["usageMB"])


def cmd_client(m: Meraki, args, out: Out) -> None:
    mac = normalize_mac(args.client)
    by_mac = {(d.get("mac") or "").lower(): d.get("name") or d["serial"] for d in m.devices()}
    rows: list[dict] = []
    if mac:
        found = m.client_search(mac)
        for r in found.get("records", []):
            r.update(mac=found.get("mac"), clientId=found.get("clientId"), manufacturer=found.get("manufacturer"),
                     network=(r.get("network") or {}).get("name"), networkId=(r.get("network") or {}).get("id"),
                     recentDeviceName=by_mac.get((r.get("recentDeviceMac") or "").lower(), r.get("recentDeviceMac")))
            for k in ("firstSeen", "lastSeen"):  # the search returns epoch seconds; the client list returns ISO
                r[k] = _iso(r.get(k))
            rows.append(r)
    else:
        # IP or name: scan network client lists (the org search only takes a MAC).
        text = args.client.lower()
        nets = m.networks_matching(args.network)
        if not args.network:
            print(f"Searching clients of {len(nets)} networks (use --network to narrow)...", file=sys.stderr)
        for net in nets:
            try:
                clients = _client_rows(m, net, _timespan(args, 24))
            except MerakiError:
                continue
            for c in clients:
                if (c.get("ip") or "") == args.client or text in (c.get("description") or "").lower() \
                        or text == (c.get("user") or "").lower():
                    c["networkId"] = net["id"]
                    rows.append(c)
    if args.detail:
        for r in rows:
            if r.get("ssid") and r.get("networkId"):
                r["connectionStats"] = m.try_get(f"/networks/{r['networkId']}/wireless/clients/{r['id'] if 'id' in r else r.get('clientId')}/connectionStats",
                                                 timespan=_timespan(args, 24))
    if not rows:
        out.add("null" if args.json else f"No Meraki client matches {args.client!r}.")
        return
    _emit(out, args, rows, CLIENT_COLUMNS + ["firstSeen"])
    if args.detail and not args.json:
        for r in rows:
            if "connectionStats" in r:
                out.add(f"{r['network']} wireless connection stats: {to_json(r['connectionStats'].get('connectionStats', r['connectionStats']))}")


TOP_KINDS = {
    "clients": ("clients/byUsage", ["name", "mac", "network=network.name", "totalMB=usage.total", "pct=usage.percentage"]),
    "apps": ("applications/byUsage", ["application", "totalMB=total", "downMB=downstream", "upMB=upstream", "pct=percentage"]),
    "ssids": ("ssids/byUsage", ["name", "clients=clients.counts.total", "totalMB=usage.total", "pct=usage.percentage"]),
    "devices": ("devices/byUsage", ["name", "model", "serial", "network=network.name", "clients=clients.counts.total",
                                    "totalMB=usage.total", "pct=usage.percentage"]),
    "models": ("devices/models/byUsage", ["model", "count", "totalMB=usage.total", "avgMB=usage.average"]),
    "networks": ("networks/byStatus", ["name", "status=statuses.overall", "online", "clients=clients.counts.total", "tags"]),
}


def cmd_top(m: Meraki, args, out: Out) -> None:
    path, columns = TOP_KINDS[args.kind]
    params = {"quantity": args.limit} if args.kind not in ("networks",) else {}
    if args.kind == "networks":
        rows = m.get_all(f"/organizations/{m.org_id}/summary/top/{path}", timespan=_timespan(args, 24))
        for r in rows:  # "wireless 2/2 switch 1/1": online / total per product type
            r["online"] = " ".join(f"{b['productType']} {b['counts'].get('online', 0)}/{sum(b['counts'].values())}"
                                   for b in (r.get("statuses") or {}).get("byProductType") or [] if sum(b["counts"].values()))
        rows.sort(key=lambda r: (r.get("statuses") or {}).get("overall") == "online")
    else:
        rows = m.top(path, timespan=_timespan(args, 24), **params)
    _emit(out, args, rows, columns)


def cmd_ssid(m: Meraki, args, out: Out) -> None:
    want = args.ssid.lower()
    found = []
    for net in m.networks_matching(args.network, "wireless"):
        for s in m.ssids(net["id"]):
            if want in (s.get("name") or "").lower() and (s.get("enabled") or args.disabled):
                s["network"] = net["name"]
                s["networkId"] = net["id"]
                found.append(s)
    exact = [s for s in found if s["name"].lower() == want]
    found = exact or found
    if args.json or args.full:
        for s in found:
            base = f"networks/{s['networkId']}/wireless/ssids/{s['number']}"
            s["l3FirewallRules"] = m.try_get(f"{base}/firewall/l3FirewallRules").get("rules")
            s["l7FirewallRules"] = m.try_get(f"{base}/firewall/l7FirewallRules").get("rules")
            s["trafficShaping"] = m.try_get(f"{base}/trafficShaping/rules")
            s["splashSettings"] = m.try_get(f"{base}/splash/settings")
    if args.json:
        out.add(to_json(found))
        return
    for s in found:
        s["radius"] = [f"{r.get('host')}:{r.get('port')}" for r in s.get("radiusServers") or []]
        s["vlan"] = s.get("defaultVlanId") or s.get("vlanId") or ""
        s["scope"] = "all APs" if s.get("availableOnAllAps", True) else "tags: " + " ".join(s.get("availabilityTags") or [])
    out.add(table(found, ["network", "number", "name", "enabled", "authMode", "encryption=wpaEncryptionMode",
                          "ipAssignmentMode", "vlan", "radius", "band=bandSelection", "visible", "scope"]))
    if args.full:
        for s in found:
            out.section(f"{s['network']} / SSID {s['number']} {s['name']}", to_json(s))


def cmd_rf_profiles(m: Meraki, args, out: Out) -> None:
    rows = []
    for net in m.networks_matching(args.network, "wireless"):
        for p in m.try_get(f"networks/{net['id']}/wireless/rfProfiles") or []:
            if isinstance(p, dict):
                p["network"] = net["name"]
                rows.append(p)
    _emit(out, args, rows, ["network", "name", "bandSelectionType", "clientBalancingEnabled", "minBitrateType",
                            "24min=twoFourGhzSettings.minPower", "24max=twoFourGhzSettings.maxPower",
                            "24ch=twoFourGhzSettings.validAutoChannels", "5width=fiveGhzSettings.channelWidth",
                            "5min=fiveGhzSettings.minPower", "5max=fiveGhzSettings.maxPower"])


def cmd_wifi_health(m: Meraki, args, out: Out) -> None:
    net = m.network_by_name(args.network)
    ts = min(_timespan(args, 24), 7 * 86400)
    names = {d["serial"]: d.get("name") or d["serial"] for d in m.devices()}
    overall = m.try_get(f"networks/{net['id']}/wireless/connectionStats", timespan=ts)
    per_ap = m.try_get(f"networks/{net['id']}/wireless/devices/connectionStats", timespan=ts)
    failures = m.try_get(f"networks/{net['id']}/wireless/failedConnections", timespan=ts)
    util = m.try_get(f"organizations/{m.org_id}/wireless/devices/channelUtilization/byDevice",
                     **{"networkIds[]": net["id"], "timespan": max(ts, 7200)})
    if args.json:
        out.add(to_json({"connectionStats": overall, "byAp": per_ap, "failedConnections": failures, "channelUtilization": util}))
        return
    out.section(f"{net['name']} connection steps that failed ({ts // 3600} h)", to_json(overall))
    util_by = {}
    for u in util if isinstance(util, list) else []:
        util_by[u.get("serial")] = {b.get("band"): (b.get("total") or {}).get("percentage") for b in u.get("byBand") or []}
    rows = []
    for a in per_ap if isinstance(per_ap, list) else []:
        cs = a.get("connectionStats") or {}
        rows.append({"ap": names.get(a.get("serial"), a.get("serial")), **cs,
                     "util24": util_by.get(a.get("serial"), {}).get("2.4"),
                     "util5": util_by.get(a.get("serial"), {}).get("5")})
    rows.sort(key=lambda r: r["ap"].lower())
    out.section("Per AP (failures by step, success count, channel utilization)",
                table(rows, ["ap", "assoc", "auth", "dhcp", "dns", "success", "util2.4GHz%=util24", "util5GHz%=util5"]))
    if isinstance(failures, list):
        steps = collections.Counter((f.get("failureStep"), f.get("type")) for f in failures)
        by_ap = collections.Counter(names.get(f.get("serial"), f.get("serial")) for f in failures)
        out.section(f"Failed connections: {len(failures)}",
                    table([{"step": s, "type": t, "count": n} for (s, t), n in steps.most_common()], ["step", "type", "count"])
                    + "\n\n" + table([{"ap": a, "failures": n} for a, n in by_ap.most_common(10)], ["ap", "failures"]))
    else:
        out.section("Failed connections", to_json(failures))


def cmd_air_marshal(m: Meraki, args, out: Out) -> None:
    net = m.network_by_name(args.network)
    rows = m.get(f"networks/{net['id']}/wireless/airMarshal", timespan=_timespan(args, 24))
    for r in rows:
        bssids = r.get("bssids") or []
        r["bssidCount"] = len(bssids)
        r["contained"] = any(b.get("contained") for b in bssids)
        r["seenBy"] = len({d.get("device") for b in bssids for d in b.get("detectedBy") or []})
        r["onWired"] = bool(r.get("wiredMacs"))
        r["firstSeen"], r["lastSeen"] = _iso(r.get("firstSeen")), _iso(r.get("lastSeen"))
    if args.wired:
        rows = [r for r in rows if r["onWired"]]
    rows.sort(key=lambda r: (r["onWired"], r.get("lastSeen") or ""), reverse=True)  # wired first, then newest
    _emit(out, args, rows, ["ssid", "bssidCount", "channels", "seenBy", "onWired", "wiredVlans", "contained", "firstSeen", "lastSeen"])


def cmd_ap_ports(m: Meraki, args, out: Out) -> None:
    params = {}
    if args.network:
        params["networkIds[]"] = m.network_by_name(args.network)["id"]
    names = m.network_names()
    rows = m.get_all(f"organizations/{m.org_id}/wireless/devices/ethernet/statuses", **params)
    for r in rows:
        r["networkName"] = names.get((r.get("network") or {}).get("id"))
        port = (r.get("ports") or [{}])[0]
        r["poe"] = (port.get("poe") or {}).get("standard")
        r["speed"] = (port.get("linkNegotiation") or {}).get("speed")
        r["duplex"] = (port.get("linkNegotiation") or {}).get("duplex")
    rows.sort(key=lambda r: ((r["networkName"] or ""), r.get("name") or ""))
    _emit(out, args, rows, ["network=networkName", "name", "serial", "power=power.mode", "poe", "speed", "duplex"])


def cmd_uplinks(m: Meraki, args, out: Out) -> None:
    params = {}
    if args.network:
        params["networkIds[]"] = m.network_by_name(args.network)["id"]
    names = m.network_names()
    loss = {}
    if args.loss:
        for r in m.uplink_loss_latency():
            series = [p for p in r.get("timeSeries") or [] if p.get("lossPercent") is not None]
            if series:
                loss[(r["serial"], r["uplink"])] = (
                    round(sum(p["lossPercent"] for p in series) / len(series), 1),
                    round(sum(p.get("latencyMs") or 0 for p in series) / len(series), 1))
    rows = []
    for d in m.uplink_statuses(**params):
        for u in d.get("uplinks") or []:
            row = {"network": names.get(d.get("networkId"), d.get("networkId")), "serial": d.get("serial"),
                   "model": d.get("model"), "ha": (d.get("highAvailability") or {}).get("role"), **u}
            if args.loss:
                row["loss%"], row["latencyMs"] = loss.get((d.get("serial"), u.get("interface")), ("", ""))
            rows.append(row)
    if args.down:
        rows = [r for r in rows if r.get("status") not in ("active", "ready")]
    rows.sort(key=lambda r: (r["network"] or "", r.get("interface") or ""))
    _emit(out, args, rows, ["network", "model", "serial", "ha", "interface", "status", "ip", "gateway", "publicIp",
                            "primaryDns", "provider", "signalType"] + (["loss%", "latencyMs"] if args.loss else []))


def cmd_vpn(m: Meraki, args, out: Out) -> None:
    if args.third_party:
        _emit(out, args, m.third_party_vpn_peers(),
              ["name", "publicIp", "remoteId", "privateSubnets", "ikeVersion", "networkTags", "secret"])
        return
    if args.config:
        rows = []
        for net in m.networks_matching(args.network, "appliance"):
            cfg = m.try_get(f"networks/{net['id']}/appliance/vpn/siteToSiteVpn")
            rows.append({"network": net["name"], **cfg})
        if args.json:
            out.add(to_json(rows))
            return
        for r in rows:
            r["hubs"] = [m.network_names().get(h.get("hubId"), h.get("hubId")) for h in r.get("hubs") or []]
            r["subnets_in_vpn"] = [s["localSubnet"] for s in r.get("subnets") or [] if s.get("useVpn")]
        out.add(table(rows, ["network", "mode", "hubs", "subnets_in_vpn", "error"], width=120))
        return
    params = {}
    if args.network:
        params["networkIds[]"] = m.network_by_name(args.network)["id"]
    rows = []
    for v in m.vpn_statuses(**params):
        peers = v.get("merakiVpnPeers") or []
        third = v.get("thirdPartyVpnPeers") or []
        down = [p.get("networkName") for p in peers if p.get("reachability") != "reachable"] + \
               [p.get("name") for p in third if p.get("reachability") != "reachable"]
        rows.append({**v, "network": v.get("networkName"), "peers": len(peers) + len(third),
                     "unreachable": down, "subnets": [s.get("subnet") for s in v.get("exportedSubnets") or []]})
    if args.down:
        rows = [r for r in rows if r["unreachable"] or r.get("deviceStatus") != "online"]
    rows.sort(key=lambda r: r["network"] or "")
    _emit(out, args, rows, ["network", "mode=vpnMode", "status=deviceStatus", "peers", "unreachable", "subnets"], width=80)


def cmd_vlans(m: Meraki, args, out: Out) -> None:
    rows = []
    for net in m.networks_matching(args.network, "appliance"):
        try:
            vlans = m.vlans(net["id"])
        except MerakiError as exc:
            if "VLANs are not enabled" not in str(exc):
                rows.append({"network": net["name"], "name": f"error: {exc}"})
                continue
            single = m.get(f"networks/{net['id']}/appliance/singleLan")
            vlans = [{"id": "(single LAN)", "name": "", **single}]
        for v in vlans:
            rows.append({"network": net["name"], **v})
    _emit(out, args, rows, ["network", "id", "name", "subnet", "applianceIp", "dhcpHandling", "dhcpRelayServerIps", "groupPolicyId"])


def cmd_routes(m: Meraki, args, out: Out) -> None:
    rows = []
    for net in m.networks_matching(args.network, "appliance"):
        for r in m.try_get(f"networks/{net['id']}/appliance/staticRoutes") or []:
            if isinstance(r, dict):
                rows.append({"network": net["name"], **r})
    _emit(out, args, rows, ["network", "name", "subnet", "gatewayIp", "enabled", "gatewayVlanId"])


FIREWALL_KINDS = {
    "l3": ("l3FirewallRules", ["policy", "protocol", "srcCidr", "srcPort", "destCidr", "destPort", "syslogEnabled", "comment"]),
    "l7": ("l7FirewallRules", ["policy", "type", "value"]),
    "inbound": ("inboundFirewallRules", ["policy", "protocol", "srcCidr", "srcPort", "destCidr", "destPort", "comment"]),
    "portfwd": ("portForwardingRules", ["name", "uplink", "protocol", "publicPort", "lanIp", "localPort", "allowedIps"]),
    "nat": ("oneToOneNatRules", ["name", "uplink", "publicIp", "lanIp", "allowedInbound"]),
    "nat-many": ("oneToManyNatRules", ["uplink", "publicIp", "portRules"]),
}


def cmd_firewall(m: Meraki, args, out: Out) -> None:
    net = m.network_by_name(args.network)
    kinds = [args.kind] if args.kind else list(FIREWALL_KINDS)
    result = {}
    for kind in kinds:
        path, columns = FIREWALL_KINDS[kind]
        data = m.try_get(f"networks/{net['id']}/appliance/firewall/{path}")
        result[kind] = data.get("rules", data) if isinstance(data, dict) else data
        if not args.json:
            body = table(result[kind], columns, width=80) if isinstance(result[kind], list) else to_json(result[kind])
            out.section(f"{net['name']} {kind} ({path})", body)
    if args.json:
        out.add(to_json(result))


def cmd_security(m: Meraki, args, out: Out) -> None:
    net = m.network_by_name(args.network) if args.network else None
    if args.events:
        rows = m.security_events(_timespan(args, 24), net["id"] if net else None)
        rows.sort(key=lambda r: r.get("ts") or "", reverse=True)
        _emit(out, args, rows[:args.limit] if args.limit else rows,
              ["ts", "eventType", "priority", "srcIp", "destIp", "protocol", "blocked", "classification", "message"], width=70)
        return
    if not net:
        raise MerakiError("security needs --network (or --events for the whole org)")
    data = {name: m.try_get(f"networks/{net['id']}/appliance/{path}") for name, path in (
        ("contentFiltering", "contentFiltering"), ("intrusion", "security/intrusion"), ("malware", "security/malware"))}
    if args.json:
        out.add(to_json(data))
        return
    for name, body in data.items():
        out.section(f"{net['name']} {name}", to_json(body))


def cmd_sdwan(m: Meraki, args, out: Out) -> None:
    net = m.network_by_name(args.network)
    data = {name: m.try_get(f"networks/{net['id']}/appliance/{path}") for name, path in (
        ("uplinkSelection", "trafficShaping/uplinkSelection"), ("uplinkBandwidth", "trafficShaping/uplinkBandwidth"),
        ("trafficShaping", "trafficShaping"), ("shapingRules", "trafficShaping/rules"))}
    if args.json:
        out.add(to_json(data))
        return
    for name, body in data.items():
        out.section(f"{net['name']} {name}", to_json(body))


def cmd_appliance(m: Meraki, args, out: Out) -> None:
    net = m.network_by_name(args.network)
    mxs = [d for d in m.devices() if d.get("networkId") == net["id"] and d.get("productType") == "appliance"]
    data: dict[str, Any] = {
        "ports": m.try_get(f"networks/{net['id']}/appliance/ports"),
        "warmSpare": m.try_get(f"networks/{net['id']}/appliance/warmSpare"),
        "settings": m.try_get(f"networks/{net['id']}/appliance/settings"),
        "devices": [{"name": d.get("name"), "serial": d["serial"], "model": d.get("model"), "firmware": d.get("firmware"),
                     "performance": m.try_get(f"devices/{d['serial']}/appliance/performance"),
                     "dhcpSubnets": m.try_get(f"devices/{d['serial']}/appliance/dhcp/subnets")} for d in mxs],
    }
    if args.json:
        out.add(to_json(data))
        return
    out.section(f"{net['name']} appliances", table(
        [{**d, "perfScore": (d["performance"] or {}).get("perfScore") if isinstance(d["performance"], dict) else ""} for d in data["devices"]],
        ["name", "serial", "model", "firmware", "perfScore", "performance.error"]))
    ports = data["ports"]
    out.section("LAN ports", table(ports, ["number", "enabled", "type", "vlan", "allowedVlans", "accessPolicy", "dropUntaggedTraffic"])
                if isinstance(ports, list) else to_json(ports))
    for d in data["devices"]:
        subnets = d["dhcpSubnets"]
        out.section(f"DHCP subnets on {d['name'] or d['serial']}",
                    table(subnets, ["subnet", "vlanId", "usedCount", "freeCount"]) if isinstance(subnets, list) else to_json(subnets))
    out.section("Warm spare", to_json(data["warmSpare"]))
    out.section("Appliance settings", to_json(data["settings"]))


PORT_COLUMNS = ["switch", "portId", "name", "enabled", "status", "speed", "duplex", "type", "vlan", "allowedVlans",
                "voiceVlan", "poeW=powerUsageInWh", "errors", "warnings", "neighbor", "clientCount", "accessPolicyType"]


def _neighbor(port_status: dict) -> str:
    lldp = port_status.get("lldp") or {}
    cdp = port_status.get("cdp") or {}
    name = lldp.get("systemName") or cdp.get("deviceId") or ""
    port = lldp.get("portId") or cdp.get("portId") or ""
    return f"{name} {port}".strip()


def cmd_ports(m: Meraki, args, out: Out) -> None:
    rows = []
    if args.switch:
        switches = [m.device_by_name(args.switch)]
    elif args.network:
        net = m.network_by_name(args.network)
        switches = [d for d in m.devices() if d.get("networkId") == net["id"] and d.get("productType") == "switch"]
    else:
        raise MerakiError("ports needs a switch name/serial or --network")
    for sw in sorted(switches, key=lambda d: d.get("name") or ""):
        cfg = {p["portId"]: p for p in m.switch_ports(sw["serial"])}
        for st in m.switch_port_statuses(sw["serial"], _timespan(args, 1)):
            row = {**cfg.get(st["portId"], {}), **st, "switch": sw.get("name") or sw["serial"], "neighbor": _neighbor(st)}
            rows.append(row)
    if args.port:
        rows = [r for r in rows if str(r["portId"]) == args.port]
    if args.errors:  # "Port disconnected" is listed as an error; ignore it here
        rows = [r for r in rows if [e for e in r.get("errors") or [] if e != "Port disconnected"] or r.get("warnings")]
    if args.connected:
        rows = [r for r in rows if r.get("status") == "Connected"]
    _emit(out, args, rows, PORT_COLUMNS)


SWITCH_KINDS = {
    "stacks": "networks/{net}/switch/stacks",
    "stp": "networks/{net}/switch/stp",
    "access-policies": "networks/{net}/switch/accessPolicies",
    "dhcp-policy": "networks/{net}/switch/dhcpServerPolicy",
    "acl": "networks/{net}/switch/accessControlLists",
    "qos": "networks/{net}/switch/qosRules",
    "mtu": "networks/{net}/switch/mtu",
    "settings": "networks/{net}/switch/settings",
    "interfaces": "devices/{serial}/switch/routing/interfaces",
    "routes": "devices/{serial}/switch/routing/staticRoutes",
}


def cmd_switch(m: Meraki, args, out: Out) -> None:
    net = m.network_by_name(args.network)
    switches = [d for d in m.devices() if d.get("networkId") == net["id"] and d.get("productType") == "switch"]
    result: dict[str, Any] = {}
    for kind in [args.kind] if args.kind else list(SWITCH_KINDS):
        path = SWITCH_KINDS[kind]
        if "{serial}" in path:
            result[kind] = {sw.get("name") or sw["serial"]: m.try_get(path.format(serial=sw["serial"])) for sw in switches}
        else:
            result[kind] = m.try_get(path.format(net=net["id"]))
        if not args.json:
            out.section(f"{net['name']} switch {kind}", to_json(result[kind]))
    if args.json:
        out.add(to_json(result))


def cmd_neighbors(m: Meraki, args, out: Out) -> None:
    if args.device:
        d = m.device_by_name(args.device)
        data = m.lldp_cdp(d["serial"])
        if args.json:
            out.add(to_json(data))
            return
        rows = []
        for port, info in sorted((data.get("ports") or {}).items(), key=lambda kv: _natural(kv[0])):
            for proto in ("lldp", "cdp"):
                n = info.get(proto)
                if n:
                    rows.append({"port": port, "protocol": proto,
                                 "neighbor": n.get("systemName") or n.get("deviceId"),
                                 "neighborPort": n.get("portId"), "address": n.get("managementAddress") or n.get("address"),
                                 "platform": n.get("platform") or n.get("systemDescription")})
        out.add(f"{d.get('name') or d['serial']} ({d['serial']})")
        out.add(table(rows, ["port", "protocol", "neighbor", "neighborPort", "address", "platform"]))
        return
    if not args.network:
        raise MerakiError("neighbors needs a device name/serial or --network")
    net = m.network_by_name(args.network)
    topo = m.get(f"networks/{net['id']}/topology/linkLayer")
    if args.json:
        out.add(to_json(topo))
        return
    names = {}
    for n in topo.get("nodes") or []:
        disc = n.get("discovered") or {}
        names[n.get("derivedId")] = ((n.get("device") or {}).get("name") or (disc.get("lldp") or {}).get("systemName")
                                     or (disc.get("cdp") or {}).get("deviceId") or n.get("mac") or n.get("derivedId"))
    rows = []
    for link in topo.get("links") or []:
        ends = link.get("ends") or []
        row = {}
        for i, e in enumerate(ends[:2]):
            disc = e.get("discovered") or {}
            row[f"{'ab'[i]}"] = (e.get("device") or {}).get("name") or names.get((e.get("node") or {}).get("derivedId"))
            row[f"{'ab'[i]}_port"] = (disc.get("lldp") or {}).get("portId") or (disc.get("cdp") or {}).get("portId")
        rows.append(row)
    out.add(table(rows, ["device=a", "port=a_port", "neighbor=b", "neighborPort=b_port"]))


EVENT_PRODUCTS = ("appliance", "camera", "campusGateway", "cellularGateway", "secureConnect", "switch",
                  "systemsManager", "wireless", "wirelessController")


def cmd_events(m: Meraki, args, out: Out) -> None:
    net = m.network_by_name(args.network)
    params: dict[str, Any] = {}
    if args.type:
        params["includedEventTypes[]"] = args.type
    if args.device:
        params["deviceSerial"] = m.device_by_name(args.device)["serial"]
    if args.client:
        params["clientMac"] = normalize_mac(args.client) or args.client
    products = [args.product] if args.product else         [p for p in net.get("productTypes") or [] if p in EVENT_PRODUCTS] or [None]
    rows = []
    for product in products:
        try:
            for e in m.events(net["id"], product, per_page=min(args.limit, 1000), **params):
                rows.append({**e, "productType": e.get("productType") or product})
        except MerakiError as exc:
            if args.product:
                raise
            print(f"skipped {product} events: {exc}", file=sys.stderr)
    rows.sort(key=lambda e: e.get("occurredAt") or "", reverse=True)
    _emit(out, args, rows[:args.limit], ["occurredAt", "productType", "device=deviceName", "type", "description",
                                         "client=clientDescription", "clientMac", "eventData"], width=70)


def cmd_alerts(m: Meraki, args, out: Out) -> None:
    params: dict[str, Any] = {"active": "true"} if not args.all else {}
    if args.network:
        params["networkId"] = m.network_by_name(args.network)["id"]
    if args.severity:
        params["severity"] = args.severity
    rows = m.assurance_alerts(**params)
    for r in rows:
        r["devices"] = [d.get("name") or d.get("serial") for d in (r.get("scope") or {}).get("devices") or []]
    rows.sort(key=lambda r: r.get("startedAt") or "", reverse=True)
    _emit(out, args, rows, ["startedAt", "severity", "category=categoryType", "type", "title", "network=network.name", "devices"])


def cmd_changes(m: Meraki, args, out: Out) -> None:
    params: dict[str, Any] = {}
    if args.network:
        params["networkId"] = m.network_by_name(args.network)["id"]
    rows = m.config_changes(timespan=min(_timespan(args, 24), 365 * 86400), **params)
    if args.admin:
        rows = [r for r in rows if args.admin.lower() in f"{r.get('adminName')} {r.get('adminEmail')}".lower()]
    _emit(out, args, rows, ["ts", "admin=adminName", "network=networkName", "page", "label", "oldValue", "newValue"], width=50)


def cmd_availability(m: Meraki, args, out: Out) -> None:
    params: dict[str, Any] = {}
    if args.network:
        params["networkIds[]"] = m.network_by_name(args.network)["id"]
    if args.product_type:
        params["productTypes[]"] = args.product_type
    rows = m.availability_changes(timespan=min(_timespan(args, 24), 31 * 86400), **params)
    for r in rows:
        det = r.get("details") or {}
        r["old"] = " ".join(str(x.get("value")) for x in det.get("old") or [])
        r["new"] = " ".join(str(x.get("value")) for x in det.get("new") or [])
    if args.summary and not args.json:
        counts = collections.Counter(((r.get("network") or {}).get("name"), (r.get("device") or {}).get("name"),
                                      (r.get("device") or {}).get("serial")) for r in rows)
        out.add(table([{"network": n, "device": d, "serial": s, "changes": c} for (n, d, s), c in counts.most_common()],
                      ["network", "device", "serial", "changes"]))
        return
    _emit(out, args, rows, ["ts", "network=network.name", "device=device.name", "serial=device.serial",
                            "type=device.productType", "old", "new"])


def cmd_firmware(m: Meraki, args, out: Out) -> None:
    if args.scheduled or args.history:
        statuses = ["scheduled", "started"] if args.scheduled else ["completed", "canceled"]
        rows = m.firmware_upgrades(**{"status[]": statuses})
        if args.network:
            want = {n["id"] for n in m.networks_matching(args.network)}
            rows = [r for r in rows if (r.get("network") or {}).get("id") in want]
        _emit(out, args, rows, ["time", "status", "network=network.name", "product=productTypes",
                                "from=fromVersion.shortName", "to=toVersion.shortName"])
        return
    names = m.network_names()
    want = {n["id"] for n in m.networks_matching(args.network)} if args.network else None
    counts = collections.Counter()
    for d in m.devices():
        if want is None or d.get("networkId") in want:
            counts[(names.get(d.get("networkId"), d.get("networkId")) if args.by_network else "", d.get("productType"),
                    d.get("model") if args.by_model else "", d.get("firmware"))] += 1
    rows = [{"network": n, "product": p, "model": mo, "firmware": f, "devices": c}
            for (n, p, mo, f), c in sorted(counts.items(), key=lambda kv: tuple(str(x) for x in kv[0]))]
    cols = (["network"] if args.by_network else []) + ["product"] + (["model"] if args.by_model else []) + ["firmware", "devices"]
    _emit(out, args, rows, cols)


def cmd_licenses(m: Meraki, args, out: Out) -> None:
    if args.coterm:
        # Older co-termination licenses (the org moved to subscription licensing).
        rows = m.get_all(f"organizations/{m.org_id}/licensing/coterm/licenses")
        if not args.all:
            rows = [r for r in rows if not r.get("expired") and not r.get("invalidated")]
        _emit(out, args, rows, ["startedAt", "duration", "mode", "expired", "invalidated", "editions", "counts"], width=80)
        return
    subs = m.subscriptions()
    if args.json:
        out.add(to_json(subs))
        return
    out.section("Subscriptions", table(subs, ["name", "subscriptionId", "status", "type", "startDate", "endDate",
                                              "assigned=counts.seats.assigned", "limit=counts.seats.limit", "productTypes"]))
    ents = [{"subscription": s.get("name"), "status": s.get("status"), **e} for s in subs for e in s.get("entitlements") or []]
    out.section("Seats by SKU", table(ents, ["subscription", "status", "sku", "assigned=seats.assigned",
                                             "available=seats.available", "limit=seats.limit"]))


def cmd_inventory(m: Meraki, args, out: Out) -> None:
    params: dict[str, Any] = {}
    if args.unused:
        params["usedState"] = "unused"
    if args.product_type:
        params["productTypes[]"] = args.product_type
    names = m.network_names()
    rows = m.inventory(**params)
    for r in rows:
        r["network"] = names.get(r.get("networkId"), "")
    rows.sort(key=lambda r: (r["network"], r.get("model") or ""))
    _emit(out, args, rows, ["network", "name", "model", "serial", "mac", "productType", "claimedAt", "licenseExpirationDate"])


def cmd_admins(m: Meraki, args, out: Out) -> None:
    rows = m.admins()
    for r in rows:
        r["networks"] = len(r.get("networks") or [])
        r["tags"] = len(r.get("tags") or [])
    rows.sort(key=lambda r: (r.get("name") or "").lower())
    _emit(out, args, rows, ["name", "email", "orgAccess", "networks", "tags", "accountStatus", "twoFactorAuthEnabled",
                            "authenticationMethod", "hasApiKey", "lastActive"])


SETTINGS_PATHS = {
    "settings": "settings", "syslog": "syslogServers", "snmp": "snmp", "alerts": "alerts/settings",
    "groupPolicies": "groupPolicies", "trafficAnalysis": "trafficAnalysis", "netflow": "netflow",
    "firmware": "firmware/upgrades",
}


def cmd_settings(m: Meraki, args, out: Out) -> None:
    net = m.network_by_name(args.network)
    data = {"network": net}
    data.update({name: m.try_get(f"networks/{net['id']}/{path}") for name, path in SETTINGS_PATHS.items()})
    if args.json:
        out.add(to_json(data))
        return
    for name, body in data.items():
        out.section(f"{net['name']} {name}", to_json(body))


def cmd_get(m: Meraki, args, out: Out) -> None:
    params: dict[str, Any] = {}
    for kv in args.param:
        key, value = kv.split("=", 1)
        if key in params:  # repeated array params, e.g. -p serials[]=A -p serials[]=B
            params[key] = (params[key] if isinstance(params[key], list) else [params[key]]) + [value]
        else:
            params[key] = value
    data = m.get(args.path, **params) if args.one_page else m.get_all(args.path, **params)
    out.add(to_json(data))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass
    parser = argparse.ArgumentParser(description="Read-only Meraki Dashboard API helper (GET only; secrets masked).")
    parser.add_argument("--org", default=DEFAULT_ORG_ID, help=f"Organization ID (default: {DEFAULT_ORG_ID})")
    parser.add_argument("--json", action="store_true", help="Print JSON")
    parser.add_argument("-o", "--output", help="Also write the output to this file")
    parser.add_argument("--append", action="store_true", help="With -o: append instead of overwriting")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add(name: str, func, help_text: str, network: str | None = None, hours: float | None = None):
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.set_defaults(func=func)
        if network == "required":
            p.add_argument("--network", required=True, help="Network name (exact, or a unique substring)")
        elif network == "optional":
            p.add_argument("--network", help="Network name (exact, or a unique substring)")
        elif network == "many":
            p.add_argument("--network", help="Only networks whose name equals, else contains, this text")
        if hours is not None:
            p.add_argument("--hours", type=float, help=f"Look back this many hours (default {hours:g})")
        return p

    # Inventory and status
    add("sites", None, "Every network with device counts and online count")
    p = add("devices", cmd_devices, "Devices with status (optionally for one network)", "optional")
    p.add_argument("--type", dest="product_type", help="appliance, switch, wireless, camera, cellularGateway...")
    add("aps", cmd_devices, "Access points with status and tags (optionally for one network)", "optional")
    add("offline", cmd_devices, "Devices whose status is not online", "optional")
    p = add("device", cmd_device, "One device in full: model, firmware, status, IPs, tags, address, mgmt interface")
    p.add_argument("device", help="Device name, serial or MAC")
    p = add("inventory", cmd_inventory, "Every claimed device, including spares not in a network")
    p.add_argument("--unused", action="store_true", help="Only devices not assigned to a network")
    p.add_argument("--type", dest="product_type", help="productType filter")
    p = add("licenses", cmd_licenses, "Subscription licenses: status, dates, seats used per SKU")
    p.add_argument("--coterm", action="store_true", help="Older co-term licenses instead (valid ones unless --all)")
    p.add_argument("--all", action="store_true", help="With --coterm: include expired and invalidated")
    p = add("firmware", cmd_firmware, "Firmware versions in use (device counts), or scheduled/past upgrades", "many")
    p.add_argument("--by-network", action="store_true", help="Break counts down by network")
    p.add_argument("--by-model", action="store_true", help="Break counts down by model")
    p.add_argument("--scheduled", action="store_true", help="Scheduled and in-progress upgrades")
    p.add_argument("--history", action="store_true", help="Completed and canceled upgrades")
    p = add("availability", cmd_availability, "Device online/offline changes (flaps)", "optional", 24)
    p.add_argument("--type", dest="product_type", help="productType filter")
    p.add_argument("--summary", action="store_true", help="Count changes per device instead of listing them")

    # Clients
    p = add("clients", cmd_clients, "Clients seen in one network", "required", 24)
    p.add_argument("--ssid", help="Only clients on SSIDs containing this text")
    p.add_argument("--vlan", help="Only clients in this VLAN")
    p.add_argument("--search", help="Only clients whose name, MAC, IP, user, OS or manufacturer contains this text")
    p.add_argument("--sort", choices=["name", "usage"], default="name")
    p = add("client", cmd_client, "Find a client by MAC (org-wide search), or by IP/name (scans network client lists)", "many", 24)
    p.add_argument("client", help="MAC (any format), IP address or client name")
    p.add_argument("--detail", action="store_true", help="Add wireless connection stats")
    p = add("top", cmd_top, "Top clients, applications, SSIDs, devices, models or networks by usage", hours=24)
    p.add_argument("kind", choices=list(TOP_KINDS))
    p.add_argument("--limit", type=int, default=10, help="How many to show (default 10)")

    # Wireless
    p = add("ssids", None, "Enabled SSIDs and how many APs broadcast each")
    p.add_argument("--by-network", action="store_true", help="One row per network and SSID instead of totals per SSID")
    p.add_argument("--network", help="Only networks whose name contains this text")
    p = add("ssid", cmd_ssid, "One SSID's config in every network that has it (secrets masked)", "many")
    p.add_argument("ssid", help="SSID name (exact, else contains)")
    p.add_argument("--full", action="store_true", help="Also print full config, firewall, shaping and splash per network")
    p.add_argument("--disabled", action="store_true", help="Include disabled SSID slots")
    add("rf-profiles", cmd_rf_profiles, "Wireless RF profiles", "many")
    add("wifi-health", cmd_wifi_health, "Wireless connection failures by step and AP, and channel utilization", "required", 24)
    p = add("air-marshal", cmd_air_marshal, "Rogue and neighbor SSIDs seen by the APs", "required", 24)
    p.add_argument("--wired", action="store_true", help="Only SSIDs whose BSSIDs were also seen on the wired LAN")
    add("ap-ports", cmd_ap_ports, "AP ethernet uplink: power source, PoE standard, speed, duplex", "optional")

    # Appliance, WAN, VPN
    p = add("uplinks", cmd_uplinks, "WAN uplinks: status, IP, gateway, public IP, DNS, cellular", "optional")
    p.add_argument("--loss", action="store_true", help="Add average loss and latency over the last 5 minutes")
    p.add_argument("--down", action="store_true", help="Only uplinks that aren't active or ready")
    p = add("vpn", cmd_vpn, "AutoVPN status per network (peers, unreachable peers, exported subnets)", "many")
    p.add_argument("--down", action="store_true", help="Only networks with unreachable peers or an offline MX")
    p.add_argument("--config", action="store_true", help="Site-to-site VPN config (mode, hubs, subnets in VPN)")
    p.add_argument("--third-party", action="store_true", help="Third-party IPsec peers (PSKs masked)")
    add("vlans", cmd_vlans, "MX VLANs / subnets / DHCP mode (all appliance networks unless --network)", "many")
    add("routes", cmd_routes, "MX static routes", "many")
    p = add("firewall", cmd_firewall, "MX firewall and NAT rules", "required")
    p.add_argument("--kind", choices=list(FIREWALL_KINDS), help="Only one rule set (default all)")
    p = add("security", cmd_security, "Content filtering, IDS/IPS and AMP settings, or security events", "optional", 24)
    p.add_argument("--events", action="store_true", help="Security events (IDS/AMP) instead of settings")
    p.add_argument("--limit", type=int, default=100, help="With --events: newest N (0 = all, default 100)")
    add("sdwan", cmd_sdwan, "SD-WAN uplink selection, bandwidth and traffic shaping", "required")
    add("appliance", cmd_appliance, "MX devices, performance, LAN ports, DHCP subnets, warm spare", "required")

    # Switches
    p = add("ports", cmd_ports, "Switch ports: config plus live status, PoE, errors, neighbor", "optional", 1)
    p.add_argument("switch", nargs="?", help="Switch name, serial or MAC (or use --network for every switch)")
    p.add_argument("--port", help="Only this port ID")
    p.add_argument("--errors", action="store_true", help="Only ports with errors or warnings")
    p.add_argument("--connected", action="store_true", help="Only connected ports")
    p = add("switch", cmd_switch, "Switch network config: stacks, STP, access policies, ACLs, QoS, L3 interfaces...", "required")
    p.add_argument("--kind", choices=list(SWITCH_KINDS), help="Only one section (default all)")

    # Topology, events, audit
    p = add("neighbors", cmd_neighbors, "LLDP/CDP neighbors of a device, or the L2 topology of a network", "optional")
    p.add_argument("device", nargs="?", help="Device name, serial or MAC")
    p = add("events", cmd_events, "Network event log (newest first)", "required")
    p.add_argument("--product", help="appliance, switch, wireless... (default: every product in the network)")
    p.add_argument("--type", action="append", help="Only this event type (repeatable)")
    p.add_argument("--device", help="Only events from this device (name, serial or MAC)")
    p.add_argument("--client", help="Only events for this client MAC")
    p.add_argument("--limit", type=int, default=100, help="Newest N events (max 1000 per product)")
    p = add("alerts", cmd_alerts, "Assurance alerts (active by default)", "optional")
    p.add_argument("--severity", choices=["critical", "warning", "informational"])
    p.add_argument("--all", action="store_true", help="Include resolved/dismissed alerts")
    p = add("changes", cmd_changes, "Dashboard configuration change log (who changed what)", "optional", 24)
    p.add_argument("--admin", help="Only changes by an admin whose name or email contains this text")
    add("admins", cmd_admins, "Dashboard administrators and their access")
    add("settings", cmd_settings, "Network settings: syslog, SNMP, alerts, group policies, NetFlow (secrets masked)", "required")

    p = add("get", cmd_get, "GET any API path, e.g. organizations/{org}/networks")
    p.add_argument("path", help="API path; {org} is replaced with the org ID")
    p.add_argument("-p", "--param", action="append", default=[], metavar="KEY=VALUE",
                   help="Query parameter; repeat for more. Use key[]=v for array params")
    p.add_argument("--one-page", action="store_true", help="Don't follow pagination")

    # Accept --json/-o/--append after the subcommand too (SUPPRESS keeps a value given before it).
    for subparser in sub.choices.values():
        subparser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="print JSON")
        subparser.add_argument("-o", "--output", default=argparse.SUPPRESS, help="also write the output to this file")
        subparser.add_argument("--append", action="store_true", default=argparse.SUPPRESS, help="with -o: append")
    args = parser.parse_args()

    m = Meraki(org_id=args.org)
    out = Out()

    if args.cmd == "sites":
        _emit(out, args, m.sites(), ["name", "devices", "online", "by_type", "tags"])
    elif args.cmd == "ssids":
        rows = m.ssid_usage()
        if args.network:
            rows = [r for r in rows if args.network.lower() in r["network"].lower()]
        if args.by_network or args.json:
            _emit(out, args, rows, ["ssid", "network", "number", "authMode", "aps", "aps_online", "availableOnAllAps", "visible"])
        else:
            totals: dict[str, dict] = {}
            for r in rows:
                t = totals.setdefault(r["ssid"], {"ssid": r["ssid"], "networks": 0, "aps": 0, "aps_online": 0, "authModes": set()})
                t["networks"] += 1
                t["aps"] += r["aps"]
                t["aps_online"] += r["aps_online"]
                t["authModes"].add(r["authMode"] or "")
            summary = sorted(totals.values(), key=lambda t: (-t["aps"], t["ssid"].lower()))
            for t in summary:
                t["authModes"] = ", ".join(sorted(t["authModes"]))
            out.add(table(summary, ["ssid", "networks", "aps", "aps_online", "authModes"]))
    else:
        args.func(m, args, out)
    out.save(args.output, args.append)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except MerakiError as exc:
        sys.exit(f"Meraki error: {exc}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
    except BrokenPipeError:  # output piped into head/more, which closed early
        sys.stderr.close()
        sys.exit(0)
