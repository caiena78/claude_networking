"""Read-only access to Cisco Catalyst Center (formerly DNA Center).

Credentials are the Vault secrets cat_url, cat_user and cat_password (see vault_helper.py).
The helper gets an auth token (POST /dna/system/api/v1/auth/token, basic auth), then sends it as
X-Auth-Token on GET requests to the Intent API. The token lasts about an hour and is refreshed
automatically on 401. The auth token call is the only non-GET request, so the helper can't change
config, run Command Runner or push templates.

As a module:
    from catalyst_helper import Catalyst
    cc = Catalyst()
    cc.devices(hostname="tls-wan-rtr-01")
    cc.device("10.158.136.51")              # by hostname, management IP, serial or id
    cc.client("00:11:22:33:44:55")          # client detail (where it's connected, health)
    cc.sites()

From the command line:
    python catalyst_helper.py devices --family Switches --limit 50
    python catalyst_helper.py device tls-wan-rtr-01
    python catalyst_helper.py interfaces tls-wan-rtr-01
    python catalyst_helper.py client 00:11:22:33:44:55
    python catalyst_helper.py sites
    python catalyst_helper.py health
    python catalyst_helper.py issues --priority P1
    python catalyst_helper.py get dna/intent/api/v1/network-device/count
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
from typing import Any
from urllib.parse import urlparse

import requests

SECRET_KEYS = ("cat_url", "cat_user", "cat_password")
INTENT = "dna/intent/api/v1"
PAGE_SIZE = 500  # network-device maximum
MAX_RETRIES = 5
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{4}(\.[0-9A-Fa-f]{4}){2}$|^[0-9A-Fa-f]{12}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

DEVICE_COLUMNS = ["hostname", "managementIpAddress", "platformId", "family", "role", "softwareVersion",
                  "serialNumber", "reachabilityStatus", "upTime", "id"]
INTERFACE_COLUMNS = ["portName", "status", "adminStatus", "ipv4Address", "vlanId", "speed", "duplex",
                     "portMode", "description"]
SITE_COLUMNS = ["siteNameHierarchy", "siteType", "id"]
HEALTH_COLUMNS = ["siteName", "siteType", "healthyNetworkDevicePercentage", "healthyClientsPercentage",
                  "numberOfClients", "numberOfNetworkDevice"]
ISSUE_COLUMNS = ["priority", "name", "deviceRole", "status", "last_occurence_time", "deviceId"]


class CatalystError(Exception):
    """A Catalyst Center API call failed (status, path and the error text; never the credentials)."""


def normalize_mac(mac: str) -> str:
    """Return a MAC as lowercase aa:bb:cc:dd:ee:ff, the format Catalyst Center uses."""
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac).lower()
    if len(digits) != 12:
        raise CatalystError(f"{mac!r} is not a MAC address")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


class Catalyst:
    """Minimal read-only Catalyst Center client with token refresh, offset paging and 429 retry."""

    def __init__(self, url: str | None = None, user: str | None = None, password: str | None = None,
                 verify: bool | str | None = None, timeout: int = 60):
        if not all((url, user, password)):
            import vault_helper  # also turns on truststore, so an internal CA can be trusted

            secrets = vault_helper.get_secret_values(SECRET_KEYS, interactive=False)
            url = url or secrets["cat_url"]
            user = user or secrets["cat_user"]
            password = password or secrets["cat_password"]
        if "://" not in url:
            url = f"https://{url}"
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.timeout = timeout
        self._auth = (user, password)
        self.session = requests.Session()
        self.session.verify = verify if verify is not None else (os.environ.get("CAT_CACERT") or os.environ.get("LCMC_CACERT") or True)
        self.session.headers["Accept"] = "application/json"
        self._token: str | None = None

    # -- core ---------------------------------------------------------------

    def _send(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        try:
            return self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.exceptions.SSLError:
            raise CatalystError(f"TLS certificate for {urlparse(url).hostname} is not trusted. It uses LCMC's "
                                "internal CA (EPIC-CA); set LCMC_CACERT to its PEM file or install it as a trusted root") from None
        except requests.exceptions.ConnectionError as exc:
            raise CatalystError(f"cannot connect to {urlparse(url).netloc}: {type(exc).__name__}") from None

    def login(self) -> None:
        """Get a new auth token. This is the helper's only non-GET request."""
        resp = self._send("POST", f"{self.base_url}/dna/system/api/v1/auth/token", auth=self._auth)
        if resp.status_code == 401:
            raise CatalystError("401 on auth/token: Catalyst Center rejected cat_user / cat_password from Vault")
        if resp.status_code >= 400:
            raise CatalystError(f"{resp.status_code} on auth/token: {resp.text[:300]}")
        self._token = resp.json()["Token"]
        self.session.headers["X-Auth-Token"] = self._token

    def _url(self, path: str) -> str:
        """Accept a full URL, 'dna/...', '/dna/...', or a path relative to the Intent API ('network-device')."""
        if path.startswith("http"):
            return path
        path = path.lstrip("/")
        if not path.startswith("dna/"):
            path = f"{INTENT}/{path}"
        return f"{self.base_url}/{path}"

    def get(self, path: str, **params: Any) -> Any:
        """GET one response and return the JSON with the 'response' wrapper removed."""
        if not self._token:
            self.login()
        url = self._url(path)
        params = {k: v for k, v in params.items() if v is not None}
        refreshed = False
        for attempt in range(MAX_RETRIES):
            resp = self._send("GET", url, params=params or None)
            if resp.status_code == 401 and not refreshed:
                self.login()
                refreshed = True
                continue
            if resp.status_code == 429:
                time.sleep(float(resp.headers.get("Retry-After", 2 ** attempt)))
                continue
            if resp.status_code >= 400:
                raise CatalystError(f"{resp.status_code} on {urlparse(url).path}: {resp.text[:300]}")
            data = resp.json() if resp.content else {}
            return data.get("response", data) if isinstance(data, dict) else data
        raise CatalystError(f"rate limited too many times on {urlparse(url).path}")

    def get_all(self, path: str, max_items: int | None = None, page_size: int = PAGE_SIZE, **params: Any) -> list:
        """GET a list endpoint page by page using offset (1-based) and limit."""
        items: list = []
        offset = 1
        while True:
            limit = min(page_size, max_items - len(items)) if max_items else page_size
            page = self.get(path, offset=offset, limit=limit, **params)
            if not isinstance(page, list):
                return [page] if page else []
            items.extend(page)
            if len(page) < limit or (max_items and len(items) >= max_items):
                return items[:max_items] if max_items else items
            offset += len(page)

    # -- devices ------------------------------------------------------------

    def devices(self, max_items: int | None = None, **filters: Any) -> list[dict]:
        """Network devices. Filters: hostname, managementIpAddress, serialNumber, family, type,
        platformId, role, softwareVersion, reachabilityStatus, macAddress, locationName...
        Values can use .* wildcards, e.g. hostname='tls-.*'."""
        return self.get_all("network-device", max_items=max_items, **filters)

    def device(self, value: str) -> list[dict]:
        """Find devices by id, management IP, serial number or hostname (exact, else wildcard)."""
        value = value.strip()
        if UUID_RE.match(value):
            return [self.get(f"network-device/{value}")]
        if is_ip(value):
            return self.devices(managementIpAddress=value)
        # The hostname filter is case-sensitive and LCMC hostnames are mostly uppercase FQDNs
        # (TLS-WAN-RTR-01.lcmchealth.org), so try the name as typed, upper and lower, exact then prefix.
        for name in dict.fromkeys((value, value.upper(), value.lower())):
            found = self.devices(hostname=name) or self.devices(hostname=f"{name}.*")
            if found:
                return found
        return self.devices(serialNumber=value) or self.devices(serialNumber=value.upper())

    def device_count(self) -> int:
        return int(self.get("network-device/count"))

    def _device_id(self, value: str) -> str:
        found = self.device(value)
        if not found:
            raise CatalystError(f"no device matches {value!r}")
        if len(found) > 1:
            raise CatalystError(f"{value!r} matches {len(found)} devices: {', '.join(d.get('hostname', '?') for d in found[:10])}")
        return found[0]["id"]

    def interfaces(self, device: str) -> list[dict]:
        """Interfaces of one device (by hostname, IP, serial or id)."""
        return self.get(f"interface/network-device/{self._device_id(device)}")

    def interface_by_ip(self, ip: str) -> list[dict]:
        return self.get(f"interface/ip-address/{ip}")

    def device_config(self, device: str) -> str:
        """The running config Catalyst Center collected for a device (read from its inventory)."""
        return self.get(f"network-device/{self._device_id(device)}/config")

    def device_health(self, max_items: int | None = None, **filters: Any) -> list[dict]:
        """Device health scores. Filters: deviceRole, siteId, health (POOR/FAIR/GOOD)."""
        return self.get_all("device-health", max_items=max_items, page_size=500, **filters)

    # -- sites, clients, issues ---------------------------------------------

    def sites(self, name: str | None = None) -> list[dict]:
        return self.get_all("site", page_size=500, name=name)

    def site_health(self) -> list[dict]:
        return self.get_all("site-health", page_size=50)

    def client(self, mac: str) -> dict | None:
        """A client by MAC from the assurance data API: connected AP/switch (name, IP, interface), IP,
        type, site, health. None when Catalyst Center has no assurance data for it (common for wired
        PCs). Falls back to the older client-detail API if the data API isn't available."""
        try:
            rows = self.get("dna/data/api/v1/clients", macAddress=normalize_mac(mac))
            return rows[0] if isinstance(rows, list) and rows else None
        except CatalystError as exc:
            if not str(exc).startswith(("404", "400")):
                raise
        try:
            return self.get("client-detail", macAddress=normalize_mac(mac))
        except CatalystError as exc:
            if str(exc).startswith("404"):
                return None
            raise

    def clients(self, max_items: int | None = 100, **filters: Any) -> list[dict]:
        """Clients from the assurance data API. Filters: type (Wired/Wireless), siteId, ipv4Address,
        connectedNetworkDeviceName, ssid, band, osType..."""
        return self.get_all("dna/data/api/v1/clients", max_items=max_items, page_size=100, **filters)

    def client_health(self) -> Any:
        return self.get("client-health")

    def issues(self, **filters: Any) -> list[dict]:
        """Open assurance issues. Filters: priority (P1-P4), issueStatus (ACTIVE/IGNORED/RESOLVED),
        deviceId, macAddress, siteId, aiDriven."""
        data = self.get("issues", **filters)
        return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print(data: Any, as_json: bool = True, columns: list[str] | None = None) -> None:
    if as_json or not isinstance(data, list) or not data or not columns or not isinstance(data[0], dict):
        print(data if isinstance(data, str) else json.dumps(data, indent=2, default=str))
        return
    rows = [[("" if item.get(c) is None else str(item.get(c)))[:50] for c in columns] for item in data]
    widths = [max(len(x) for x in col) for col in zip(columns, *rows)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*columns))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows:
        print(fmt.format(*row))
    print(f"\n{len(data)} row(s)", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Cisco Catalyst Center helper.")
    parser.add_argument("--json", action="store_true", help="Print full records / raw JSON")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("devices", help="List network devices")
    for flag in ("hostname", "family", "role", "platform", "version", "reachability", "location"):
        p.add_argument(f"--{flag}")
    p.add_argument("--limit", type=int, default=0, help="Max devices (default all)")
    p = sub.add_parser("device", help="One device by hostname, management IP, serial or id")
    p.add_argument("value")
    sub.add_parser("count", help="Number of devices in inventory")
    p = sub.add_parser("interfaces", help="Interfaces of a device")
    p.add_argument("device")
    p = sub.add_parser("config", help="Running config Catalyst Center collected for a device")
    p.add_argument("device")
    p = sub.add_parser("client", help="Client detail for a MAC")
    p.add_argument("mac")
    p = sub.add_parser("sites", help="Sites (areas, buildings, floors)")
    p.add_argument("--name", help="Site name hierarchy, e.g. Global/UMC")
    sub.add_parser("health", help="Site health")
    p = sub.add_parser("device-health", help="Device health scores")
    p.add_argument("--role", help="ACCESS, DISTRIBUTION, CORE, ROUTER, WLC, AP")
    p.add_argument("--health", choices=["POOR", "FAIR", "GOOD"])
    p.add_argument("--limit", type=int, default=0)
    p = sub.add_parser("issues", help="Assurance issues")
    p.add_argument("--priority", choices=["P1", "P2", "P3", "P4"])
    p.add_argument("--status", default="ACTIVE", choices=["ACTIVE", "IGNORED", "RESOLVED"])
    p = sub.add_parser("get", help="GET any API path, e.g. dna/intent/api/v1/network-device/count")
    p.add_argument("path")
    p.add_argument("-p", "--param", action="append", default=[], metavar="KEY=VALUE", help="Query parameter; repeat for more")
    p.add_argument("--all", action="store_true", help="Page through with offset/limit")
    args = parser.parse_args()

    cc = Catalyst()
    if args.cmd == "devices":
        filters = {"hostname": args.hostname, "family": args.family, "role": args.role, "platformId": args.platform,
                   "softwareVersion": args.version, "reachabilityStatus": args.reachability, "locationName": args.location}
        _print(cc.devices(max_items=args.limit or None, **{k: v for k, v in filters.items() if v}), args.json, DEVICE_COLUMNS)
    elif args.cmd == "device":
        found = cc.device(args.value)
        _print(found, args.json or len(found) == 1, DEVICE_COLUMNS)
    elif args.cmd == "count":
        print(cc.device_count())
    elif args.cmd == "interfaces":
        _print(cc.interfaces(args.device), args.json, INTERFACE_COLUMNS)
    elif args.cmd == "config":
        _print(cc.device_config(args.device))
    elif args.cmd == "client":
        c = cc.client(args.mac)
        if c and not args.json and "connectedNetworkDevice" in c:
            dev = c.get("connectedNetworkDevice") or {}
            c = {"mac": c.get("macAddress"), "ip": c.get("ipv4Address"), "name": c.get("name"), "user": c.get("username"),
                 "type": c.get("type"), "deviceType": c.get("deviceType"), "vendor": c.get("vendor"),
                 "status": c.get("connectionStatus"), "site": c.get("siteHierarchy"),
                 "connectedTo": dev.get("connectedNetworkDeviceName"), "connectedToIp": dev.get("connectedNetworkDeviceManagementIp"),
                 "connectedToType": dev.get("connectedNetworkDeviceType"), "interface": dev.get("interfaceName"),
                 "ssid": (c.get("connection") or {}).get("ssid"), "vlan": (c.get("connection") or {}).get("vlanId"),
                 "healthScore": (c.get("health") or {}).get("overallScore"), "lastUpdated": c.get("lastUpdatedTime")}
        _print(c)
    elif args.cmd == "sites":
        _print(cc.sites(args.name), args.json, SITE_COLUMNS)
    elif args.cmd == "health":
        _print(cc.site_health(), args.json, HEALTH_COLUMNS)
    elif args.cmd == "device-health":
        filters = {"deviceRole": args.role, "health": args.health}
        _print(cc.device_health(args.limit or None, **{k: v for k, v in filters.items() if v}), args.json,
               ["name", "ipAddress", "deviceType", "deviceFamily", "overallHealth", "reachabilityHealth", "location"])
    elif args.cmd == "issues":
        _print(cc.issues(priority=args.priority, issueStatus=args.status), args.json, ISSUE_COLUMNS)
    elif args.cmd == "get":
        params = dict(kv.split("=", 1) for kv in args.param)
        _print(cc.get_all(args.path, **params) if args.all else cc.get(args.path, **params))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CatalystError as exc:
        sys.exit(f"Catalyst Center error: {exc}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
