"""Read-only access to the Ordr SCE REST API.

Credentials are the Vault secrets ORDR_URL, ORDR_USER, ORDR_PASSWORD and ORDR_TENANTGUID
(see vault_helper.py). Authentication is HTTP basic auth, and the tenant GUID is sent as the
`tenantGuid` query parameter on every request. The client only issues GET requests, so it can't
clear or mute alarms, change vulnerabilities or update asset info.

API reference: https://api.ordr.net/api-docs/index.html (spec: https://api.ordr.net/api-docs/OrdrRestAPI.json)

As a module:
    from ordr_helper import Ordr
    o = Ordr()
    o.device("00:11:22:33:44:55")          # by MAC, IP or device name
    o.devices(group="Medical Devices", limit=50)
    o.alarms(mac="00:11:22:33:44:55")
    o.report("24-hour/device-count-by-type")

From the command line:
    python ordr_helper.py device 10.158.10.25
    python ordr_helper.py devices --profile "GE Healthcare Monitor" --limit 20
    python ordr_helper.py devices --conn-status ONLINE_IN_LAST_24_HRS --limit 50
    python ordr_helper.py alarms --severity high --limit 20
    python ordr_helper.py vulns --mac 00:11:22:33:44:55
    python ordr_helper.py summary                     # alarm + vulnerability summaries
    python ordr_helper.py reports device-count        # list report names matching text
    python ordr_helper.py report 24-hour/device-count-by-type
    python ordr_helper.py get Rest/Locations
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

SECRET_KEYS = ("ORDR_URL", "ORDR_USER", "ORDR_PASSWORD", "ORDR_TENANTGUID")
SPEC_URL = "https://api.ordr.net/api-docs/OrdrRestAPI.json"
MAX_RETRIES = 5
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{4}(\.[0-9A-Fa-f]{4}){2}$")

DEVICE_COLUMNS = ["MacAddress", "IpAddress", "dhcpHostname", "Group", "Profile", "MfgName", "ModelNameNo",
                  "Vlan", "RiskState", "connStatus", "deviceLocation", "lastSeen"]
ALARM_COLUMNS = ["recentTimestamp", "severityLevel", "category", "alarm_type", "deviceMac", "riskScore", "sensorName"]
VULN_COLUMNS = ["vulnId", "severityLevel", "deviceName", "deviceMac", "currIpAddress", "deviceCategory", "vulnSummary"]


class OrdrError(Exception):
    """An Ordr API call failed (status, path and Ordr's error text; never the credentials)."""


def normalize_mac(mac: str) -> str:
    """Return a MAC as uppercase AA:BB:CC:DD:EE:FF (accepts -, : or Cisco dotted format).
    Ordr's mac= filter is case-sensitive and only matches uppercase."""
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


class Ordr:
    """Minimal read-only Ordr REST API client with MetaData.next pagination and 429 retry."""

    def __init__(self, url: str | None = None, user: str | None = None, password: str | None = None,
                 tenant_guid: str | None = None, timeout: int = 60):
        if not all((url, user, password, tenant_guid)):
            import vault_helper

            secrets = vault_helper.get_secret_values(SECRET_KEYS, interactive=False)
            url = url or secrets["ORDR_URL"]
            user = user or secrets["ORDR_USER"]
            password = password or secrets["ORDR_PASSWORD"]
            tenant_guid = tenant_guid or secrets["ORDR_TENANTGUID"]
        if "://" not in url:
            url = f"https://{url}"
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.tenant_guid = tenant_guid
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.headers["Accept"] = "application/json"

    # -- core ---------------------------------------------------------------

    def _url(self, path: str) -> str:
        """Accept a full URL, '/Rest/Devices', 'Rest/Devices' or just 'Devices'."""
        if path.startswith("http"):
            return path
        path = path.lstrip("/")
        if not path.startswith("Rest/"):
            path = f"Rest/{path}"
        return f"{self.base_url}/{path}"

    def _with_tenant(self, url: str, params: dict | None) -> tuple[str, dict]:
        """Make sure tenantGuid is on the request, whether it's in the URL already or not."""
        params = dict(params or {})
        if "tenantGuid" not in parse_qs(urlparse(url).query):
            params.setdefault("tenantGuid", self.tenant_guid)
        return url, params

    def _request(self, url: str, params: dict | None = None) -> requests.Response:
        url, params = self._with_tenant(url, params)
        for attempt in range(MAX_RETRIES):
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 429:
                time.sleep(float(resp.headers.get("Retry-After", 2 ** attempt)))
                continue
            if resp.status_code >= 400:
                where = urlparse(url).path
                if resp.status_code == 401:
                    raise OrdrError(f"401 on {where}: Ordr rejected the ORDR_USER / ORDR_PASSWORD from Vault")
                raise OrdrError(f"{resp.status_code} on {where}: {resp.text[:300]}")
            return resp
        raise OrdrError(f"rate limited too many times on {urlparse(url).path}")

    def get(self, path: str, **params: Any) -> Any:
        """GET one response and return the decoded JSON."""
        resp = self._request(self._url(path), params)
        return resp.json() if resp.content else {}

    def get_all(self, path: str, max_items: int | None = None, **params: Any) -> list:
        """GET a list endpoint and follow MetaData.next until done (or until max_items).

        Returns the items from the response's list field (Devices, alarms, and so on). If the response
        has no list field, it is returned as-is in a one-item list.
        """
        url: str | None = self._url(path)
        query: dict | None = params
        items: list = []
        while url:
            data = self._request(url, query).json()
            if isinstance(data, list):
                items.extend(data)
                break
            list_key = next((k for k, v in data.items() if isinstance(v, list)), None)
            if list_key is None:
                # Single-device lookups return one flat object; "not found" comes back as 200 {"error": ...}.
                return [] if set(data) == {"error"} else [data]
            items.extend(data[list_key])
            if max_items and len(items) >= max_items:
                return items[:max_items]
            meta = data.get("MetaData") or data.get("metaData") or {}
            next_link = meta.get("next") if isinstance(meta, dict) else None
            url = urljoin(self.base_url + "/", next_link) if next_link else None
            query = None  # the next link carries its own query string (clientMacToken etc.)
        return items[:max_items] if max_items else items

    # -- devices ------------------------------------------------------------

    def devices(self, max_items: int | None = None, **filters: Any) -> list[dict]:
        """Devices, optionally filtered. Filter names are the API's query parameters, e.g.
        mac, ip, deviceName, group, profile, location, type, riskState, connStatus, mfg, model,
        serial, iot=True, include='connectivity-info'. Use the API spelling for hyphenated names
        by passing a dict: devices(**{"os-type": "Windows"})."""
        params = {k: (str(v).lower() if isinstance(v, bool) else v) for k, v in filters.items() if v is not None}
        if max_items:
            params.setdefault("limit", max_items)
        return self.get_all("Rest/Devices", max_items=max_items, **params)

    def device(self, value: str, include: str | None = None) -> list[dict]:
        """Look up a device by MAC, IP or device name (all matches)."""
        extra = {"include": include} if include else {}
        if MAC_RE.match(value.strip()):
            return self.devices(mac=normalize_mac(value), **extra)
        try:
            ipaddress.ip_address(value.strip())
            return self.devices(ip=value.strip(), **extra)
        except ValueError:
            # deviceName matches the short hostname (any case) but not an FQDN, so drop the domain.
            return self.devices(deviceName=value.strip().split(".")[0], **extra)

    # -- security -----------------------------------------------------------

    def alarms(self, max_items: int | None = None, **filters: Any) -> list[dict]:
        """Security alarms. Filters: mac, ip, sensorName, category, limit, and (hyphenated, via dict)
        severity-level, start-time, end-time."""
        params = {k: v for k, v in filters.items() if v is not None}
        if max_items:
            params.setdefault("limit", max_items)
        return self.get_all("Rest/SecurityAlarms", max_items=max_items, **params)

    def alarm_summary(self) -> Any:
        return self.get("Rest/SecurityAlarms/Summary")

    def vulnerabilities(self, max_items: int | None = None, **filters: Any) -> list[dict]:
        """Vulnerabilities. Filters: mac, ip, limit, include='deviceinfo' or 'details-blob'."""
        params = {k: v for k, v in filters.items() if v is not None}
        if max_items:
            params.setdefault("limit", max_items)
        return self.get_all("Rest/Vulnerabilities", max_items=max_items, **params)

    def vulnerability_summary(self) -> Any:
        return self.get("Rest/Vulnerabilities/Summary")

    # -- other --------------------------------------------------------------

    def profiles(self, include: str = "name,type") -> list[dict]:
        return self.get_all("Rest/Profiles", include=include)

    def locations(self) -> Any:
        return self.get("Rest/Locations")

    def applications(self, mac: str | None = None, ip: str | None = None) -> Any:
        return self.get("Rest/Applications", **({"mac": normalize_mac(mac)} if mac else {"ip": ip}))

    def flows(self, max_items: int | None = 500, **filters: Any) -> list[dict]:
        """Flows. Filters: srcIp, dstIp, srcMac, dstMac, limit."""
        if max_items:
            filters.setdefault("limit", max_items)
        return self.get_all("Rest/Flows", max_items=max_items, **filters)

    def report(self, name: str, **params: Any) -> Any:
        """One of the ~290 reports in the spec, e.g. 'high-risk-devices'. Note: as of 2026-10 the LCMC
        tenant answers every report with 400 'Unknown report', so prefer devices()/alarms() queries."""
        return self.get(f"Rest/Reports/{name.strip('/').removeprefix('Rest/Reports/')}", **params)


def report_names(match: str | None = None) -> list[str]:
    """Report names from Ordr's public API spec (no credentials needed)."""
    spec = requests.get(SPEC_URL, timeout=60).json()
    names = sorted({p.split("?")[0].removeprefix("/Rest/Reports/") for p in spec["paths"] if p.startswith("/Rest/Reports/")})
    return [n for n in names if not match or match.lower() in n.lower()]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print(data: Any, as_json: bool, columns: list[str] | None = None) -> None:
    if as_json or not isinstance(data, list) or not data or not columns or not isinstance(data[0], dict):
        print(json.dumps(data, indent=2, default=str))
        return
    rows = [[("" if item.get(c) is None else str(item.get(c)))[:60] for c in columns] for item in data]
    widths = [max(len(x) for x in col) for col in zip(columns, *rows)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*columns))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows:
        print(fmt.format(*row))
    print(f"\n{len(data)} row(s)", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Ordr REST API helper.")
    parser.add_argument("--json", action="store_true", help="Print raw JSON")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("device", help="Look up a device by MAC, IP or device name")
    p.add_argument("value")
    p.add_argument("--include", help="e.g. connectivity-info, clinical-info, asset-info")

    p = sub.add_parser("devices", help="List devices with filters")
    for flag in ("group", "profile", "location", "type", "mfg", "model", "subcategory"):
        p.add_argument(f"--{flag}")
    p.add_argument("--risk", dest="riskState", help="Risk state, e.g. High, Critical")
    p.add_argument("--conn-status", dest="connStatus",
                   help="ONLINE, OFFLINE, ONLINE_IN_LAST_24_HRS, ONLINE_IN_LAST_WEEK, OFFLINE_IN_LAST_24_HRS, OFFLINE_IN_LAST_WEEK")
    p.add_argument("--iot", action="store_true", help="Only IoT devices")
    p.add_argument("--include", help="e.g. connectivity-info, clinical-info, asset-info")
    p.add_argument("--limit", type=int, default=100, help="Max devices to return (default 100; 0 = all)")

    p = sub.add_parser("alarms", help="Security alarms")
    p.add_argument("--mac")
    p.add_argument("--ip")
    p.add_argument("--severity", type=str.lower, choices=["normal", "low", "medium", "high", "critical"],
                   help="Severity level")
    p.add_argument("--category")
    p.add_argument("--limit", type=int, default=100, help="Max alarms (default 100; 0 = all)")

    p = sub.add_parser("vulns", help="Vulnerabilities")
    p.add_argument("--mac")
    p.add_argument("--ip")
    p.add_argument("--limit", type=int, default=100, help="Max rows (default 100; 0 = all)")

    sub.add_parser("summary", help="Security alarm and vulnerability summaries")
    sub.add_parser("locations", help="Ordr locations")
    sub.add_parser("profiles", help="Profiles with name and type")

    p = sub.add_parser("reports", help="List report names (from the public API spec)")
    p.add_argument("match", nargs="?", help="Only names containing this text")

    p = sub.add_parser("report", help="Run one report, e.g. 24-hour/device-count-by-type")
    p.add_argument("name")

    p = sub.add_parser("get", help="GET any API path, e.g. Rest/Locations")
    p.add_argument("path")
    p.add_argument("-p", "--param", action="append", default=[], metavar="KEY=VALUE", help="Query parameter; repeat for more")
    p.add_argument("--all", action="store_true", help="Follow MetaData.next pagination")

    # Accept --json after the subcommand too (SUPPRESS keeps a --json given before it).
    for subparser in sub.choices.values():
        subparser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="print JSON")
    args = parser.parse_args()

    if args.cmd == "reports":
        for name in report_names(args.match):
            print(name)
        return 0

    o = Ordr()
    if args.cmd == "device":
        _print(o.device(args.value, include=args.include), args.json, DEVICE_COLUMNS)
    elif args.cmd == "devices":
        filters = {k: getattr(args, k) for k in ("group", "profile", "location", "type", "mfg", "model",
                                                 "subcategory", "riskState", "connStatus", "include")}
        if args.iot:
            filters["iot"] = True
        _print(o.devices(max_items=args.limit or None, **filters), args.json, DEVICE_COLUMNS)
    elif args.cmd == "alarms":
        filters = {"mac": normalize_mac(args.mac) if args.mac else None, "ip": args.ip,
                   "severity-level": args.severity, "category": args.category}
        _print(o.alarms(max_items=args.limit or None, **filters), args.json, ALARM_COLUMNS)
    elif args.cmd == "vulns":
        filters = {"mac": normalize_mac(args.mac) if args.mac else None, "ip": args.ip}
        _print(o.vulnerabilities(max_items=args.limit or None, **filters), args.json, VULN_COLUMNS)
    elif args.cmd == "summary":
        _print({"alarms": o.alarm_summary(), "vulnerabilities": o.vulnerability_summary()}, True)
    elif args.cmd == "locations":
        _print(o.locations(), True)
    elif args.cmd == "profiles":
        _print(o.profiles(), args.json, ["guid", "name", "type"])
    elif args.cmd == "report":
        _print(o.report(args.name), True)
    elif args.cmd == "get":
        params = dict(kv.split("=", 1) for kv in args.param)
        _print(o.get_all(args.path, **params) if args.all else o.get(args.path, **params), True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OrdrError as exc:
        sys.exit(f"Ordr error: {exc}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
