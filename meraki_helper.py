"""Read-only access to the Cisco Meraki Dashboard API.

The API key is the Vault secret `meraki_api` (see vault_helper.py). The client only issues
GET requests, so it can't change live Meraki config.

As a module:
    from meraki_helper import Meraki
    m = Meraki()
    nets = m.networks()
    devs = m.devices(productTypes=["appliance"])
    clients = m.get_all(f"/networks/{nets[0]['id']}/clients", timespan=86400)

From the command line:
    python meraki_helper.py sites                       # every network with device counts / online
    python meraki_helper.py devices --network "PUC_Kenner"
    python meraki_helper.py offline                     # devices whose status is not online
    python meraki_helper.py get organizations/{org}/appliance/vpn/statuses
    python meraki_helper.py get networks/N_123/clients -p timespan=3600 --json
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


class MerakiError(Exception):
    """A Meraki API call failed (status, path and Meraki's error text; never the API key)."""


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

    # -- core ---------------------------------------------------------------

    def _url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        path = path.replace("{org}", self.org_id).replace("{orgId}", self.org_id)
        return f"{BASE_URL}/{path.lstrip('/')}"

    def _request(self, url: str, params: dict | None) -> requests.Response:
        for attempt in range(MAX_RETRIES):
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 429:
                time.sleep(float(resp.headers.get("Retry-After", 2 ** attempt)))
                continue
            if resp.status_code >= 400:
                try:
                    detail = "; ".join(resp.json().get("errors", [])) or resp.text[:200]
                except ValueError:
                    detail = resp.text[:200]
                raise MerakiError(f"{resp.status_code} on {url.replace(BASE_URL, '')}: {detail}")
            return resp
        raise MerakiError(f"rate limited too many times on {url.replace(BASE_URL, '')}")

    def get(self, path: str, **params: Any) -> Any:
        """GET one page and return the decoded JSON."""
        return self._request(self._url(path), params or None).json()

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
        while True:
            data = resp.json()
            if not isinstance(data, list):
                return data
            items.extend(data)
            url = resp.links.get("next", {}).get("url")
            if not url:
                return items
            resp = self._request(url, None)  # the next URL already carries the query string

    # -- common lookups -----------------------------------------------------

    def organizations(self) -> list[dict]:
        return self.get_all("/organizations")

    def networks(self, **params: Any) -> list[dict]:
        return self.get_all(f"/organizations/{self.org_id}/networks", **params)

    def network_by_name(self, name: str) -> dict:
        """Find a network by exact name, else by case-insensitive substring (must be unique)."""
        nets = self.networks()
        exact = [n for n in nets if n["name"] == name]
        if exact:
            return exact[0]
        partial = [n for n in nets if name.lower() in n["name"].lower()]
        if len(partial) == 1:
            return partial[0]
        if not partial:
            raise MerakiError(f"no network matches {name!r}")
        raise MerakiError(f"{name!r} matches {len(partial)} networks: {', '.join(n['name'] for n in partial)}")

    def devices(self, **params: Any) -> list[dict]:
        """Org inventory of devices in networks. Filters: networkIds, productTypes, serial, model, tags..."""
        return self.get_all(f"/organizations/{self.org_id}/devices", **params)

    def device_statuses(self, **params: Any) -> list[dict]:
        """status is one of online, alerting, offline, dormant."""
        return self.get_all(f"/organizations/{self.org_id}/devices/statuses", **params)

    def uplink_statuses(self, **params: Any) -> list[dict]:
        return self.get_all(f"/organizations/{self.org_id}/uplinks/statuses", **params)

    def vpn_statuses(self, **params: Any) -> list[dict]:
        return self.get_all(f"/organizations/{self.org_id}/appliance/vpn/statuses", **params)

    def clients(self, network_id: str, timespan: int = 86400, **params: Any) -> list[dict]:
        return self.get_all(f"/networks/{network_id}/clients", timespan=timespan, **params)

    def vlans(self, network_id: str) -> list[dict]:
        return self.get_all(f"/networks/{network_id}/appliance/vlans")

    def lldp_cdp(self, serial: str) -> dict:
        return self.get(f"/devices/{serial}/lldpCdp")

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
# CLI
# ---------------------------------------------------------------------------

def _print(data: Any, as_json: bool, columns: list[str] | None = None) -> None:
    if as_json or not isinstance(data, list) or not data or not columns:
        print(json.dumps(data, indent=2, default=str))
        return
    rows = [[str(item.get(c, "") if not isinstance(item.get(c), (list, dict)) else
              (" ".join(map(str, item[c])) if isinstance(item[c], list)
               else " ".join(f"{k}:{v}" for k, v in sorted(item[c].items()))))
             for c in columns] for item in data]
    widths = [max(len(x) for x in col) for col in zip(columns, *rows)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*columns))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows:
        print(fmt.format(*row))


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Meraki Dashboard API helper.")
    parser.add_argument("--org", default=DEFAULT_ORG_ID, help=f"Organization ID (default: {DEFAULT_ORG_ID})")
    parser.add_argument("--json", action="store_true", help="Print raw JSON")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("sites", help="Every network with device counts and online count")
    p_dev = sub.add_parser("devices", help="Devices with status (optionally for one network)")
    p_dev.add_argument("--network", help="Network name (exact, or a unique substring)")
    p_dev.add_argument("--type", dest="product_type", help="appliance, switch, wireless, camera, cellularGateway...")
    sub.add_parser("offline", help="Devices whose status is not online")
    p_ssid = sub.add_parser("ssids", help="Enabled SSIDs and how many APs broadcast each")
    p_ssid.add_argument("--by-network", action="store_true", help="One row per network and SSID instead of totals per SSID")
    p_ssid.add_argument("--network", help="Only networks whose name contains this text")
    p_get = sub.add_parser("get", help="GET any API path, e.g. organizations/{org}/networks")
    p_get.add_argument("path", help="API path; {org} is replaced with the org ID")
    p_get.add_argument("-p", "--param", action="append", default=[], metavar="KEY=VALUE",
                       help="Query parameter; repeat for more. Use key[]=v for array params")
    p_get.add_argument("--one-page", action="store_true", help="Don't follow pagination")
    # Accept --json after the subcommand too (SUPPRESS keeps a --json given before it).
    for subparser in sub.choices.values():
        subparser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="print JSON")
    args = parser.parse_args()

    m = Meraki(org_id=args.org)

    if args.cmd == "sites":
        _print(m.sites(), args.json, ["name", "devices", "online", "by_type", "tags"])
    elif args.cmd in ("devices", "offline"):
        params: dict[str, Any] = {}
        net_names = {n["id"]: n["name"] for n in m.networks()}
        if getattr(args, "network", None):
            params["networkIds[]"] = m.network_by_name(args.network)["id"]
        if getattr(args, "product_type", None):
            params["productTypes[]"] = args.product_type
        rows = m.device_statuses(**params)
        if args.cmd == "offline":
            rows = [d for d in rows if d.get("status") != "online"]
        for d in rows:
            d["network"] = net_names.get(d.get("networkId"), d.get("networkId"))
        rows.sort(key=lambda d: (d["network"] or "", d.get("name") or ""))
        _print(rows, args.json, ["network", "name", "model", "serial", "status", "lanIp", "publicIp", "lastReportedAt"])
    elif args.cmd == "ssids":
        rows = m.ssid_usage()
        if args.network:
            rows = [r for r in rows if args.network.lower() in r["network"].lower()]
        if args.by_network or args.json:
            _print(rows, args.json, ["ssid", "network", "number", "authMode", "aps", "aps_online", "availableOnAllAps", "visible"])
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
            _print(summary, False, ["ssid", "networks", "aps", "aps_online", "authModes"])
    elif args.cmd == "get":
        params = dict(kv.split("=", 1) for kv in args.param)
        data = m.get(args.path, **params) if args.one_page else m.get_all(args.path, **params)
        _print(data, True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except MerakiError as exc:
        sys.exit(f"Meraki error: {exc}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
