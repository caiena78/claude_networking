"""Read-only access to Cisco ISE.

Credentials are the Vault secrets ise_url, ise_user and ise_password (see vault_helper.py).
ISE exposes three APIs, all with HTTP basic auth:

    ERS      https://<ise>:9060/ers/config/...    config objects: endpoints, network devices, groups, SGTs
    MnT      https://<ise>/admin/API/mnt/...      live sessions and recent authentications (XML)
    OpenAPI  https://<ise>/api/v1/...             deployment nodes, policy sets

The client only issues GET requests, so it can't change ISE config or send CoA/disconnects.

As a module:
    from ise_helper import ISE
    ise = ISE()
    ise.lookup("00:11:22:33:44:55")     # ERS endpoint + MnT session for a MAC
    ise.session("10.158.10.25")          # active session by MAC, IP or username
    ise.network_device("tls-wan-rtr-01")

From the command line:
    python ise_helper.py lookup 0011.2233.4455        # endpoint record + live session
    python ise_helper.py session 10.158.10.25          # by MAC, IP or username
    python ise_helper.py auth 00:11:22:33:44:55 --hours 24
    python ise_helper.py active --count
    python ise_helper.py nad 10.158.136.51             # network device by name or IP
    python ise_helper.py ers endpointgroup
    python ise_helper.py api deployment/node
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import quote, urlparse

import requests

SECRET_KEYS = ("ise_url", "ise_user", "ise_password")
ERS_PORT = 9060
ERS_PAGE_SIZE = 100  # ERS maximum
MAX_RETRIES = 5
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{4}(\.[0-9A-Fa-f]{4}){2}$|^[0-9A-Fa-f]{12}$")

SESSION_FIELDS = ["passed", "failure_reason", "calling_station_id", "user_name", "framed_ip_address", "network_device_name", "nas_ip_address",
                  "nas_port_id", "endpoint_policy", "identity_group", "selected_azn_profiles", "authentication_method",
                  "authentication_protocol", "posture_status", "cts_security_group", "acs_server", "acct_session_time",
                  "auth_acs_timestamp", "acs_timestamp", "nas_port_type"]


class ISEError(Exception):
    """An ISE API call failed (status, path and ISE's error text; never the credentials)."""


def normalize_mac(mac: str) -> str:
    """Return a MAC as uppercase AA:BB:CC:DD:EE:FF, the format ISE uses."""
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(digits) != 12:
        raise ISEError(f"{mac!r} is not a MAC address")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def is_mac(value: str) -> bool:
    return bool(MAC_RE.match(value.strip()))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def xml_to_dict(element: ET.Element) -> Any:
    """Convert an MnT XML element to dicts/lists/strings. Repeated child tags become lists."""
    children = list(element)
    if not children:
        return element.text.strip() if element.text and element.text.strip() else (dict(element.attrib) or None)
    result: dict[str, Any] = dict(element.attrib)
    for child in children:
        value = xml_to_dict(child)
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(value)
        else:
            result[child.tag] = value
    return result


class ISE:
    """Minimal read-only Cisco ISE client for the ERS, MnT and OpenAPI interfaces."""

    def __init__(self, url: str | None = None, user: str | None = None, password: str | None = None,
                 verify: bool | str | None = None, timeout: int = 60):
        if not all((url, user, password)):
            import vault_helper  # also turns on truststore, so an internal CA on ISE is trusted

            secrets = vault_helper.get_secret_values(SECRET_KEYS, interactive=False)
            url = url or secrets["ise_url"]
            user = user or secrets["ise_user"]
            password = password or secrets["ise_password"]
        if "://" not in url:
            url = f"https://{url}"
        self.host = urlparse(url).hostname
        self.timeout = timeout
        self.http = requests.Session()
        self.http.auth = (user, password)
        self.http.verify = verify if verify is not None else (os.environ.get("ISE_CACERT") or os.environ.get("LCMC_CACERT") or True)
        self._mnt_host: str | None = os.environ.get("ISE_MNT_HOST")

    @property
    def mnt_host(self) -> str:
        """The primary monitoring node. MnT calls only work there, not on the PAN in ise_url.
        Found from the deployment node list (or ISE_MNT_HOST); falls back to the PAN if there is no
        dedicated MnT node."""
        if not self._mnt_host:
            nodes = self.nodes()
            primary = next((n for n in nodes if any(r in ("PrimaryDedicatedMonitoring", "PrimaryMonitoring")
                                                    for r in n.get("roles", []))), None)
            self._mnt_host = (primary.get("fqdn") or primary.get("hostname")) if primary else self.host
        return self._mnt_host

    # -- core ---------------------------------------------------------------

    def _get(self, url: str, accept: str, params: dict | None = None) -> requests.Response:
        for attempt in range(MAX_RETRIES):
            try:
                resp = self.http.get(url, params=params, headers={"Accept": accept}, timeout=self.timeout)
            except requests.exceptions.SSLError:
                raise ISEError(f"TLS certificate for {urlparse(url).hostname} is not trusted. ISE uses LCMC's internal "
                               "CA (EPIC-CA); set LCMC_CACERT to its PEM file or install it as a trusted root") from None
            except requests.exceptions.ConnectionError as exc:
                hint = " (is ERS enabled on ISE? It listens on port 9060)" if f":{ERS_PORT}/" in url else ""
                raise ISEError(f"cannot connect to {urlparse(url).netloc}{hint}: {type(exc).__name__}") from None
            if resp.status_code == 429:
                time.sleep(float(resp.headers.get("Retry-After", 2 ** attempt)))
                continue
            if resp.status_code >= 400:
                where = urlparse(url).path
                if resp.status_code == 401:
                    if "/admin/API/mnt/" in url:
                        raise ISEError(f"401 on {where}: the ISE account isn't allowed to use the MnT API (its admin "
                                       "group needs MnT/Monitoring access). ERS and OpenAPI calls still work")
                    raise ISEError(f"401 on {where}: ISE rejected ise_user / ise_password from Vault")
                if resp.status_code == 403:
                    raise ISEError(f"403 on {where}: the ISE account lacks the admin role for this API "
                                   "(ERS Admin/Operator for ERS, MnT access for sessions)")
                raise ISEError(f"{resp.status_code} on {where}: {resp.text[:300]}")
            return resp
        raise ISEError(f"rate limited too many times on {urlparse(url).path}")

    def ers(self, path: str, **params: Any) -> Any:
        """GET an ERS path (relative to /ers/config/) and return the JSON."""
        url = path if path.startswith("http") else f"https://{self.host}:{ERS_PORT}/ers/config/{path.lstrip('/')}"
        return self._get(url, "application/json", params or None).json()

    def ers_search(self, resource: str, filter: str | list[str] | None = None, max_items: int | None = None,
                   **params: Any) -> list[dict]:
        """List ERS resources (id, name, description), following nextPage. filter uses ERS syntax,
        e.g. 'mac.EQ.AA:BB:CC:DD:EE:FF', 'name.CONTAINS.wan', 'ipaddress.EQ.10.1.1.1'."""
        query: dict[str, Any] = {"size": ERS_PAGE_SIZE, **params}
        if filter:
            query["filter"] = filter
        data = self.ers(resource, **query)
        items: list[dict] = []
        while True:
            result = data.get("SearchResult", {})
            items.extend(result.get("resources", []))
            if max_items and len(items) >= max_items:
                return items[:max_items]
            next_href = (result.get("nextPage") or {}).get("href")
            if not next_href:
                return items
            data = self.ers(next_href)

    def ers_get(self, resource: str, object_id: str) -> dict:
        """GET one ERS object by id and unwrap it (e.g. {'ERSEndPoint': {...}} -> {...})."""
        data = self.ers(f"{resource}/{object_id}")
        return next(iter(data.values())) if isinstance(data, dict) and len(data) == 1 else data

    def mnt(self, path: str) -> Any:
        """GET an MnT path (relative to /admin/API/mnt/) and return the parsed XML as dicts."""
        url = f"https://{self.mnt_host}/admin/API/mnt/{path.lstrip('/')}"
        text = self._get(url, "application/xml", None).text.strip()
        if not text:
            return None
        root = ET.fromstring(text)
        return {root.tag: xml_to_dict(root)}

    def api(self, path: str, **params: Any) -> Any:
        """GET an OpenAPI path (relative to /api/v1/) and return the JSON (unwrapping 'response')."""
        url = f"https://{self.host}/api/v1/{path.lstrip('/')}"
        data = self._get(url, "application/json", params or None).json()
        return data.get("response", data) if isinstance(data, dict) else data

    # -- endpoints and sessions ---------------------------------------------

    def endpoint(self, mac: str) -> dict | None:
        """The ERS endpoint record for a MAC (profile, identity group, static assignment, custom attributes)."""
        mac = normalize_mac(mac)
        found = self.ers_search("endpoint", filter=f"mac.EQ.{mac}")
        return self.ers_get("endpoint", found[0]["id"]) if found else None

    def session(self, value: str) -> dict | None:
        """The live MnT session for a MAC, IP address or username (None when there isn't one).

        ISE answers "no session" with HTTP 500 (cpm-code 34110) rather than 404, and its IP lookup
        fails the same way even for live sessions, so IPs are matched via the active-session list."""
        value = value.strip()
        if is_ip(value):
            match = next((s for s in self.active_sessions() if s.get("framed_ip_address") == value), None)
            return self.session(match["calling_station_id"]) if match and match.get("calling_station_id") else None
        path = (f"Session/MACAddress/{normalize_mac(value)}" if is_mac(value)
                else f"Session/UserName/{quote(value)}")
        try:
            data = self.mnt(path)
        except ISEError as exc:
            if str(exc).startswith("404") or (str(exc).startswith("500") and "34110" in str(exc)):
                return None
            raise
        return next(iter(data.values())) if data else None

    def auth_status(self, mac: str, hours: int = 24, records: int = 10) -> list[dict]:
        """Recent authentication records for a MAC (newest first). ISE allows up to 120 hours."""
        seconds = min(max(hours, 1), 120) * 3600
        data = self.mnt(f"AuthStatus/MACAddress/{normalize_mac(mac)}/{seconds}/{records}/All")
        # Shape: {"authStatusOutputList": {"authStatusList": {"key": mac, "authStatusElements": [...]}}}
        status_list = ((next(iter(data.values())) or {}).get("authStatusList") or {}) if data else {}
        rows = status_list.get("authStatusElements", []) if isinstance(status_list, dict) else []
        return rows if isinstance(rows, list) else [rows]

    def lookup(self, mac: str) -> dict:
        """Everything ISE knows about a MAC: ERS endpoint record plus the live session."""
        return {"endpoint": self.endpoint(mac), "session": self.session(mac)}

    def active_count(self) -> int:
        data = self.mnt("Session/ActiveCount")
        return int(next(iter(data.values()))["count"])

    def active_sessions(self, max_items: int | None = None) -> list[dict]:
        """Active sessions (user, MAC, NAS IP, framed IP). This can be large; use max_items."""
        data = self.mnt("Session/ActiveList")
        rows = (next(iter(data.values())) or {}).get("activeSession", []) if data else []
        rows = rows if isinstance(rows, list) else [rows]
        return rows[:max_items] if max_items else rows

    def session_protocols(self, workers: int = 8) -> dict[str, Any]:
        """Count active sessions by authentication protocol (EAP-TLS, PEAP, MAB...).

        The active list has no protocol field, so each session's detail is fetched by MAC."""
        from collections import Counter
        from concurrent.futures import ThreadPoolExecutor

        sessions = self.active_sessions()
        macs = [s.get("calling_station_id") for s in sessions if s.get("calling_station_id")]

        def detail(mac: str) -> tuple[str, str]:
            try:
                s = self.session(mac) or {}
            except ISEError:
                return ("(lookup failed)", "")
            return (s.get("authentication_protocol") or "(no session detail)", s.get("authentication_method") or "")

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            results = list(pool.map(detail, macs))
        return {
            "active_sessions": len(sessions),
            "looked_up": len(macs),
            "by_protocol": dict(Counter(p for p, _ in results).most_common()),
            "by_method": dict(Counter(m or "(none)" for _, m in results).most_common()),
        }

    # -- network devices and groups -----------------------------------------

    def network_device(self, value: str) -> list[dict]:
        """Network devices (NADs) by IP or by name substring, with full details."""
        value = value.strip()
        flt = f"ipaddress.EQ.{value}" if is_ip(value) else f"name.CONTAINS.{value}"
        return [self.ers_get("networkdevice", r["id"]) for r in self.ers_search("networkdevice", filter=flt, max_items=25)]

    def network_devices(self, name_contains: str | None = None, max_items: int | None = None) -> list[dict]:
        flt = f"name.CONTAINS.{name_contains}" if name_contains else None
        return self.ers_search("networkdevice", filter=flt, max_items=max_items)

    def endpoint_groups(self) -> list[dict]:
        return self.ers_search("endpointgroup")

    def identity_groups(self) -> list[dict]:
        return self.ers_search("identitygroup")

    def sgts(self) -> list[dict]:
        return self.ers_search("sgt")

    def authorization_profiles(self) -> list[dict]:
        return self.ers_search("authorizationprofile")

    def nodes(self) -> Any:
        return self.api("deployment/node")

    def policy_sets(self, device_admin: bool = False) -> Any:
        return self.api(f"policy/{'device-admin' if device_admin else 'network-access'}/policy-set")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print(data: Any, as_json: bool = True, columns: list[str] | None = None) -> None:
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


def _session_view(session: dict | None, full: bool) -> Any:
    if not session or full:
        return session
    return {k: session.get(k) for k in SESSION_FIELDS if session.get(k) not in (None, "")}


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Cisco ISE helper (ERS, MnT, OpenAPI).")
    parser.add_argument("--json", action="store_true", help="Print full records / raw JSON")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("lookup", help="Endpoint record + live session for a MAC")
    p.add_argument("mac")
    p = sub.add_parser("session", help="Live session by MAC, IP or username")
    p.add_argument("value")
    p = sub.add_parser("auth", help="Recent authentications for a MAC")
    p.add_argument("mac")
    p.add_argument("--hours", type=int, default=24, help="Look back this many hours (max 120, default 24)")
    p.add_argument("--records", type=int, default=10, help="Max records (default 10)")
    p = sub.add_parser("active", help="Active sessions")
    p.add_argument("--count", action="store_true", help="Only print the number of active sessions")
    p.add_argument("--protocols", action="store_true",
                   help="Count active sessions by auth protocol (EAP-TLS, PEAP...) and method (dot1x, mab)")
    p.add_argument("--limit", type=int, default=50, help="Max sessions to print (default 50; 0 = all)")
    p = sub.add_parser("nad", help="Network device(s) by IP or name substring")
    p.add_argument("value")
    p = sub.add_parser("nads", help="List network devices (id, name)")
    p.add_argument("--name", help="Only names containing this text")
    p.add_argument("--limit", type=int, default=0, help="Max devices (default all)")
    sub.add_parser("groups", help="Endpoint identity groups")
    sub.add_parser("nodes", help="ISE deployment nodes (OpenAPI)")
    p = sub.add_parser("policy-sets", help="Policy sets (OpenAPI)")
    p.add_argument("--device-admin", action="store_true", help="TACACS device-admin policy sets instead of network access")
    p = sub.add_parser("ers", help="GET any ERS resource, e.g. endpointgroup, sgt, internaluser")
    p.add_argument("resource")
    p.add_argument("-f", "--filter", action="append", help="ERS filter, e.g. name.CONTAINS.wan (repeatable)")
    p.add_argument("--id", help="Get one object by id instead of listing")
    p = sub.add_parser("mnt", help="GET any MnT path, e.g. Session/ActiveCount")
    p.add_argument("path")
    p = sub.add_parser("api", help="GET any OpenAPI path, e.g. deployment/node")
    p.add_argument("path")
    # Accept --json after the subcommand too (SUPPRESS keeps a --json given before it).
    for subparser in sub.choices.values():
        subparser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="print JSON")
    args = parser.parse_args()

    ise = ISE()
    if args.cmd == "lookup":
        result = ise.lookup(args.mac)
        result["session"] = _session_view(result["session"], args.json)
        _print(result)
    elif args.cmd == "session":
        _print(_session_view(ise.session(args.value), args.json))
    elif args.cmd == "auth":
        rows = ise.auth_status(args.mac, args.hours, args.records)
        _print(rows if args.json else [_session_view(r, False) for r in rows])
    elif args.cmd == "active":
        if args.count:
            print(ise.active_count())
        elif args.protocols:
            _print(ise.session_protocols())
        else:
            _print(ise.active_sessions(args.limit or None), args.json,
                   ["user_name", "calling_station_id", "framed_ip_address", "nas_ip_address", "server"])
    elif args.cmd == "nad":
        _print(ise.network_device(args.value))
    elif args.cmd == "nads":
        _print(ise.network_devices(args.name, args.limit or None), args.json, ["name", "description", "id"])
    elif args.cmd == "groups":
        _print(ise.endpoint_groups(), args.json, ["name", "description", "id"])
    elif args.cmd == "nodes":
        _print(ise.nodes())
    elif args.cmd == "policy-sets":
        _print(ise.policy_sets(args.device_admin))
    elif args.cmd == "ers":
        _print(ise.ers_get(args.resource, args.id) if args.id else ise.ers_search(args.resource, filter=args.filter),
               args.json or bool(args.id), ["name", "description", "id"])
    elif args.cmd == "mnt":
        _print(ise.mnt(args.path))
    elif args.cmd == "api":
        _print(ise.api(args.path))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ISEError as exc:
        sys.exit(f"ISE error: {exc}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
