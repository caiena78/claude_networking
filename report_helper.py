"""Daily network health brief from every system, in one report. Read-only.

    python report_helper.py daily                     # print the brief
    python report_helper.py daily -o brief.txt        # also save it
    python report_helper.py daily --no-cdo            # skip CDO (it runs with YOUR personal CDO key)
    python report_helper.py daily --json

Sections (each one is skipped with a note if that system is unreachable):
    Meraki    devices offline / alerting, WAN uplinks down, AutoVPN networks with unreachable peers,
              critical assurance alerts, subscriptions that aren't active
    Catalyst  unreachable devices, active P1 / P2 assurance issues
    ISE       active session count
    CDO       managed firewalls whose health isn't green

To run it every morning on Windows, a Task Scheduler action like:
    python <repo>\\report_helper.py daily -o <somewhere>\\brief-%date%.txt
It runs as the person who scheduled it (their Vault login, and their CDO key unless --no-cdo).
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from helper_common import Out, table, to_json


def _try(label: str, fn, errors: list[str]):
    try:
        return fn()
    except SystemExit as exc:
        errors.append(f"{label}: {exc}")
    except Exception as exc:  # noqa: BLE001 - one system down must not stop the brief
        errors.append(f"{label}: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}")
    return None


def meraki_section() -> dict[str, Any]:
    from meraki_helper import Meraki

    m = Meraki()
    names = m.network_names()
    statuses = m.device_statuses()
    counts: dict[str, int] = {}
    for d in statuses:
        counts[d.get("status") or "?"] = counts.get(d.get("status") or "?", 0) + 1
    down = [{"network": names.get(d.get("networkId"), ""), "name": d.get("name") or d["serial"], "model": d.get("model"),
             "status": d.get("status"), "lastReportedAt": d.get("lastReportedAt")}
            for d in statuses if d.get("status") in ("offline", "alerting")]
    uplinks = [{"network": names.get(u.get("networkId"), ""), "model": u.get("model"), "interface": up.get("interface"),
                "status": up.get("status"), "ip": up.get("ip")}
               for u in m.uplink_statuses() for up in u.get("uplinks") or []
               if up.get("status") not in ("active", "ready", "not connected")]
    vpn = []
    for v in m.vpn_statuses():
        if v.get("deviceStatus") != "online":
            continue  # offline MXs are already in the device list
        bad = [p.get("networkName") for p in v.get("merakiVpnPeers") or [] if p.get("reachability") != "reachable"]
        if bad:
            vpn.append({"network": v.get("networkName"), "unreachable": bad})
    week = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    alerts = [{"startedAt": a.get("startedAt"), "network": (a.get("network") or {}).get("name"), "title": a.get("title"),
               "devices": [d.get("name") or d.get("serial") for d in (a.get("scope") or {}).get("devices") or []]}
              for a in m.assurance_alerts(active="true", severity="critical") if (a.get("startedAt") or "") >= week]
    subs = [{"name": s.get("name"), "status": s.get("status"), "endDate": s.get("endDate")}
            for s in m.subscriptions() if s.get("status") != "active"]
    return {"counts": counts, "down": down, "uplinks": uplinks, "vpn": vpn, "alerts": alerts, "subscriptions": subs}


def catalyst_section() -> dict[str, Any]:
    from catalyst_helper import Catalyst

    cc = Catalyst()
    unreachable = [{"hostname": d.get("hostname"), "ip": d.get("managementIpAddress"), "family": d.get("family"),
                    "platform": d.get("platformId")}
                   for d in cc.devices(max_items=None, reachabilityStatus="Unreachable")]
    issues = {}
    for prio in ("P1", "P2"):
        issues[prio] = [{"name": i.get("name"), "role": i.get("deviceRole"), "last": i.get("last_occurence_time"),
                         "device": i.get("deviceId")} for i in cc.issues(priority=prio, issueStatus="ACTIVE")]
    return {"total": cc.device_count(), "unreachable": unreachable, "issues": issues}


def ise_section() -> dict[str, Any]:
    from ise_helper import ISE

    return {"active_sessions": ISE().active_count()}


def cdo_section() -> dict[str, Any]:
    import cdo_helper

    devs = cdo_helper.client().devices()
    return {"total": len(devs), "not_green": [{"name": d.get("name"), "health": d.get("healthStatus"),
                                               "model": d.get("model"), "version": d.get("sw_version")}
                                              for d in devs if d.get("healthStatus") != "green"]}


def daily(include_cdo: bool = True, log=None) -> dict[str, Any]:
    log = log or (lambda msg: None)
    errors: list[str] = []
    res: dict[str, Any] = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M"), "errors": errors}
    for name, fn in (("meraki", meraki_section), ("catalyst", catalyst_section), ("ise", ise_section)) + \
                    ((("cdo", cdo_section),) if include_cdo else ()):
        log(name)
        res[name] = _try(name, fn, errors)
    return res


def _ms(value) -> str:
    """Catalyst timestamps are epoch milliseconds."""
    try:
        return datetime.fromtimestamp(int(value) / 1000, timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    except (TypeError, ValueError):
        return str(value or "")


def _issue_kind(name: str) -> str:
    """An issue title with the device / interface names taken out, so the same kind groups together."""
    import re

    if re.fullmatch(r"\S+ Health Degradation", name or ""):
        return "Application health degradation (any app)"
    name = re.sub(r'"[^"]*"', '"..."', name or "")
    name = re.sub(r"\bon (AP |Switch |WLC )?[\w.:/()-]+\.?$", "on ...", name)
    return re.sub(r"\(Interface description: [^)]*\)?", "", name).strip()


def print_daily(r: dict, out: Out) -> None:
    flags = 0
    out.add(f"NETWORK DAILY BRIEF  {r['generated']}")
    m = r.get("meraki")
    if m:
        c = m["counts"]
        flags += len(m["down"]) + len(m["uplinks"]) + len(m["vpn"]) + len(m["alerts"]) + len(m["subscriptions"])
        out.add(f"\nMERAKI  devices: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
        if m["down"]:
            out.section(f"Meraki devices offline or alerting ({len(m['down'])})",
                        table(sorted(m["down"], key=lambda d: (d["network"], d["name"])),
                              ["network", "name", "model", "status", "lastReportedAt"]))
        if m["uplinks"]:
            out.section(f"WAN uplinks down ({len(m['uplinks'])})", table(m["uplinks"], ["network", "model", "interface", "status", "ip"]))
        if m["vpn"]:
            out.section(f"Online MXs with unreachable AutoVPN peers ({len(m['vpn'])})", table(m["vpn"], ["network", "unreachable"]))
        if m["alerts"]:
            out.section(f"Critical assurance alerts started in the last 7 days ({len(m['alerts'])})",
                        table(m["alerts"], ["startedAt", "network", "title", "devices"]))
        if m["subscriptions"]:
            out.section("Meraki subscriptions that aren't active", table(m["subscriptions"], ["name", "status", "endDate"]))
    cat = r.get("catalyst")
    if cat:
        flags += sum(1 for d in cat["unreachable"] if d["family"] != "Unified AP") + len(cat["issues"]["P1"])
        out.add(f"\nCATALYST CENTER  devices: {cat['total']}, unreachable: {len(cat['unreachable'])}, "
                f"active P1 issues: {len(cat['issues']['P1'])}, P2: {len(cat['issues']['P2'])}")
        infra = [d for d in cat["unreachable"] if d["family"] != "Unified AP"]
        aps = len(cat["unreachable"]) - len(infra)
        if infra:
            out.section(f"Unreachable switches, routers and WLCs ({len(infra)})",
                        table(sorted(infra, key=lambda d: d["hostname"] or ""), ["hostname", "ip", "family", "platform"]))
        if aps:
            out.add(f"Unreachable access points: {aps} (list them with: catalyst_helper.py devices "
                    f"--family \"Unified AP\" --reachability Unreachable)")
        if cat["issues"]["P1"]:
            out.section(f"Active P1 issues ({len(cat['issues']['P1'])})",
                        table([{**i, "last": _ms(i["last"])} for i in cat["issues"]["P1"]], ["last", "name"], width=110))
        if cat["issues"]["P2"]:
            kinds: dict[str, int] = {}
            for i in cat["issues"]["P2"]:
                kinds[_issue_kind(i["name"])] = kinds.get(_issue_kind(i["name"]), 0) + 1
            out.section(f"Active P2 issues by type ({len(cat['issues']['P2'])})",
                        table([{"count": n, "type": k} for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])],
                              ["count", "type"], width=100))
    if r.get("ise"):
        out.add(f"\nISE  active sessions: {r['ise']['active_sessions']}")
    cdo = r.get("cdo")
    if cdo:
        flags += len(cdo["not_green"])
        out.add(f"\nCDO  firewalls: {cdo['total']}, not green: {len(cdo['not_green'])}")
        if cdo["not_green"]:
            out.add(table(cdo["not_green"], ["name", "health", "model", "version"]))
    for e in r["errors"]:
        out.add(f"\n! {e}")
    out.add(f"\nItems needing attention: {flags}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Daily network health brief (read-only).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("daily", help="one report across Meraki, Catalyst Center, ISE and CDO")
    p.add_argument("--no-cdo", action="store_true", help="skip CDO (it uses your personal CDO key)")
    p.add_argument("--json", action="store_true")
    p.add_argument("-o", "--output", help="also write the brief to this file")
    p.add_argument("--append", action="store_true")
    args = ap.parse_args()

    out = Out()
    r = daily(include_cdo=not args.no_cdo, log=lambda msg: print(f"... {msg}", file=sys.stderr))
    out.add(to_json(r)) if args.json else print_daily(r, out)
    out.save(args.output, args.append)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
