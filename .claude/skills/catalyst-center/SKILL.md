---
name: catalyst-center
description: Cisco Catalyst Center (DNA Center) through catalyst_helper.py: managed switches/routers/WLCs/APs (version, serial, reachability), interfaces, collected configs, sites, site and device health, assurance issues, and where a client MAC is connected.
---

# Cisco Catalyst Center

Use Catalyst Center (formerly DNA Center) for questions about **managed network devices and assurance**: the inventory of switches, routers, WLCs and APs (hostname, management IP, model, software version, serial, reachability, uptime), device interfaces, the running config Catalyst Center has collected, the site hierarchy, site and device health, assurance issues, and client details such as where a MAC is connected. ISE covers authentication, Ordr covers what an endpoint is, Meraki covers Meraki networks, and `cisco_helper.py route` gives live routing from the WAN routers.

**Always use `catalyst_helper.py` for Catalyst Center.** Don't write ad-hoc `requests` calls. It reads `cat_url`, `cat_user` and `cat_password` from Vault in one call. It gets an auth token (`POST /dna/system/api/v1/auth/token`, the only non-GET call it makes), sends it as `X-Auth-Token`, refreshes it on 401 (tokens last about an hour), pages with `offset` (starting at 1) and `limit` (max 500), and retries on 429. Paths without a `dna/` prefix are treated as relative to `dna/intent/api/v1/`.

Command line (start with these):

```
python catalyst_helper.py count                              # devices in inventory
python catalyst_helper.py devices --family "Switches and Hubs" --limit 50   # family must be the exact name
python catalyst_helper.py devices --hostname "TLS-.*"        # case-sensitive; .* wildcards work
python catalyst_helper.py devices --reachability Unreachable
python catalyst_helper.py device tls-wan-rtr-01              # by hostname, management IP, serial or id
python catalyst_helper.py interfaces 10.158.136.51           # interfaces of one device
python catalyst_helper.py config tls-wan-rtr-01              # running config as collected by Catalyst Center
python catalyst_helper.py client 00:11:22:33:44:55           # connected AP/switch + interface, IP, SSID, VLAN, health
python catalyst_helper.py sites [--name Global/UMC]
python catalyst_helper.py health                             # site health
python catalyst_helper.py device-health --health POOR
python catalyst_helper.py issues --priority P1               # active assurance issues
python catalyst_helper.py get network-device/count           # any Intent API path
python catalyst_helper.py get network-device -p family=Switches --all
```

- **Hostname filters are case-sensitive**, and only `.*` wildcards work (no `(?i)` or `[Aa]`). LCMC hostnames are mostly uppercase, and some include the domain (`TLS-WAN-RTR-01.lcmchealth.org`, `TLS-WAN-DIS-01`), so use uppercase in `--hostname` filters, e.g. `"TLS-.*"`. `device <name>` handles this for you: it tries the name as typed, in uppercase and in lowercase, exact then with `.*`, and then falls back to serial number. Commands that need exactly one device (`interfaces`, `config`) fail and list the matches if the name is ambiguous.
- `devices` filters: `--hostname`, `--family` (e.g. `Switches and Hubs`, `Routers`, `Wireless Controller`, `Unified AP`), `--role`, `--platform`, `--version`, `--reachability`, `--location`. For other filters, use `get network-device -p <param>=<value>`.
- Add `--json` for full records. `config` and `get` always print raw output.
- `client <mac>` uses the assurance data API (`dna/data/api/v1/clients`) and takes a MAC in any format. It prints `null` when Catalyst Center has no assurance data for the client. That's common for wired PCs. In that case, try Meraki, or Ordr's `device <mac> --include connectivity-info`. Assurance sees about 18,000 clients, mostly wireless.
- `config` returns a full running config, which includes credential hashes and keys. Read it to answer questions, but only quote the relevant lines, and never repeat secrets, keys or hashes from it.
- Catalyst Center is `ej-dnac-01.lcmchealth.org`, with about 4,775 devices and 80 sites (tested 2026-10-09) (certificate also valid for `dnac.lcmchealth.org`). **TLS:** its certificate is issued by `EPIC-ICA02` under LCMC's root `EPIC-CA`, the same root as ISE. See "LCMC internal CA" under Setup.

In Python:

```python
from catalyst_helper import Catalyst

cc = Catalyst()
cc.device_count(); cc.devices(max_items=100, family="Switches and Hubs"); cc.device("tls-wan-rtr-01")
cc.interfaces("10.158.136.51"); cc.interface_by_ip("10.143.100.18"); cc.device_config("tls-wan-rtr-01")
cc.client("00:11:22:33:44:55"); cc.clients(max_items=100, type="Wireless"); cc.client_health()
cc.sites(); cc.site_health(); cc.device_health(health="POOR"); cc.issues(priority="P1", issueStatus="ACTIVE")
cc.get("network-device/count"); cc.get_all("network-device", max_items=1000, platformId="C9300-48P")
```

Summarize the results for the user. Show raw JSON only when they ask for it.

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).
