---
name: cisco-devices
description: Running read-only commands on Cisco routers, switches and WLCs through cisco_helper.py (NETCONF first, then SSH) - uptime, version, interfaces, errors, config sections, logs, CDP/LLDP, BGP/OSPF/EIGRP, ARP/MAC, CPU/memory; route lookups ("where is 10.x.x.x routed"); 9800 and AireOS WLC SSIDs, client counts, client MACs, EAP-TLS vs PEAP, wireless clients; the VRF rules on the Lakeview/Lakeside/Tulane cores; NETCONF/YANG queries; adding a platform. Use for anything run on a Cisco device.
---

# Cisco devices (cisco_helper.py)

**Use `cisco_helper.py` for anything run on a router, switch or WLC.** Never write ad-hoc netmiko or Python snippets. If a command or option is missing, add it (the `COMMANDS` table, `AIREOS_COMMANDS`, or `RENDERERS` in `netconf_helper.py`), test it, document it, then use it. The helper reads the credentials from Vault, finds devices through NetBox, runs on many devices at once, only sends single `show` commands over SSH and NETCONF `get`s (it refuses anything else and any `| redirect/tee/append/copy`), and masks passwords, keys, communities and hashes in config output.

**Read the reference when the task needs it:**
- `references/netconf.md`: how NETCONF-first works, which commands have a NETCONF version, exploring YANG models, adding one.
- `references/wireless.md`: 9800 and AireOS WLCs. SSID lists and counts, client MACs, EAP type, manufacturers, SSID config, wireless client lookup, AireOS commands, `--cache`.
- `references/routes.md`: how to answer "where is X routed" and summarize it; the `buyer`, `div` and global VRFs on the Lakeview, Lakeside and Tulane cores.

Choosing devices (combine as needed; at most 25 by default, change with `--max-devices`):
- `-d <name|ip>` (repeatable). Names are looked up in NetBox (exact name, else name contains). IPs connect directly as `cisco_ios` (set `--device-type`, e.g. `cisco_xe` or `cisco_wlc_ssh`).
- `--site <name or slug>`, `--tag <tag>` (e.g. `wan_router`), `--name <text>`.
- Lakeside = `tls-*`, Lakeview = `lvr-*`, East Jefferson = `ej-*`, and so on (see `bgp_community.txt`). Virtual chassis (stacks) are one device, named after the chassis, connecting to the master's IP.

```
python cisco_helper.py list                                       # every built-in command
python cisco_helper.py uptime --site Lakeside --tag wan_router    # also version, clock, cpu, memory, env, inventory, ntp, license
python cisco_helper.py interfaces -d tls-wan-rtr-01               # also interface <name>, errors, status, desc, transceivers
python cisco_helper.py section "router bgp" -d tls-wan-rtr-01     # config section, secrets masked; run = full config
python cisco_helper.py log -d tls-wan-rtr-01 --lines 100
python cisco_helper.py bgp --tag wan_router                       # also ospf, eigrp, standby, vrrp
python cisco_helper.py cdp -d tls-wan-rtr-01                      # also cdp-detail, lldp
python cisco_helper.py arp 10.158.136.10 -d tls-wan-rtr-01        # also mac [mac]
python cisco_helper.py route 10.158.10.1                          # route lookup on all wan_router devices
python cisco_helper.py locate 10.158.0.139                        # IP -> switchport (see the device-lookup skill)
python cisco_helper.py show "show ip nat translations total" -d tls-wan-rtr-01   # any single show command
python cisco_helper.py ssid-count -d <wlc>                        # WLC SSIDs and client counts (more in references/wireless.md)
```

- `-o FILE` also writes the results to a file (`--append` adds to it). `.gitignore` excludes `*.txt`.
- `--json` gives `[{device, host, site, command, output, error}]` (route lookups add `route_result`; `transport` says netconf or ssh). `--parse` turns SSH output into structured data with TextFSM where a template exists, e.g. `interfaces --parse --json`.
- A device that rejects a command (`% Invalid input`) is reported as an error. One failing device never stops the others.
- Exit codes: 0 = every device answered, 1 = at least one failed, 2 = setup error. For `route <ip>`: 0 = found somewhere, 1 = found nowhere.
- Even with masking, quote only the config lines that answer the question. Run commands only when the user asks for information from the devices, and keep to the devices the question needs.

## Adding a platform

1. `netbox_helper.py`: add the NetBox platform slug to `PLATFORM_MAP`, mapped to a netmiko device_type. Unknown slugs fall back to `cisco_ios`, with a warning. (AireOS WLCs, platform `airos`, map to `cisco_wlc_ssh`.)
2. `cisco_route.py`: if the platform's route command differs, add a branch in `route_command()`. If its "not found" text is new, add it to `ROUTE_NOT_FOUND`. In `cisco_helper.py`, for other commands, add a platform column or override in `COMMANDS`.
3. Run `python -m pytest -q` after changing a parser.

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).
