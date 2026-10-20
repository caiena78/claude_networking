---
name: cisco-devices
description: Running read-only show commands on Cisco routers, switches and WLCs through cisco_helper.py - uptime, version, interfaces, errors, config sections, logs, CDP/LLDP, BGP/OSPF/EIGRP, ARP/MAC, CPU/memory, 9800 WLAN/SSID config, wireless clients, and route lookups ("show me routes for 10.x.x.x", "which router has a route to X", "where is X routed"). Also the VRF rules on the Lakeview/Lakeside/Tulane cores and how to add a platform. Use for anything run on a Cisco device over SSH.
---

# Cisco devices (cisco_helper.py)

**Use `cisco_helper.py` for anything run on a router or switch.** Never write ad-hoc netmiko or Python snippets. If a command or option is missing, add it to `cisco_helper.py` (the `COMMANDS` table), then use it. The helper reads the SSH credentials from Vault, finds devices through NetBox, runs on many devices at once, only sends single `show` commands (it refuses anything else and any `| redirect/tee/append/copy`), and masks passwords, keys, communities and hashes in config output.

**NETCONF first.** Before a command runs on an IOS/IOS-XE device, `cisco_helper.py` checks TCP 830. If it is open and the command has a NETCONF version, it queries over NETCONF (`get` only) and prints the same kind of table; otherwise it uses SSH. The header shows `[netconf]` or `[ssh]`, and `--json` has `transport`, `netconf_port` and, after a failed attempt, `netconf_error`. `--transport ssh` skips NETCONF, `--transport netconf` fails instead of falling back. Commands with a NETCONF version: `python netconf_helper.py list` (version, uptime, clock, interfaces, interface, errors, cpu, memory, arp, cdp, lldp, ntp, wlans). Everything else stays on SSH: `show "..."`, `run`, `section`, `log`, `route`, `locate`, `bgp`, `ospf`, `wclient`, `ssid`, `ssid-auth` (the YANG client model has no EAP type), `--parse`, AireOS WLCs and devices with 830 closed. NETCONF output is a rendered table, not the CLI text. `interface` over NETCONF needs the full interface name (`TenGigabitEthernet0/1/0`); abbreviations fall back to SSH. The WLAN PSK is returned in clear text by NETCONF, so the helper never selects it and masks it in `netconf_helper.py get`. Use `netconf_helper.py caps|get|schema` to explore a device's YANG models before adding a command.

Choosing devices (combine as needed; at most 25 by default, change with `--max-devices`):
- `-d <name|ip>` (repeatable). Names are looked up in NetBox (exact name, else name contains). IPs connect directly as `cisco_ios` (set `--device-type`).
- `--site <name or slug>`, e.g. `--site Lakeside`. `--tag <tag>`, e.g. `--tag wan_router`. `--name <text>`.
- Lakeside = `tls-*`, Lakeview = `lvr-*`, East Jefferson = `ej-*`, and so on (see `bgp_community.txt`).
- Virtual chassis (stacks) are one device, named after the chassis, connecting to the master's IP.

```
python cisco_helper.py list                                       # every built-in command
python cisco_helper.py uptime --site Lakeside --tag wan_router
python cisco_helper.py version -d tls-wan-rtr-01
python cisco_helper.py interfaces -d tls-wan-rtr-01               # show ip interface brief
python cisco_helper.py interface Te0/1/0 -d tls-wan-rtr-01
python cisco_helper.py errors -d tls-wan-rtr-01                   # CRC, input/output errors, drops
python cisco_helper.py section "router bgp" -d tls-wan-rtr-01     # config section, secrets masked
python cisco_helper.py run -d tls-wan-rtr-01                      # full running config, secrets masked
python cisco_helper.py log -d tls-wan-rtr-01 --lines 100
python cisco_helper.py bgp --tag wan_router                       # also ospf, eigrp, standby, vrrp
python cisco_helper.py cdp -d tls-wan-rtr-01                      # also cdp-detail, lldp
python cisco_helper.py arp 10.158.136.10 -d tls-wan-rtr-01        # also mac [mac]
python cisco_helper.py route 10.158.10.1                          # route lookup on all wan_router devices
python cisco_helper.py locate 10.158.0.139                        # IP -> switchport (see the device-lookup skill)
python cisco_helper.py cpu -d tls-wan-rtr-01                      # also memory, env, inventory, transceivers, ntp, clock, license, sla
python cisco_helper.py show "show ip nat translations total" -d tls-wan-rtr-01   # any single show command
python cisco_helper.py wlans -d lakeview-wlc-ha01                 # Catalyst 9800: WLAN/SSID summary
python cisco_helper.py ssid LCMC-DATA -d lakeview-wlc-ha01 -o lakeviewssid.txt   # all config for an SSID
python cisco_helper.py ssid LCMC-VOIP -d lakeview-wlc-ha01 -o lakeviewssid.txt --append
python cisco_helper.py ssid-count -d lakeview-wlc-ha01              # clients per SSID on a 9800 (fast: two commands); no -d = every 9800
python cisco_helper.py ssid-clients LCMC-IOTS -d <wlc> -o macs.txt   # client MACs on an SSID; then: python ordr_helper.py devices --macs-file macs.txt --limit 0 --summary (manufacturers, from Ordr)
python cisco_helper.py ssid-auth LCMC-VOIP                     # clients on an SSID by EAP type (PEAP vs EAP-TLS) on every 9800; add -d/--site to narrow
python cisco_helper.py wclient 78:02:8b:19:63:0e                  # wireless client on every WLC in NetBox (9800 + AireOS): AP, SSID, VLAN, IP, user
python cisco_helper.py wclient <mac> -d umc-wlc-8540-01            # one controller; anchor/foreign mobility is shown
```

- `-o FILE` also writes the results to a file (`--append` adds to it). Use it when the user asks for output in a file. `.gitignore` excludes `*.txt`.
- `ssid-auth <ssid>` (Catalyst 9800 only; AireOS is skipped) maps the SSID to its WLAN IDs, lists the clients on them and reads `EAP Type` from each client's detail, so it runs one command per client and is slow (about 3 minutes for 226 clients; use `--timeout`/`--workers` as needed). `--json` has `ssid_auth` per WLC. EAP type `Not Applicable` means no 802.1x EAP (e.g. PSK or a roaming/anchor stub). ISE gives the same split faster: `ise_helper.py active --protocols --ssid <ssid>`.
- `ssid <name>` (Catalyst 9800) matches the SSID or the WLAN profile name, so it handles one SSID on several profiles (e.g. LCMC-DATA = `LCMC-DATA_SBH` and `LCMC-DATA_profile`). For each profile it collects the `wlan` config, the policy tags that map it, each policy profile's config, and `show wlan name`. PSKs (`set-key`) are masked.
- 9800 WLCs are IOS-XE (`cisco_xe`) in NetBox, e.g. `lakeview-wlc-ha01` (10.158.8.21), `lakeview-wlc-stby`, `lakeview-wlc-guest01`.
- `--json` gives `[{device, host, site, command, output, error}]` (route lookups add `route_result`). `--parse` turns the output into structured data with TextFSM (ntc-templates) where a template exists, e.g. `interfaces --parse --json`.
- A device that rejects a command (`% Invalid input`) is reported as an error. One failing device never stops the others.
- Exit codes: 0 = every device answered, 1 = at least one failed, 2 = setup error. For `route <ip>`: 0 = found somewhere, 1 = found nowhere.
- Even with masking, quote only the config lines that answer the question.
- Run show commands only when the user asks for information from the devices, and keep to the devices the question needs.

## Answering route questions

Requests like "show me routes for 10.158.8.1", "where is 10.x.x.x routed" or "which router has a route to 10.158.8.0/24" mean:

```
python cisco_helper.py route <ip-or-prefix> --json
```

With no device options, this runs on every NetBox device tagged `wan_router`. Add `--site <name>`, `-d <device>` or `--vrf <name>` only when the user asks for them. On the Lakeview Hospital, Lakeside and Tulane cores, route lookups use VRF `buyer` automatically (see below), and each result's `vrf` says which VRF was used. In the JSON, each result's `route_result` is `found`, `not found` or `error`, and `output` holds the router's output. Found routes also have `route_detail`: `prefix`, `protocol`, `distance`, `metric` and `next_hops` (`next_hop`, `interface`, `active`). For recursive routes such as BGP, the helper looks up the route to the next hop on the same router to fill in the real outgoing interface, and records how it got there in `resolved_via` (e.g. `198.18.255.32/32 ospf 500 -> 198.18.0.30`). The text output's Summary shows all of this on one line per router.

To name the devices behind the destination and the next hops, look the IPs up in NetBox: `python netbox_helper.py ip <ip>` (device and interface) and `python netbox_helper.py prefix <ip>` (site, VLAN, VRF).

Then summarize for the user:
- which routers have the route, and for each one the matched prefix, the next hop, the outgoing interface, the protocol (BGP, OSPF, static, connected and so on) and the AD/metric if shown;
- whether any router only matched the default route (0.0.0.0/0), and say so explicitly;
- which routers did not have it, and any errors or skipped devices.

Show the full raw output only if the user asks for it (it is in `output`, or in the text sections above the Summary).

## VRFs on the cores

At **Lakeview Hospital, Lakeside and Tulane**, user and server subnets live in VRF **`buyer`**, and **only on the core switches** (NetBox role `Core`, e.g. `lv-mdf-core-9500(1)`, `ls-mdf-core-9500(1)`, `tul-mdf-core-9606(1)`). The WAN routers at those sites use the global table. `cisco_helper.py` handles this for you (`CORE_VRFS` in the code): route and ARP lookups on those cores use VRF `buyer` only and skip every other VRF, unless you pass `--vrf`. In the global table those cores show other routes, such as a static route to a firewall for the server VLAN, and those routes are wrong for this purpose. To add a site, add it to `CORE_VRFS`.

On those same cores, **VRF `div` and the global (default) table are for isolated networks**, which aren't routed to the WAN. `locate` looks there only after the normal trace finds nothing (`CORE_ISOLATED_VRFS`), and labels the result `isolated`. To look in one of them yourself, pass `--vrf div`, or `--vrf global` for the global table: `python cisco_helper.py route 10.67.240.11 -d "lv-mdf-core-9500(1)" --vrf global`.

## Adding a platform

1. `netbox_helper.py`: add the NetBox platform slug to `PLATFORM_MAP`, mapped to a netmiko device_type. Unknown slugs fall back to `cisco_ios`, with a warning. (AireOS WLCs, platform `airos`, map to `cisco_wlc_ssh`.)
2. `cisco_helper.py`: if the platform's route command differs, add a branch in `route_command()`. If its "not found" text is new, add it to `ROUTE_NOT_FOUND`. For other commands, add a platform column or override in `COMMANDS`.
3. Run `python -m pytest -q` after changing a parser.

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).
