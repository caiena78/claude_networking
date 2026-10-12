# claude-network

Network operations toolkit for LCMC Health. It answers questions about routers, switches, WLCs, sites, IPs and endpoints using NetBox (inventory), the devices themselves over SSH, Catalyst Center, ISE, Meraki and Ordr. All credentials come from HashiCorp Vault.

## Ground rules (read first)

1. **Every task goes through a `*_helper.py` script.** For anything the user asks, use the matching helper. **If the helper can't do what's needed, update the helper first.** Add the command or option, test it read-only, document it in this file, then use it to do the task. Never work around a helper with ad-hoc Python, netmiko or `requests` snippets.
2. **NetBox is the inventory.** Use `netbox_helper.py` (or `cisco_helper.py`, which resolves devices through NetBox) to find devices, sites, management IPs, roles, models, serials, IP assignments and prefixes. Catalyst Center, ISE, Meraki and Ordr have their own device lists. Use them for their own data (assurance, sessions, Meraki networks, endpoint identity), not as the inventory. If they disagree with NetBox, say so; don't silently prefer them.

```
python netbox_helper.py sites --name Lake
python netbox_helper.py devices --site Lakeside [--tag wan_router] [--role wan] [--name wlc]
python netbox_helper.py device lakeview-wlc-ha01        # full record: site, role, model, serial, platform, primary IP, tags
python netbox_helper.py ip 10.158.8.21                  # which device and interface has an IP
python netbox_helper.py prefix 10.158.10.25             # prefixes (site, VLAN, VRF, role) containing an IP
python netbox_helper.py prefixes --site Tulane [--vlan 700] [--vrf buyer] [--search text]   # subnet -> site list
python netbox_helper.py tags
```

`--site` accepts a site name, a slug or a unique part of a name. `--json` gives full output.

3. **Look devices up in the order below** (see "Finding a device").
4. **Don't use the `netbox-netmiko-mcp` MCP tools** (`mcp__netbox-netmiko-mcp__*`), even if they're connected. That server is abandoned, and this repo replaces it. Use the helpers.

## Finding a device

Pick the path by what the user gives you and what kind of device it is.

**A Cisco network device** (router, switch, WLC, core, WAN router), by name, IP, site or role: **use NetBox.**

```
python netbox_helper.py device <name>          # or: devices --site X --role Core, ip <mgmt-ip>
```

Use Catalyst Center or Meraki for a Cisco device only for their own data (health, assurance, Meraki status), not to find it.

**A non-Cisco device or endpoint** (PC, printer, phone, medical or IoT device, server), by MAC, name or IP. Try the helpers **in this order**, and stop at the first one that knows the device. Use the later ones only for what the first can't tell you:

1. **Ordr**: what the device is (group, profile, maker, model, OS, risk) and where Ordr last saw it.
   `python ordr_helper.py device <mac|ip|name> [--include connectivity-info]`
2. **ISE**: whether and how it authenticates, its live session, and the switch/port or WLC it authenticated through.
   `python ise_helper.py lookup <mac>`, `python ise_helper.py session <mac|ip>`, `python ise_helper.py auth <mac>`
3. **Catalyst Center**: assurance data on where it is connected (AP or switch and interface, SSID, VLAN, health).
   `python catalyst_helper.py client <mac>`

If none of them has it, or the IP is in a Meraki site (NetBox prefix site `Cisco Meraki`, or the `PUC_*`, `LRPG *`, `CHMPC *` and `CC_*` networks), use `python meraki_helper.py client <mac|ip>`.

**Finding the switchport for an IP** ("where is 10.x.x.x plugged in", "what port is this IP on"): trace it through the network with `cisco_helper.py locate`:

```
python cisco_helper.py locate <ip>                         # full trace; --json for every step
python cisco_helper.py locate <mac> -d <router or switch>  # MAC trace from a starting device (e.g. the core)
```

`locate` does what you would do by hand, using only `show` commands:

1. **NetBox** `prefix <ip>`: the subnet, its site, VLAN and VRF. NetBox's prefix list is the subnet-to-site map, and `netbox_helper.py prefixes --site X` lists a site's subnets. A subnet can appear twice, once with the site in the global VRF and once in VRF `buyer` with no site, and the helper takes the site from the row that has one. `ip <ip>`: whether the IP is assigned to a device.
2. **Route lookup on the `wan_router` devices** at that site (or on every `wan_router` if the site has none, or none of them has a specific route, because NetBox's site can be stale). Then follow the next hop router by router, finding each next hop's device in NetBox, until a device has the subnet **directly connected**. That device is the gateway, usually the site core.
3. **`show ip arp <ip>`** on the gateway gives the MAC and the SVI.
   If that finds nothing, the subnet may be an **isolated network**. The helper then asks the cores at Lakeview Hospital, Lakeside and Tulane directly in VRF `div` and in the global table, starting with NetBox's site (see "VRFs on the cores").
4. **`show mac address-table address <mac>`** gives the port. If the port is a port-channel, the helper finds its members (`show etherchannel summary`). **`show cdp neighbors <port> detail`** shows what is on that port. If it is another Cisco switch, the helper connects to it (looked up by name in NetBox, else by its CDP IP) and repeats. The trace stops at the first port with no switch behind it, the access port, and shows it with `show interfaces <port> status`.

It reports the gateway, the MAC (Cisco and colon formats), each L2 hop and the final switch, port, VLAN and port status. Its notes cover the cases where the trace stops early:
- **IP phone** on the port: the host is behind the phone.
- **AP** on the port: the host is a wireless client. Use ISE `auth <mac>` or Catalyst `client <mac>`.
- **Meraki** device: continue with `meraki_helper.py client <mac>`.
- A next hop that doesn't answer SSH (a firewall or a non-Cisco device): get the MAC from Ordr or ISE, then run `locate <mac> -d <last router>`.
- An ARP entry with no MAC-table entry: the host has been idle, so try again later.
- **Isolated network**: the subnet is in VRF `div` or the global table on a core and isn't routed to the WAN.
- **NetBox site mismatch**: the device that really has the subnet is at a different site than NetBox says. Tell the user, because NetBox's prefix record needs fixing.

Then take the MAC to Ordr or ISE to say what the device is. Exit codes: 0 = switchport found, 1 = not found, 2 = setup error.

**VRFs on the cores:** at **Lakeview Hospital, Lakeside and Tulane**, user and server subnets live in VRF **`buyer`**, and **only on the core switches** (NetBox role `Core`, e.g. `lv-mdf-core-9500(1)`, `ls-mdf-core-9500(1)`, `tul-mdf-core-9606(1)`). The WAN routers at those sites use the global table. `cisco_helper.py` handles this for you (`CORE_VRFS` in the code): route and ARP lookups on those cores use VRF `buyer` only and skip every other VRF, unless you pass `--vrf`. In the global table those cores show other routes, such as a static route to a firewall for the server VLAN, and those routes are wrong for this purpose. To add a site, add it to `CORE_VRFS`.

On those same cores, **VRF `div` and the global (default) table are for isolated networks**, which aren't routed to the WAN. `locate` looks there only after the normal trace finds nothing (`CORE_ISOLATED_VRFS`), and labels the result `isolated`. To look in one of them yourself, pass `--vrf div`, or `--vrf global` for the global table: `python cisco_helper.py route 10.67.240.11 -d "lv-mdf-core-9500(1)" --vrf global`.

## Files

| File | Role |
|---|---|
| `cisco_helper.py` | Read-only show commands on Cisco devices over SSH (uptime, interfaces, config sections, logs, neighbors, BGP/OSPF/EIGRP, ARP/MAC, CPU/memory, route lookups and any `show` command), plus `locate <ip\|mac>` (traces an IP to its switchport). Use it for everything run on a device |
| `vault_helper.py` | Vault login (token from `VAULT_TOKEN`, then `~/.vault-token`, then OIDC browser login), `get_secrets()` (router and NetBox credentials) and `get_secret(key)` (any one key, e.g. `meraki_api`) |
| `netbox_helper.py` | **The inventory.** CLI: `sites`, `devices`, `device`, `ip`, `prefix`, `prefixes`, `tags`. Also `get_devices()` (used by `cisco_helper.py`) and `PLATFORM_MAP` (NetBox platform slug to netmiko device_type) |
| `catalyst_helper.py` | Read-only Cisco Catalyst Center (DNA Center) client and CLI (`devices`, `device`, `count`, `interfaces`, `config`, `client`, `sites`, `health`, `device-health`, `issues`, `get <path>`). Use it for all Catalyst Center access |
| `ise_helper.py` | Read-only Cisco ISE client and CLI for the ERS, MnT and OpenAPI interfaces (`lookup`, `session`, `auth`, `active`, `nad`, `nads`, `groups`, `nodes`, `policy-sets`, `ers`, `mnt`, `api`). Use it for all ISE access |
| `ordr_helper.py` | Read-only Ordr SCE REST API client and CLI (`device`, `devices`, `alarms`, `vulns`, `summary`, `reports`, `report`, `get <path>`). Use it for all Ordr access |
| `meraki_helper.py` | Read-only Meraki Dashboard API client and CLI: inventory (`sites`, `devices`, `aps`, `device`, `inventory`, `licenses`, `firmware`), clients (`clients`, `client`, `top`), wireless (`ssids`, `ssid`, `wifi-health`, `air-marshal`), MX (`uplinks`, `vpn`, `vlans`, `routes`, `firewall`, `security`, `appliance`), switches (`ports`, `switch`), audit (`events`, `alerts`, `changes`, `admins`) and `get <path>`. Secrets are masked. Use it for all Meraki access |
| `bgp_community.py` | Reads each router's BGP outbound route-map (`set community`) and writes `bgp_community.txt` (site, router, IP, AS, community) |
| `vault_login.ps1` / `vault_login.sh` | Vault OIDC login in a private browser window (Windows / macOS and Linux). The token is never printed. Both also save `VAULT_ADDR` from `.env` permanently, writing it only when it changes. `vault_login.ps1` sets a user environment variable (`-NoPersist` skips this), so `set_vault_addr.ps1` is no longer needed. `vault_login.sh` writes one `export VAULT_ADDR=...  # set by vault_login.sh` line to `~/.zshrc`, `~/.bash_profile` (macOS bash), `~/.bashrc` (Linux bash) or `~/.profile` (`-n` skips this) |
| `set_vault_addr.ps1` | Sets `VAULT_ADDR` permanently for the Windows user. **Local only:** it's in `.gitignore` and must not be committed, because it holds the internal Vault address |
| `vault_list.py` | Lists the Vault secrets the logged-in account can see. Also used to sign in as a different user |
| `requirements.txt` | Python dependencies |
| `.env` | `VAULT_ADDR`, `VAULT_MOUNT` and `VAULT_PATH` (not secrets). It may also hold `LCMC_CACERT`, a path to the EPIC-CA root PEM. **`.env` is the only place the Vault address is kept.** `vault_helper.py` (and so every helper and `vault_list.py`), `vault_login.ps1`, `vault_login.sh` and `set_vault_addr.ps1` read `VAULT_ADDR` from it, and it wins over a `VAULT_ADDR` environment variable. Never hard-code the address in a tracked file. For the other keys, an environment variable still wins over `.env` |
| `.env.old` | Backup. Do not read it, use it or change it |

Vault secrets at `VAULT_MOUNT`/`VAULT_PATH`: `ansible_user`, `ansible_password`, `ansible_become_password` (enable secret), `netbox_url`, `netbox_token`, `meraki_api` (Cisco Meraki Dashboard API key), `ORDR_URL`, `ORDR_USER`, `ORDR_PASSWORD`, `ORDR_TENANTGUID` (Ordr SCE API), `ise_url`, `ise_user`, `ise_password` (Cisco ISE), `cat_url`, `cat_user`, `cat_password` (Cisco Catalyst Center).

## Answering route questions

Requests like "show me routes for 10.158.8.1", "where is 10.x.x.x routed" or "which router has a route to 10.158.8.0/24" mean:

```
python cisco_helper.py route <ip-or-prefix> --json
```

With no device options, this runs on every NetBox device tagged `wan_router`. Add `--site <name>`, `-d <device>` or `--vrf <name>` only when the user asks for them. On the Lakeview Hospital, Lakeside and Tulane cores, route lookups use VRF `buyer` automatically (see "VRFs on the cores"), and each result's `vrf` says which VRF was used. In the JSON, each result's `route_result` is `found`, `not found` or `error`, and `output` holds the router's output. Found routes also have `route_detail`: `prefix`, `protocol`, `distance`, `metric` and `next_hops` (`next_hop`, `interface`, `active`). For recursive routes such as BGP, the helper looks up the route to the next hop on the same router to fill in the real outgoing interface, and records how it got there in `resolved_via` (e.g. `198.18.255.32/32 ospf 500 -> 198.18.0.30`). The text output's Summary shows all of this on one line per router.

To name the devices behind the destination and the next hops, look the IPs up in NetBox: `python netbox_helper.py ip <ip>` (device and interface) and `python netbox_helper.py prefix <ip>` (site, VLAN, VRF).

Then summarize for the user:
- which routers have the route, and for each one the matched prefix, the next hop, the outgoing interface, the protocol (BGP, OSPF, static, connected and so on) and the AD/metric if shown;
- whether any router only matched the default route (0.0.0.0/0), and say so explicitly;
- which routers did not have it, and any errors or skipped devices.

Show the full raw output only if the user asks for it (it is in `output`, or in the text sections above the Summary).

Exit codes: 0 = found on at least one router, 1 = not found anywhere, 2 = setup error (Vault, NetBox or a bad argument).

## Running commands on Cisco devices

**Use `cisco_helper.py` for anything run on a router or switch.** Never write ad-hoc netmiko or Python snippets. If a command or option is missing, add it to `cisco_helper.py` (the `COMMANDS` table), or to the right helper for the other systems, then use it. The helper reads the SSH credentials from Vault, finds devices through NetBox, runs on many devices at once, only sends single `show` commands (it refuses anything else and any `| redirect/tee/append/copy`), and masks passwords, keys, communities and hashes in config output.

Choosing devices (combine as needed; at most 25 by default, change with `--max-devices`):
- `-d <name|ip>` (repeatable). Names are looked up in NetBox (exact name, else name contains). IPs connect directly as `cisco_ios` (set `--device-type`).
- `--site <name or slug>`, e.g. `--site Lakeside`. `--tag <tag>`, e.g. `--tag wan_router`. `--name <text>`.
- Lakeside = `tls-*`, Lakeview = `lvr-*`, East Jefferson = `ej-*`, and so on (see `bgp_community.txt`).

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
python cisco_helper.py locate 10.158.0.139                        # IP -> gateway -> MAC -> access switchport (see "Finding a device")
python cisco_helper.py locate ac:b4:80:b9:a0:1f -d "lv-mdf-core-9500(1)"   # MAC trace from a starting device
python cisco_helper.py cpu -d tls-wan-rtr-01                      # also memory, env, inventory, transceivers, ntp, clock, license, sla
python cisco_helper.py show "show ip nat translations total" -d tls-wan-rtr-01   # any single show command
python cisco_helper.py wlans -d lakeview-wlc-ha01                 # Catalyst 9800: WLAN/SSID summary
python cisco_helper.py ssid LCMC-DATA -d lakeview-wlc-ha01 -o lakeviewssid.txt   # all config for an SSID
python cisco_helper.py ssid LCMC-VOIP -d lakeview-wlc-ha01 -o lakeviewssid.txt --append
```

- `-o FILE` also writes the results to a file (`--append` adds to it). Use it when the user asks for output in a file. `.gitignore` excludes `*.txt`.
- `ssid <name>` (Catalyst 9800) matches the SSID or the WLAN profile name, so it handles one SSID on several profiles (e.g. LCMC-DATA = `LCMC-DATA_SBH` and `LCMC-DATA_profile`). For each profile it collects the `wlan` config, the policy tags that map it, each policy profile's config, and `show wlan name`. PSKs (`set-key`) are masked.
- 9800 WLCs are IOS-XE (`cisco_xe`) in NetBox, e.g. `lakeview-wlc-ha01` (10.158.8.21), `lakeview-wlc-stby`, `lakeview-wlc-guest01`.

- `--json` gives `[{device, host, site, command, output, error}]` (route lookups add `route_result`). `--parse` turns the output into structured data with TextFSM (ntc-templates) where a template exists, e.g. `interfaces --parse --json`.
- A device that rejects a command (`% Invalid input`) is reported as an error. One failing device never stops the others.
- Exit codes: 0 = every device answered, 1 = at least one failed, 2 = setup error. For `route <ip>`: 0 = found somewhere, 1 = found nowhere.
- Even with masking, quote only the config lines that answer the question.

## Cisco Meraki

**Always use `meraki_helper.py` for Meraki.** Don't write ad-hoc `requests` calls. It reads the API key from Vault (`vault_helper.get_secret("meraki_api")`), uses the LCMC Health org (ID **793109**, the only org the key can access) by default, follows pagination, adjusts `perPage` to each endpoint's limit, and retries on `429` and `502/503/504`. It only sends `GET` requests. Live Tools (ping, cable test, blink and so on) need `POST`, so they are out of scope. **Secrets are masked** (`*****`) in every command's output, `--json` and `get` included: PSKs, RADIUS and VPN secrets, SNMP communities, passwords and license keys.

Command line (`python meraki_helper.py <command> --help` lists each command's options):

```
# Inventory and status
python meraki_helper.py sites                              # every network: device count, online count, types, tags
python meraki_helper.py devices --network PUC_Kenner [--type switch]   # devices + status, LAN/public IP, last reported
python meraki_helper.py aps [--network PUC_Kenner]         # access points + status and tags
python meraki_helper.py offline [--network X]              # every device whose status is not online
python meraki_helper.py device "Kenner MX85"               # one device by name, serial or MAC: model, firmware, IPs, address, mgmt interface
python meraki_helper.py inventory --unused [--type wireless]   # claimed hardware not in any network (spares)
python meraki_helper.py licenses [--coterm [--all]]        # subscriptions, status, end dates, seats per SKU
python meraki_helper.py firmware [--by-network] [--by-model] [--network X]   # firmware versions in use
python meraki_helper.py firmware --scheduled | --history   # scheduled/in-progress or completed/canceled upgrades
python meraki_helper.py availability --hours 72 [--summary] [--network X] [--type wireless]   # online/offline flaps

# Clients
python meraki_helper.py clients --network PUC_Kenner [--hours 24] [--ssid DATA] [--vlan 2] [--search dell] [--sort usage]
python meraki_helper.py client 00:11:22:33:44:55           # org-wide MAC search: every network that has seen it
python meraki_helper.py client 10.187.5.95 --network PUC   # IP or name: scans client lists (all networks if no --network; slow)
python meraki_helper.py client <mac> --detail              # adds wireless connection stats
python meraki_helper.py top clients|apps|ssids|devices|models|networks [--hours 24] [--limit 10]

# Wireless
python meraki_helper.py ssids [--by-network] [--network PUC]   # enabled SSIDs: networks, APs broadcasting/online, auth mode
python meraki_helper.py ssid LCMC-DATA [--network PUC] [--full]   # one SSID's config per network (RADIUS, VLAN, scope); --full adds firewall/shaping/splash
python meraki_helper.py rf-profiles [--network X]
python meraki_helper.py wifi-health --network PUC_Kenner [--hours 24]   # failures by step (assoc/auth/dhcp/dns), per AP, channel utilization
python meraki_helper.py air-marshal --network PUC_Kenner [--wired]      # rogue/neighbor SSIDs; --wired = also seen on the LAN
python meraki_helper.py ap-ports [--network X]             # AP uplink: power source, PoE standard, speed, duplex

# Appliance (MX/Z3), WAN and VPN
python meraki_helper.py uplinks [--network X] [--loss] [--down]   # WAN1/WAN2/cellular status, IPs, gateway, DNS; --loss adds 5-min loss/latency
python meraki_helper.py vpn [--network X] [--down]         # AutoVPN: peers, unreachable peers, exported subnets
python meraki_helper.py vpn --config [--network X]         # site-to-site mode, hubs, subnets in VPN
python meraki_helper.py vpn --third-party                  # third-party IPsec peers
python meraki_helper.py vlans [--network X]                # VLAN id, name, subnet, MX IP, DHCP mode (all MX networks if no --network)
python meraki_helper.py routes [--network X]               # MX static routes
python meraki_helper.py firewall --network X [--kind l3|l7|inbound|portfwd|nat|nat-many]
python meraki_helper.py security --network X               # content filtering, IDS/IPS, AMP settings
python meraki_helper.py security --events [--network X] [--hours 24] [--limit 100]   # IDS/AMP events
python meraki_helper.py sdwan --network X                  # uplink selection, bandwidth limits, traffic shaping
python meraki_helper.py appliance --network X              # MX perf score, LAN ports, DHCP subnet usage, warm spare, settings

# Switches (MS)
python meraki_helper.py ports "Kenner MS130" [--port 12] [--connected] [--errors]   # port config + live status, PoE, LLDP/CDP neighbor
python meraki_helper.py ports --network PUC_Kenner [--errors]    # every switch in the network
python meraki_helper.py switch --network X [--kind stacks|stp|access-policies|dhcp-policy|acl|qos|mtu|settings|interfaces|routes]

# Topology, events, audit
python meraki_helper.py neighbors "Kenner MS130"           # LLDP/CDP neighbors per port
python meraki_helper.py neighbors --network PUC_Kenner     # L2 topology links of a network
python meraki_helper.py events --network X [--product wireless] [--type association] [--device NAME] [--client MAC] [--limit 100]
python meraki_helper.py alerts [--network X] [--severity critical] [--all]   # assurance alerts (active by default)
python meraki_helper.py changes [--hours 168] [--network X] [--admin name]   # Dashboard config change log (who changed what)
python meraki_helper.py admins                             # Dashboard admins, access level, 2FA, last active
python meraki_helper.py settings --network X               # network, syslog, SNMP, alerts, group policies, NetFlow, firmware

# Anything else
python meraki_helper.py get organizations/{org}/appliance/vpn/statuses
python meraki_helper.py get networks/<networkId>/clients -p timespan=3600
python meraki_helper.py get organizations/{org}/devices -p "serials[]=A" -p "serials[]=B" --one-page
```

- Every command takes `--json` (full records) and `-o FILE` (also write the output to a file; `--append` adds to it). `get` always prints JSON.
- `{org}` in a path is replaced with the org ID. Write paths **without a leading slash**, because Git Bash rewrites `/organizations/...` into a Windows path.
- `--network`: commands that work on one network (`clients`, `firewall`, `events`, `wifi-health` and so on) take an exact name or a unique substring, and the error lists the matches if there are several. Commands that loop over networks (`vlans`, `routes`, `vpn`, `ssid`, `rf-profiles`, `firmware`, `client`) take an exact name, or else run on every network whose name contains the text.
- Wherever a device is needed, a device name, serial or MAC works (exact name, else a unique substring).
- Device status is one of `online`, `alerting`, `offline` or `dormant`.
- Notes from testing (2026-10-12): the org uses **subscription licensing**, so `licenses/overview` returns 400 and `licenses` reads the subscriptions instead. Networks bound to a template (e.g. `PUC_*`) return 400 for `appliance/trafficShaping`, and `sdwan` shows that as an error section. `changes` returns one page of up to 5000 changes, newest first. `events` asks each product type in the network separately and merges the results. `clients` shows usage in MB, converted from the API's KB. `top` shows usage in MB, as the API reports it.
- To follow up on a client, take its MAC to ISE (`ise_helper.py auth <mac>`) or Ordr (`ordr_helper.py device <mac>`). To compare MX subnets with NetBox, run `vlans`, then `netbox_helper.py prefix <ip>`.

In Python, for anything the CLI doesn't cover:

```python
from meraki_helper import Meraki, mask

m = Meraki()
net = m.network_by_name("PUC_Kenner"); dev = m.device_by_name("Kenner MX85")
m.networks(); m.networks_matching("PUC", "wireless"); m.devices(); m.device_statuses(); m.inventory(usedState="unused")
m.uplink_statuses(); m.uplink_loss_latency(); m.vpn_statuses(); m.third_party_vpn_peers(); m.sites(); m.subscriptions()
m.clients(net["id"], timespan=3600); m.client_search("00:11:22:33:44:55"); m.vlans(net["id"]); m.static_routes(net["id"])
m.ssids(net["id"]); m.ssid_usage(); m.switch_ports(serial); m.switch_port_statuses(serial); m.lldp_cdp(serial)
m.events(net["id"], "wireless"); m.config_changes(timespan=86400); m.assurance_alerts(active="true"); m.admins()
m.availability_changes(timespan=86400); m.firmware_upgrades(); m.security_events(86400); m.top("clients/byUsage")
m.get_all("networks/{id}/appliance/firewall/l3FirewallRules")  # any list endpoint
m.get("devices/{serial}"); m.try_get(path)                    # one object; try_get returns {"error": ...} instead of raising
print(mask(data))                                             # mask secrets before printing anything yourself
```

How sites are named in Meraki (79 networks): `CHMPC *` = Children's clinics, `LRPG *` = Tulane/LRPG clinics, `PUC_*` = urgent care, `CC_*` = Community Connect partners (single Z3/MX), `* GUEST Internet` = hospital guest MXs, `UMC Concentrator` / `UMC ACB Concentrator` = VPN concentrators.

Summarize the results for the user. Show raw JSON only when they ask for it. The `meraki` SDK is not installed and isn't needed.

## Ordr

Use Ordr for questions about what an endpoint **is**: device identity and classification (group, profile, manufacturer, model, OS), risk, security alarms, vulnerabilities, where a device sits on the network, and its flows and applications. It is especially useful for medical and IoT devices. Use Meraki for Meraki network and client state, and `cisco_helper.py route` for routing.

**Always use `ordr_helper.py` for Ordr.** Don't write ad-hoc `requests` calls. It reads `ORDR_URL`, `ORDR_USER`, `ORDR_PASSWORD` and `ORDR_TENANTGUID` from Vault in one call (`vault_helper.get_secret_values()`), uses HTTP basic auth, adds `tenantGuid` to every request (the API requires it), follows `MetaData.next` pagination, and retries on `429`. It only sends `GET` requests.

Command line (start with these):

```
python ordr_helper.py device 00:11:22:33:44:55         # by MAC (any format), IP, or device name
python ordr_helper.py device 10.158.10.25 --include connectivity-info   # switch/port/AP details
python ordr_helper.py devices --profile "<profile>" --limit 50
python ordr_helper.py devices --group "<group>" --risk High
python ordr_helper.py devices --conn-status ONLINE_IN_LAST_24_HRS --limit 0   # 0 = all
python ordr_helper.py alarms --severity high --limit 20
python ordr_helper.py alarms --mac 00:11:22:33:44:55
python ordr_helper.py vulns --ip 10.158.10.25
python ordr_helper.py summary                          # alarm + vulnerability summaries
python ordr_helper.py reports medical                  # list report names containing "medical" (no login needed)
python ordr_helper.py report high-risk-devices
python ordr_helper.py get Rest/Locations
python ordr_helper.py get Rest/Devices -p mfg=Philips --all
```

- `devices`, `alarms` and `vulns` return 100 rows by default. Use `--limit 0` for everything, but that can be slow for all devices.
- Add `--json` to `device`, `devices`, `alarms` or `vulns` to get every field. The table shows only the main columns. `summary`, `report`, `locations` and `get` always print JSON.
- `devices` filters match the API query parameters. For others, use `get Rest/Devices -p <param>=<value>`. Examples: `os-type`, `serial`, `vulnIds`, `appName`, `sensorName`, `include=clinical-info`, `openPorts=true`, `weakPassword=true`.
- Useful device fields: `MacAddress`, `IpAddress`, `dhcpHostname`, `Group`, `Profile`, `MfgName`, `ModelNameNo`, `OsType`, `Vlan`, `RiskState`, `riskScore`, `connStatus`, `deviceLocation`, `nwEquipHostname`, `nwEquipInterface`, `essid`, `hasPhi`, `fdaClass`, `firstSeen`, `lastSeen`.
- **Reports don't work on this tenant.** The spec lists about 290 reports (`Rest/Reports/...`, browse them with `reports <text>`), but as of 2026-10 every one returns `400 Unknown report`. Build the answer from `devices`, `alarms` and `vulns` instead, for example by counting devices by `Group`, `Profile` or `RiskState`.
- Paging is verified: `--limit N` asks Ordr for up to N per page and follows `MetaData.next` (`clientMacToken`) until N rows are collected.
- Name lookups (`device <name>`) match the short hostname in any case, so `uws-dt5-lan046` works and the helper strips any domain. They are slow, about a minute, so prefer MAC or IP when you have one. One name can return several devices, for example wired and wireless NICs.
- MAC filters are case-sensitive in Ordr (uppercase only). The helper normalizes MACs for you, so use it rather than raw `get`. A device that isn't found returns an empty list.
- Severity: the `severity-level` filter takes lowercase values (`normal`, `low`, `medium`, `high`, `critical`), but results show them in uppercase (`HIGH`). Alarm categories look like `KNOWN_VULN_CONFIRMED_HIGH`.
- API reference: https://api.ordr.net/api-docs/index.html (spec: https://api.ordr.net/api-docs/OrdrRestAPI.json).

In Python:

```python
from ordr_helper import Ordr

o = Ordr()
o.device("00:11:22:33:44:55")                          # list of matching devices
o.devices(max_items=50, group="<group>", riskState="High")
o.alarms(max_items=20, **{"severity-level": "high"})
o.vulnerabilities(ip="10.158.10.25")
o.alarm_summary(); o.vulnerability_summary(); o.locations(); o.profiles()
o.applications(mac="00:11:22:33:44:55"); o.flows(srcIp="10.158.10.25")
o.report("24-hour/device-count-by-type")
o.get("Rest/Devices", mac="00:11:22:33:44:55"); o.get_all("Rest/Devices", max_items=500, mfg="Philips")
```

Summarize the results for the user. Show raw JSON only when they ask for it. Device records can include patient-related fields (`hasPhi`, clinical info), so only include those when they're relevant to the question.

## Cisco Catalyst Center

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

## Cisco ISE

Use ISE for questions about **network access**: where a MAC, IP or user is authenticated right now (switch, port or WLC/AP), how it authenticated (802.1X or MAB, which policy, which authorization profile, VLAN or SGT), its endpoint profile and identity group, its recent auth failures, and which network devices (NADs) are defined in ISE. Ordr answers what a device *is*, Meraki covers Meraki networks, and `cisco_helper.py route` covers routing.

**Always use `ise_helper.py` for ISE.** Don't write ad-hoc `requests` calls. It reads `ise_url`, `ise_user` and `ise_password` from Vault in one call. ISE is `umc-ise-pan-01.lcmchealth.org` (the PAN).

Deployment (from `nodes`): PAN `UMC-ISE-PAN-01` (primary) and `EJ-ISE-PAN-02`, dedicated MnT nodes `UMC-ISE-MNT-01` (primary) and `EJ-ISE-MNT-02`, and PSNs `UMC-ISE-PSN-01` and `EJ-ISE-PSN-02`. ERS and OpenAPI go to the PAN in `ise_url`. **MnT calls go to the primary MnT node**, which the helper finds from the node list (override it with `ISE_MNT_HOST`).

**Status (tested 2026-10-09):** all three APIs work. MnT access was granted to the `ise_user` account the same day.

MnT quirks the helper handles for you:
- ISE answers "no session" with HTTP 500 (cpm-code 34110), not 404. `session` returns `null` in that case.
- ISE's `Session/IPAddress` lookup fails even for live sessions, so `session <ip>` finds the IP in the active-session list (`framed_ip_address`) and then looks up that MAC. An IP lookup can therefore only find sessions in the active list.
- The active list is small (97 sessions when tested), because it only holds sessions that have RADIUS accounting. If `session` returns `null`, run `auth <mac>`. It still shows recent authentications, with the WLC or switch, port type, identity group and pass/fail.

| API | Base URL | Used for | Format |
|---|---|---|---|
| ERS | `https://<ise>:9060/ers/config/` | Config objects: endpoints, network devices, endpoint and identity groups, SGTs, authorization profiles | JSON. Follows `nextPage`, 100 results per page |
| MnT | `https://<ise>/admin/API/mnt/` | Live sessions, active count and list, recent authentications | XML, which the helper converts to dicts |
| OpenAPI | `https://<ise>/api/v1/` | Deployment nodes, policy sets | JSON |

Command line (start with these):

```
python ise_helper.py lookup 0011.2233.4455            # endpoint record + live session for a MAC (any format)
python ise_helper.py session 10.158.10.25             # live session by MAC, IP or username
python ise_helper.py auth 00:11:22:33:44:55 --hours 24   # recent authentications (max 120 h)
python ise_helper.py active --count                   # number of active sessions
python ise_helper.py active --protocols               # active sessions by auth protocol (EAP-TLS, PEAP...) and method (dot1x/mab)
python ise_helper.py active --limit 20                # sample of active sessions
python ise_helper.py nad 10.158.136.51                # network device by IP, or name substring
python ise_helper.py nads --name wan                  # list NADs (id, name)
python ise_helper.py groups                           # endpoint identity groups
python ise_helper.py nodes                            # deployment nodes and roles
python ise_helper.py policy-sets [--device-admin]
python ise_helper.py ers sgt                          # any ERS resource; -f name.CONTAINS.x ; --id <uuid>
python ise_helper.py mnt Session/ActiveCount          # any MnT path
python ise_helper.py api deployment/node              # any OpenAPI path
```

- `session`, `lookup` and `auth` show only the key fields by default: user, MAC, IP, NAD name and IP, port, endpoint profile, identity group, authorization profile, auth method and protocol, posture, SGT, PSN and timestamp. Add `--json` for everything.
- `session` returns `null` when the endpoint has no active session. Use `auth` to see recent attempts, including failures.
- ERS filters use the form `<field>.<OP>.<value>`, where OP is EQ, NEQ, CONTAINS, STARTSW and so on. Examples: `mac.EQ.AA:BB:CC:DD:EE:FF`, `name.CONTAINS.wan`, `ipaddress.EQ.10.1.1.1`.
- The ISE account needs ERS Admin or Operator rights for ERS, and MnT access for sessions. A 403 means the account lacks the right role. A connection error on port 9060 means ERS is disabled.

**TLS:** ISE's certificate is issued by `EPIC-ICA01` under LCMC's root `EPIC-CA`. See "LCMC internal CA" under Setup.

In Python:

```python
from ise_helper import ISE

ise = ISE()
ise.lookup("00:11:22:33:44:55")          # {"endpoint": {...ERS...}, "session": {...MnT...}}
ise.session("10.158.10.25"); ise.auth_status("00:11:22:33:44:55", hours=24, records=10)
ise.active_count(); ise.active_sessions(max_items=50)
ise.network_device("tls-wan-rtr-01"); ise.network_devices(name_contains="wan")
ise.endpoint_groups(); ise.identity_groups(); ise.sgts(); ise.authorization_profiles()
ise.nodes(); ise.policy_sets()
ise.ers_search("internaluser", filter="name.STARTSW.svc"); ise.ers_get("endpoint", "<id>")
ise.mnt("Session/ActiveCount"); ise.api("deployment/node")
```

Summarize the results for the user. Show raw JSON only when they ask for it.

## Vault login

The helpers reuse `VAULT_TOKEN` or `~/.vault-token`. If neither is valid, it opens a browser OIDC login and saves the new token to `~/.vault-token`. The Vault address always comes from `VAULT_ADDR` in `.env`. To log in beforehand with the Vault CLI directly:

```powershell
$env:VAULT_ADDR = "<value of VAULT_ADDR in .env>"
vault login -method=oidc
```

**If the normal login picks the wrong Microsoft account** (for example a Sapphire account, which fails with `samaccountname not found`), use the private-browser login scripts. Each one runs `vault login -method=oidc -no-print`, opens the login URL in a private window, and saves the token to `~/.vault-token`:

```
powershell -ExecutionPolicy Bypass -File .\vault_login.ps1      # Windows: Edge InPrivate (-Browser chrome|firefox, -Prompt login, -NoPersist); saves VAULT_ADDR permanently
./vault_login.sh                                               # macOS / Linux: Chrome incognito (-b edge|firefox, -p login, -n); saves VAULT_ADDR to the shell profile
```

These are interactive. Ask the user to run them, or run one only when the user asks, because the user has to finish the sign-in in the browser.

Alternatively, to sign in as a **different account** (the browser otherwise reuses the current Microsoft session):

```
python vault_list.py --private --prompt login
```

This opens an Edge InPrivate window, asks for a username and password, and saves the token for the helpers to use.

Known problem: `claim "samaccountname" not found in token` means the account used to sign in has no on-prem sAMAccountName in LCMC's tenant, for example a guest or B2B account such as a Sapphire account. The fix is to sign in with an LCMC account. Do not change the code to work around it.

## Rules

- Never print, log or write the credentials (`ansible_*`, `netbox_token`, `meraki_api`, `ORDR_*`, `ise_*`, `cat_*`, or the other keys at the Vault path) or a Vault token. Do not run `vault_list.py --show-values` unless the user explicitly asks.
- Meraki is **read-only**: go through `meraki_helper.py`, which only sends `GET` requests. Never send `POST`, `PUT` or `DELETE` to the Dashboard API (those change live config), unless the user explicitly asks for that specific change and confirms it.
- Catalyst Center is **read-only**: go through `catalyst_helper.py`, which only sends `GET` requests (plus the auth token `POST`). Never run Command Runner, push templates or config, provision or reboot devices, trigger syncs, or make any other `POST`, `PUT` or `DELETE` call, unless the user explicitly asks for that specific change and confirms it.
- ISE is **read-only**: go through `ise_helper.py`, which only sends `GET` requests. Never `POST`, `PUT` or `DELETE` to ERS or OpenAPI, and never send CoA, reauthenticate or disconnect requests through MnT (`/admin/API/mnt/CoA/...`). Those change live network access. The only exception is when the user explicitly asks for that specific change and confirms it.
- Ordr is **read-only**: go through `ordr_helper.py`, which only sends `GET` requests. Never call the Ordr write endpoints (`POST /Rest/SecurityAlarm/StateChange` clears alarms, `POST /Rest/SecurityAlarms/mute` mutes them, and so on for `Vulnerabilities/StateChange`, `UpdateAssetInfo`, `DeviceOnboard`, `UserLocations` and `UserRole`), unless the user explicitly asks for that specific change and confirms it.
- Never put secrets in `.env`. Do not touch `.env.old`.
- Only read-only `show` commands on the routers. No config mode, no `write`, no `clear`, no `reload`, nothing that changes state.
- **No ad-hoc snippets.** Use the helpers (`netbox_helper.py`, `cisco_helper.py`, `catalyst_helper.py`, `ise_helper.py`, `meraki_helper.py`, `ordr_helper.py`, `bgp_community.py`). If one can't do what's needed, extend that helper (and this file), test it, then use it. See "Ground rules" at the top.
- **NetBox is the source of truth for inventory.** Look devices up there first.
- Run show commands on devices only when the user asks for information from them. Keep to the devices the question needs.

## Adding a platform

1. `netbox_helper.py`: add the NetBox platform slug to `PLATFORM_MAP`, mapped to a netmiko device_type. Unknown slugs fall back to `cisco_ios`, with a warning.
2. `cisco_helper.py`: if the platform's route command differs, add a branch in `route_command()`. If its "not found" text is new, add it to `ROUTE_NOT_FOUND`. For other commands, add a platform column or override in `COMMANDS`.

## Setup

```
python -m pip install -r requirements.txt
vault version          # Vault CLI, already installed at C:\Program Files\vault\vault.exe
python cisco_helper.py list
```

If Vault or NetBox use an internal CA, `truststore` lets Python use the Windows certificate store. Otherwise set `VAULT_CACERT`.

### LCMC internal CA (ISE and Catalyst Center)

ISE (`umc-ise-pan-01`) and Catalyst Center (`ej-dnac-01`) use certificates from LCMC's internal PKI (root `EPIC-CA`, intermediates `EPIC-ICA01` and `EPIC-ICA02`). That root is not trusted on this Sapphire laptop. Vault, NetBox, Meraki and Ordr use public certificates and aren't affected. The root's SHA-256 fingerprint is `7A553FD7BE90FF6293A808BCF9FDF4230A2F622C70C8621C109B484BA6B4A0A4`, valid to 2064.

You can trust it in either of two ways. Either install EPIC-CA as a trusted root for the current user, or set `LCMC_CACERT` (in `.env`) to the EPIC-CA PEM file, which both helpers use (`ISE_CACERT` and `CAT_CACERT` still work for one helper each). Never turn off certificate verification.
