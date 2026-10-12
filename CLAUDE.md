# claude-network

Network operations toolkit for LCMC Health. It answers questions about routers, switches, WLCs, sites, IPs and endpoints using NetBox (inventory), the devices themselves over SSH, Catalyst Center, ISE, Meraki and Ordr. All credentials come from HashiCorp Vault.

## Ground rules (read first)

1. **Every task goes through a `*_helper.py` script.** For anything the user asks, use the matching helper. **If the helper can't do what's needed, update the helper first.** Add the command or option, test it read-only, document it in this file, then use it to do the task. Never work around a helper with ad-hoc Python, netmiko or `requests` snippets.
2. **NetBox is the inventory.** Use `netbox_helper.py` (or `cisco_helper.py`, which resolves devices through NetBox) to find devices, sites, management IPs, roles, models, serials, IP assignments and prefixes. Catalyst Center, ISE, Meraki and Ordr have their own device lists. Use them for their own data (assurance, sessions, Meraki networks, endpoint identity), not as the inventory. If they disagree with NetBox, say so; don't silently prefer them.

```
python netbox_helper.py sites --name Lake
python netbox_helper.py devices --site Lakeside [--tag wan_router] [--role wan] [--name wlc]
python netbox_helper.py device lakeview-wlc-ha01        # full record: site, role, model, serial, platform, primary IP, tags
python netbox_helper.py vc wp-6flr                      # virtual chassis (stack): master, members, positions, serials
python netbox_helper.py ip 10.158.8.21                  # which device and interface has an IP
python netbox_helper.py prefix 10.158.10.25             # prefixes (site, VLAN, VRF, role) containing an IP
python netbox_helper.py prefixes --site Tulane [--vlan 700] [--vrf buyer] [--search text]   # subnet -> site list
python netbox_helper.py tags
```

`--site` accepts a site name, a slug or a unique part of a name. `--json` gives full output.

**Virtual chassis (switch stacks):** NetBox models a stack as a virtual chassis, for example `wp-6flr` with members `wp-6flr(1)` to `wp-6flr(7)`, and usually only the master has a management IP. Device lookups (`devices`, and `cisco_helper.py -d/--site/--name`) return each stack as **one** device. It's named after the virtual chassis, connects to the master's IP, and lists its `members`. A name filter also matches virtual chassis names. Use `devices --members` to list members separately, and `vc <name>` for the member details.

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

**One command for all of it:** `python endpoint_helper.py whois <ip|mac>` runs this whole order. It does NetBox, then the switchport trace below, then Ordr, ISE and Catalyst (stopping at the first that knows the device; `--all` asks every one), then Meraki. Use it first for "what is / where is this device". For a wireless MAC on the on-prem WLCs, `python cisco_helper.py wclient <mac>` asks every 9800 and AireOS controller. See the `network-reports` skill.

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
| `cisco_helper.py` | Read-only show commands on Cisco devices over SSH (uptime, interfaces, config sections, logs, neighbors, BGP/OSPF/EIGRP, ARP/MAC, CPU/memory, route lookups and any `show` command), plus `locate <ip\|mac>` (traces an IP to its switchport) and `wclient <mac>` (finds a wireless client on the 9800 and AireOS WLCs). Use it for everything run on a device |
| `vault_helper.py` | Vault login (token from `VAULT_TOKEN`, then `~/.vault-token`, then OIDC browser login), `get_secrets()` (router and NetBox credentials) and `get_secret(key)` (any one key, e.g. `meraki_api`) |
| `netbox_helper.py` | **The inventory.** CLI: `sites`, `devices`, `device`, `ip`, `prefix`, `prefixes`, `tags`. Also `get_devices()` (used by `cisco_helper.py`) and `PLATFORM_MAP` (NetBox platform slug to netmiko device_type) |
| `catalyst_helper.py` | Read-only Cisco Catalyst Center (DNA Center) client and CLI (`devices`, `device`, `count`, `interfaces`, `config`, `client`, `sites`, `health`, `device-health`, `issues`, `get <path>`). Use it for all Catalyst Center access |
| `ise_helper.py` | Read-only Cisco ISE client and CLI for the ERS, MnT and OpenAPI interfaces (`lookup`, `session`, `auth`, `active`, `nad`, `nads`, `groups`, `nodes`, `policy-sets`, `ers`, `mnt`, `api`). Use it for all ISE access |
| `cdo_helper.py` | Read-only Cisco Security Cloud Control (CDO) cloud-delivered FMC client and CLI (`devices`, `ha`, `interfaces`, `routes`, `objects`, `policies`, `prefilter-rules`, `prefilter-check`, `acp-check`, `nat-check`, `get <path>`). Use it for all CDO / FMC access and for checking whether a prefilter or access rule allows traffic. Guide: skill `cdo-firewall-policy` |
| `ftd_capture_helper.py` | Packet captures on the FTD firewalls listed in `.env` (`FTD_CAPTURE_HOSTS`), on the **active** unit only (`status`, `interfaces`, `list`, `start`, `check`, `stop`, `sessions`, `capture`, `cleanup`). **This is the only helper that changes anything on a device.** It logs every change to `captures/audit.log`. Rules: skill `ftd-packet-captures` |
| `ordr_helper.py` | Read-only Ordr SCE REST API client and CLI (`device`, `devices`, `alarms`, `vulns`, `summary`, `reports`, `report`, `get <path>`). Use it for all Ordr access |
| `meraki_helper.py` | Read-only Meraki Dashboard API client and CLI: inventory (`sites`, `devices`, `aps`, `device`, `inventory`, `licenses`, `firmware`), clients (`clients`, `client`, `top`), wireless (`ssids`, `ssid`, `wifi-health`, `air-marshal`), MX (`uplinks`, `vpn`, `vlans`, `routes`, `firewall`, `security`, `appliance`), switches (`ports`, `switch`), audit (`events`, `alerts`, `changes`, `admins`) and `get <path>`. Secrets are masked. Use it for all Meraki access |
| `endpoint_helper.py` | Combined, read-only answers: `whois <ip\|mac>` (NetBox, switchport trace, then Ordr → ISE → Catalyst, then Meraki) and `path <src> <dst> --port N` (which FTDs sit between two IPs and what their prefilter, access and NAT policies decide). Guide: skill `network-reports` |
| `audit_helper.py` | NetBox drift reports: `prefixes --site` (vs subnets connected on the cores), `devices` (vs Catalyst Center and Meraki serials), `meraki-vlans`. Read-only |
| `report_helper.py` | `daily`: one health brief across Meraki, Catalyst Center, ISE and CDO (`--no-cdo` skips your personal CDO key) |
| `helper_common.py` | Shared output code: `table()`, `to_json()`, `Out` (for `-o FILE`), MAC formatting. New helpers use it |
| `tools/leak_check.py`, `.githooks/pre-commit` | Leak guard: blocks commits containing `.env` values (Vault, CDO tenant, FTD IPs), your personal secrets, or token/key patterns. Enable once per clone with `git config core.hooksPath .githooks` |
| `tests/` | Offline tests for the parsers and policy matching: `python -m pytest -q` (no network, Vault or devices). `.github/workflows/checks.yml` runs them, the leak check and gitleaks on every push |
| `.claude/skills/` | Per-system guides (see "Other systems (skills)") |
| `bgp_community.py` | Reads each router's BGP outbound route-map (`set community`) and writes `bgp_community.txt` (site, router, IP, AS, community) |
| `vault_login.ps1` / `vault_login.sh` | Vault OIDC login in a private browser window (Windows / macOS and Linux). The token is never printed. Both also save `VAULT_ADDR` from `.env` permanently, writing it only when it changes. `vault_login.ps1` sets a user environment variable (`-NoPersist` skips this), so `set_vault_addr.ps1` is no longer needed. `vault_login.sh` writes one `export VAULT_ADDR=...  # set by vault_login.sh` line to `~/.zshrc`, `~/.bash_profile` (macOS bash), `~/.bashrc` (Linux bash) or `~/.profile` (`-n` skips this) |
| `set_vault_addr.ps1` | Sets `VAULT_ADDR` permanently for the Windows user. **Local only:** it's in `.gitignore` and must not be committed, because it holds the internal Vault address |
| `vault_list.py` | Lists the Vault secrets the logged-in account can see. Also used to sign in as a different user |
| `requirements.txt` | Python dependencies |
| `.env` | `VAULT_ADDR`, `VAULT_MOUNT` and `VAULT_PATH`, plus `CDO_URL` and `FTD_CAPTURE_HOSTS` (none of them secrets). It may also hold `LCMC_CACERT`, a path to the EPIC-CA root PEM. **`.env` is the only place the Vault address is kept.** `vault_helper.py` (and so every helper and `vault_list.py`), `vault_login.ps1`, `vault_login.sh` and `set_vault_addr.ps1` read `VAULT_ADDR` from it, and it wins over a `VAULT_ADDR` environment variable. Never hard-code the address in a tracked file. For the other keys, an environment variable still wins over `.env` |
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
python cisco_helper.py wclient 78:02:8b:19:63:0e                  # wireless client on every WLC in NetBox (9800 + AireOS): AP, SSID, VLAN, IP, user
python cisco_helper.py wclient <mac> -d umc-wlc-8540-01            # one controller; anchor/foreign mobility is shown
```

- `-o FILE` also writes the results to a file (`--append` adds to it). Use it when the user asks for output in a file. `.gitignore` excludes `*.txt`.
- `ssid <name>` (Catalyst 9800) matches the SSID or the WLAN profile name, so it handles one SSID on several profiles (e.g. LCMC-DATA = `LCMC-DATA_SBH` and `LCMC-DATA_profile`). For each profile it collects the `wlan` config, the policy tags that map it, each policy profile's config, and `show wlan name`. PSKs (`set-key`) are masked.
- 9800 WLCs are IOS-XE (`cisco_xe`) in NetBox, e.g. `lakeview-wlc-ha01` (10.158.8.21), `lakeview-wlc-stby`, `lakeview-wlc-guest01`.

- `--json` gives `[{device, host, site, command, output, error}]` (route lookups add `route_result`). `--parse` turns the output into structured data with TextFSM (ntc-templates) where a template exists, e.g. `interfaces --parse --json`.
- A device that rejects a command (`% Invalid input`) is reported as an error. One failing device never stops the others.
- Exit codes: 0 = every device answered, 1 = at least one failed, 2 = setup error. For `route <ip>`: 0 = found somewhere, 1 = found nowhere.
- Even with masking, quote only the config lines that answer the question.

## Other systems (skills)

The detailed guide for each of these lives in a project skill under `.claude/skills/`, which loads when the question needs it. The safety rules for all of them are in "Rules" below.

| Skill | Helper | Use it for |
|---|---|---|
| `meraki` | `meraki_helper.py` | Meraki networks, devices, APs, clients, SSIDs, wireless health, MX WAN/VPN/VLANs/firewall, MS ports, events, change log |
| `ordr` | `ordr_helper.py` | What an endpoint is: identity, profile, risk, alarms, vulnerabilities (first stop for a non-Cisco device) |
| `catalyst-center` | `catalyst_helper.py` | Managed device inventory and assurance: health, issues, configs, where a client MAC is connected |
| `ise` | `ise_helper.py` | Authentication: where and how a MAC/IP/user authenticated, failures, NADs, policy sets |
| `cdo-firewall-policy` | `cdo_helper.py` | FTD config and policy: does a prefilter/access rule allow this, NAT, interfaces, routes, objects |
| `ftd-packet-captures` | `ftd_capture_helper.py` | Live "is this traffic allowed?" captures on the FTDs (the only write action) |
| `network-reports` | `endpoint_helper.py`, `audit_helper.py`, `report_helper.py` | `whois` an IP/MAC, `path` between two IPs through the firewalls, NetBox drift audits, the daily health brief |

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
- Only read-only `show` commands on the routers. No config mode, no `write`, no `clear`, no `reload`, nothing that changes state. **The one exception** is `ftd_capture_helper.py`. It may create, start, stop and remove packet captures on the `FTD_CAPTURE_HOSTS` firewalls, under the rules in the `ftd-packet-captures` skill. Every change is logged to `captures/audit.log`.
- CDO is **read-only**: go through `cdo_helper.py`, which only sends `GET` requests. Never `POST`, `PUT` or `DELETE` to the FMC API (that changes firewall policy), unless the user explicitly asks for that specific change and confirms it.
- `CDO_UUID`, `CDO_API`, `CISCO_SRV_ACCOUNT` and `CISCO_SRV_PWD` are environment variables. Never print them, log them or write them to a file.
- **No ad-hoc snippets.** Use the helpers (`netbox_helper.py`, `cisco_helper.py`, `catalyst_helper.py`, `ise_helper.py`, `meraki_helper.py`, `ordr_helper.py`, `cdo_helper.py`, `ftd_capture_helper.py`, `endpoint_helper.py`, `audit_helper.py`, `report_helper.py`, `bgp_community.py`). If one can't do what's needed, extend that helper (and this file), test it, then use it. See "Ground rules" at the top.
- **NetBox is the source of truth for inventory.** Look devices up there first.
- Run show commands on devices only when the user asks for information from them. Keep to the devices the question needs.

## Adding a platform

1. `netbox_helper.py`: add the NetBox platform slug to `PLATFORM_MAP`, mapped to a netmiko device_type. Unknown slugs fall back to `cisco_ios`, with a warning. (AireOS WLCs, platform `airos`, map to `cisco_wlc_ssh`.)
2. `cisco_helper.py`: if the platform's route command differs, add a branch in `route_command()`. If its "not found" text is new, add it to `ROUTE_NOT_FOUND`. For other commands, add a platform column or override in `COMMANDS`.

## Setup

```
python -m pip install -r requirements.txt
vault version          # Vault CLI, already installed at C:\Program Files\vault\vault.exe
python cisco_helper.py list
git config core.hooksPath .githooks     # once per clone: the leak-guard pre-commit hook
python -m pytest -q                     # offline tests; run them after changing a parser
```

**Before committing:** the repo is public. The pre-commit hook refuses commits that contain internal addresses or secrets. Use placeholders in examples (`192.0.2.x`, `198.51.100.x`, `<vault-host>`). Never bypass it with `--no-verify`.

If Vault or NetBox use an internal CA, `truststore` lets Python use the Windows certificate store. Otherwise set `VAULT_CACERT`.

### LCMC internal CA (ISE and Catalyst Center)

ISE (`umc-ise-pan-01`) and Catalyst Center (`ej-dnac-01`) use certificates from LCMC's internal PKI (root `EPIC-CA`, intermediates `EPIC-ICA01` and `EPIC-ICA02`). That root is not trusted on this Sapphire laptop. Vault, NetBox, Meraki and Ordr use public certificates and aren't affected. The root's SHA-256 fingerprint is `7A553FD7BE90FF6293A808BCF9FDF4230A2F622C70C8621C109B484BA6B4A0A4`, valid to 2064.

You can trust it in either of two ways. Either install EPIC-CA as a trusted root for the current user, or set `LCMC_CACERT` (in `.env`) to the EPIC-CA PEM file, which both helpers use (`ISE_CACERT` and `CAT_CACERT` still work for one helper each). Never turn off certificate verification.
