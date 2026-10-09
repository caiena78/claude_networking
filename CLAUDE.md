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
python netbox_helper.py tags
```

`--site` accepts a site name, a slug or a unique part of a name. `--json` gives full output.

## Files

| File | Role |
|---|---|
| `cisco_helper.py` | Read-only show commands on Cisco devices over SSH (uptime, interfaces, config sections, logs, neighbors, BGP/OSPF/EIGRP, ARP/MAC, CPU/memory, route lookups and any `show` command). Use it for everything run on a device |
| `vault_helper.py` | Vault login (token from `VAULT_TOKEN`, then `~/.vault-token`, then OIDC browser login), `get_secrets()` (router and NetBox credentials) and `get_secret(key)` (any one key, e.g. `meraki_api`) |
| `netbox_helper.py` | **The inventory.** CLI: `sites`, `devices`, `device`, `ip`, `prefix`, `tags`. Also `get_devices()` (used by `cisco_helper.py`) and `PLATFORM_MAP` (NetBox platform slug to netmiko device_type) |
| `catalyst_helper.py` | Read-only Cisco Catalyst Center (DNA Center) client and CLI (`devices`, `device`, `count`, `interfaces`, `config`, `client`, `sites`, `health`, `device-health`, `issues`, `get <path>`). Use it for all Catalyst Center access |
| `ise_helper.py` | Read-only Cisco ISE client and CLI for the ERS, MnT and OpenAPI interfaces (`lookup`, `session`, `auth`, `active`, `nad`, `nads`, `groups`, `nodes`, `policy-sets`, `ers`, `mnt`, `api`). Use it for all ISE access |
| `ordr_helper.py` | Read-only Ordr SCE REST API client and CLI (`device`, `devices`, `alarms`, `vulns`, `summary`, `reports`, `report`, `get <path>`). Use it for all Ordr access |
| `meraki_helper.py` | Read-only Meraki Dashboard API client and CLI (`sites`, `devices`, `offline`, `get <path>`). Use it for all Meraki access |
| `bgp_community.py` | Reads each router's BGP outbound route-map (`set community`) and writes `bgp_community.txt` (site, router, IP, AS, community) |
| `vault_login.ps1` / `vault_login.sh` | Vault OIDC login in a private browser window (Windows / macOS). The token is never printed |
| `set_vault_addr.ps1` | Sets `VAULT_ADDR` permanently for the Windows user |
| `vault_list.py` | Lists the Vault secrets the logged-in account can see. Also used to sign in as a different user |
| `requirements.txt` | Python dependencies |
| `.env` | `VAULT_ADDR`, `VAULT_MOUNT` and `VAULT_PATH` (not secrets). It may also hold `LCMC_CACERT`, a path to the EPIC-CA root PEM |
| `.env.old` | Backup. Do not read it, use it or change it |

Vault secrets at `VAULT_MOUNT`/`VAULT_PATH`: `ansible_user`, `ansible_password`, `ansible_become_password` (enable secret), `netbox_url`, `netbox_token`, `meraki_api` (Cisco Meraki Dashboard API key), `ORDR_URL`, `ORDR_USER`, `ORDR_PASSWORD`, `ORDR_TENANTGUID` (Ordr SCE API), `ise_url`, `ise_user`, `ise_password` (Cisco ISE), `cat_url`, `cat_user`, `cat_password` (Cisco Catalyst Center).

## Answering route questions

Requests like "show me routes for 10.158.8.1", "where is 10.x.x.x routed" or "which router has a route to 10.158.8.0/24" mean:

```
python cisco_helper.py route <ip-or-prefix> --json
```

With no device options, this runs on every NetBox device tagged `wan_router`. Add `--site <name>`, `-d <device>` or `--vrf <name>` only when the user asks for them. In the JSON, each result's `route_result` is `found`, `not found` or `error`, and `output` holds the router's output.

Then summarize for the user:
- which routers have the route, and for each one the matched prefix, the next hop, the outgoing interface, the protocol (BGP, OSPF, static, connected and so on) and the AD/metric if shown;
- whether any router only matched the default route (0.0.0.0/0), and say so explicitly;
- which routers did not have it, and any errors or skipped devices.

Show the full raw output only if the user asks for it (`--raw` or the default rich output).

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

**Always use `meraki_helper.py` for Meraki.** Don't write ad-hoc `requests` calls. It reads the API key from Vault (`vault_helper.get_secret("meraki_api")`), uses the LCMC Health org (ID **793109**, the only org the key can access) by default, follows pagination, adjusts `perPage` to each endpoint's limit, and retries on `429`. It only sends `GET` requests.

Command line (start with these):

```
python meraki_helper.py sites                          # every network: device count, online count, types, tags
python meraki_helper.py devices --network PUC_Kenner   # devices + status, LAN/public IP, last reported
python meraki_helper.py devices --type appliance       # filter by productType
python meraki_helper.py offline                        # every device whose status is not online
python meraki_helper.py ssids                          # enabled SSIDs: networks, APs broadcasting, APs online, auth mode
python meraki_helper.py ssids --by-network [--network PUC]   # one row per network + SSID (slot number, tag scoping)
python meraki_helper.py get organizations/{org}/appliance/vpn/statuses
python meraki_helper.py get networks/<networkId>/clients -p timespan=3600
python meraki_helper.py get organizations/{org}/devices -p "productTypes[]=switch" --one-page
```

- Add `--json` to `sites`, `devices` or `offline` for machine-readable output. `get` always prints JSON.
- `{org}` in a path is replaced with the org ID. Write paths **without a leading slash**, because Git Bash rewrites `/organizations/...` into a Windows path.
- `--network` takes an exact name or a unique substring. If the name matches several networks, the error lists them.
- Device status is one of `online`, `alerting`, `offline` or `dormant`.

In Python, for anything the CLI doesn't cover:

```python
from meraki_helper import Meraki

m = Meraki()
net = m.network_by_name("PUC_Kenner")
m.networks(); m.devices(productTypes=["appliance"]); m.device_statuses()
m.uplink_statuses(); m.vpn_statuses(); m.sites()
m.clients(net["id"], timespan=3600); m.vlans(net["id"]); m.lldp_cdp("Q2YN-....")
m.get_all("networks/{id}/appliance/firewall/l3FirewallRules")  # any list endpoint
m.get("devices/{serial}")                                     # one object / one page
```

How sites are named in Meraki (78 networks): `CHMPC *` = Children's clinics, `LRPG *` = Tulane/LRPG clinics, `PUC_*` = urgent care, `CC_*` = Community Connect partners (single Z3/MX), `* GUEST Internet` = hospital guest MXs, `UMC Concentrator` / `UMC ACB Concentrator` = VPN concentrators.

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
python catalyst_helper.py devices --family Switches --limit 50
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

The helpers reuse `VAULT_TOKEN` or `~/.vault-token`. If neither is valid, it opens a browser OIDC login and saves the new token to `~/.vault-token`. To log in beforehand:

```powershell
$env:VAULT_ADDR = "<value of VAULT_ADDR in .env>"
vault login -method=oidc
```

**If the normal login picks the wrong Microsoft account** (for example a Sapphire account, which fails with `samaccountname not found`), use the private-browser login scripts. Each one runs `vault login -method=oidc -no-print`, opens the login URL in a private window, and saves the token to `~/.vault-token`:

```
powershell -ExecutionPolicy Bypass -File .\vault_login.ps1      # Windows: Edge InPrivate (-Browser chrome|firefox, -Prompt login)
./vault_login.sh                                               # macOS: Chrome incognito (-b edge|firefox, -p login)
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
