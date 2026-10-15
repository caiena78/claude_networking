# claude-network

Network operations toolkit for LCMC Health. It answers questions about routers, switches, WLCs, sites, IPs and endpoints using NetBox (inventory), the devices themselves over SSH, Catalyst Center, ISE, Meraki and Ordr. All credentials come from HashiCorp Vault.

## Ground rules (read first)

1. **Every task goes through a `*_helper.py` script.** For anything the user asks, use the matching helper. **If the helper can't do what's needed, update the helper first.** Add the command or option, test it read-only, document it (here or in its skill), then use it to do the task. Never work around a helper with ad-hoc Python, netmiko or `requests` snippets.
2. **NetBox is the inventory.** Use `netbox_helper.py` (or `cisco_helper.py`, which resolves devices through NetBox) to find devices, sites, management IPs, roles, models, serials, IP assignments and prefixes. Catalyst Center, ISE, Meraki and Ordr have their own device lists. Use them for their own data (assurance, sessions, Meraki networks, endpoint identity), not as the inventory. If they disagree with NetBox, say so; don't silently prefer them.
3. **Load the skill for the task** (table below). The procedures live there, not here.
4. **Don't use the `netbox-netmiko-mcp` MCP tools** (`mcp__netbox-netmiko-mcp__*`), even if they're connected. That server is abandoned, and this repo replaces it.

```
python netbox_helper.py sites --name Lake
python netbox_helper.py devices --site Lakeside [--tag wan_router] [--role wan] [--name wlc]
python netbox_helper.py devices --site Lakeside --summary [role,model]   # counts instead of rows
python netbox_helper.py device lakeview-wlc-ha01        # full record: site, role, model, serial, platform, primary IP, tags
python netbox_helper.py vc wp-6flr                      # virtual chassis (stack): master, members, positions, serials
python netbox_helper.py ip 10.158.8.21                  # which device and interface has an IP
python netbox_helper.py prefix 10.158.10.25             # prefixes (site, VLAN, VRF, role) containing an IP
python netbox_helper.py prefixes --site Tulane [--vlan 700] [--vrf buyer] [--search text]   # subnet -> site list
python netbox_helper.py tags
```

`--site` accepts a site name, a slug or a unique part of a name. `--json` gives full output.

**Virtual chassis (switch stacks):** NetBox models a stack as a virtual chassis, for example `wp-6flr` with members `wp-6flr(1)` to `wp-6flr(7)`, and usually only the master has a management IP. Device lookups (`devices`, and `cisco_helper.py -d/--site/--name`) return each stack as **one** device, named after the virtual chassis, connecting to the master's IP, and listing its `members`. Use `devices --members` to list members separately, and `vc <name>` for member details.

## Skills

Each task's guide is a project skill under `.claude/skills/`. Load it before doing the task.

| Skill | Helper | Use it for |
|---|---|---|
| `device-lookup` | `netbox_helper.py`, `cisco_helper.py locate`, `endpoint_helper.py` | Find a device or endpoint by name/IP/MAC; which system to ask first; trace an IP or MAC to its switchport |
| `cisco-devices` | `cisco_helper.py` | Any show command on a router/switch/WLC; route questions ("where is 10.x routed"); VRFs on the cores; 9800 SSIDs; wireless clients; adding a platform |
| `network-reports` | `endpoint_helper.py`, `audit_helper.py`, `report_helper.py` | `whois` an IP/MAC, `path` between two IPs through the firewalls, NetBox drift audits, the daily health brief |
| `meraki` | `meraki_helper.py` | Meraki networks, devices, APs, clients, SSIDs, wireless health, MX WAN/VPN/VLANs/firewall, MS ports, events, change log, licenses |
| `ordr` | `ordr_helper.py` | What an endpoint is: identity, profile, risk, alarms, vulnerabilities (first stop for a non-Cisco device) |
| `catalyst-center` | `catalyst_helper.py` | Managed device inventory and assurance: health, issues, configs, where a client MAC is connected |
| `ise` | `ise_helper.py` | Authentication: where and how a MAC/IP/user authenticated, failures, NADs, policy sets |
| `cdo-firewall-policy` | `cdo_helper.py` | FTD config and policy: does a prefilter/access rule allow this, NAT, interfaces, routes, objects |
| `ftd-packet-captures` | `ftd_capture_helper.py` | Live "is this traffic allowed?" captures on the FTDs (the only write action) |
| `thousandeyes` | `thousandeyes_helper.py` | ThousandEyes tests, agents, alerts, account groups (token in env var `TE_API`) |
| `bgp-community` | `bgp_community.py` | BGP communities and AS per WAN router; the site/router map in `bgp_community.txt` |

Every helper takes `--json` and `-o FILE [--append]`. The bulk list commands take `--summary` (counts instead of rows) and `--limit N`. Start with `--summary` when a list could be large.

## Files

| File | Role |
|---|---|
| `netbox_helper.py` | **The inventory** (commands above). Also `get_devices()` and `PLATFORM_MAP` (NetBox platform slug to netmiko device_type) |
| `cisco_helper.py` | Read-only show commands on Cisco devices over SSH, `route`, `locate <ip\|mac>`, `wclient <mac>` |
| `catalyst_helper.py`, `ise_helper.py`, `ordr_helper.py`, `meraki_helper.py`, `cdo_helper.py`, `thousandeyes_helper.py` | Read-only clients and CLIs for each system (see their skills) |
| `ftd_capture_helper.py` | Packet captures on the `FTD_CAPTURE_HOSTS` firewalls, active unit only. **The only helper that changes anything on a device.** Logs every change to `captures/audit.log` |
| `endpoint_helper.py`, `audit_helper.py`, `report_helper.py` | Combined read-only answers: `whois`, `path`, NetBox drift audits, `daily` brief (`--no-cdo` skips your personal CDO key) |
| `bgp_community.py` | Reads each router's BGP outbound route-map (`set community`) and writes `bgp_community.txt` (site, router, IP, AS, community) |
| `vault_helper.py` | Vault login (`VAULT_TOKEN`, then `~/.vault-token`, then OIDC browser login), `get_secrets()` and `get_secret(key)` |
| `helper_common.py` | Shared output code: `table()`, `to_json()`, `Out` (for `-o FILE`), MAC formatting. New helpers use it |
| `vault_login.ps1` / `vault_login.sh` | Vault OIDC login in a private browser window; also save `VAULT_ADDR` from `.env` permanently (`-NoPersist` / `-n` skips that) |
| `vault_list.py` | Lists the Vault secrets the logged-in account can see; also signs in as a different user |
| `set_vault_addr.ps1` | **Local only** (in `.gitignore`, holds the internal Vault address). No longer needed; `vault_login.ps1` does this |
| `tools/leak_check.py`, `.githooks/pre-commit` | Leak guard: blocks commits containing `.env` values, personal secrets, or token/key patterns |
| `tests/` | Offline tests for the parsers and policy matching: `python -m pytest -q`. `.github/workflows/checks.yml` runs them, the leak check and gitleaks on every push |
| `.env` | `VAULT_ADDR`, `VAULT_MOUNT`, `VAULT_PATH`, `CDO_URL`, `FTD_CAPTURE_HOSTS`, optional `LCMC_CACERT` (none are secrets). **The only place the Vault address is kept**, and it wins over a `VAULT_ADDR` environment variable. For the other keys an environment variable wins. Never hard-code the address in a tracked file |
| `.env.old` | Backup. Do not read it, use it or change it |

Vault secrets at `VAULT_MOUNT`/`VAULT_PATH`: `ansible_user`, `ansible_password`, `ansible_become_password`, `netbox_url`, `netbox_token`, `meraki_api`, `ORDR_URL`, `ORDR_USER`, `ORDR_PASSWORD`, `ORDR_TENANTGUID`, `ise_url`, `ise_user`, `ise_password`, `cat_url`, `cat_user`, `cat_password`.

## Rules

- Never print, log or write the credentials (`ansible_*`, `netbox_token`, `meraki_api`, `ORDR_*`, `ise_*`, `cat_*`, or the other keys at the Vault path) or a Vault token. Do not run `vault_list.py --show-values` unless the user explicitly asks.
- `TE_API`, `CDO_UUID`, `CDO_API`, `CISCO_SRV_ACCOUNT` and `CISCO_SRV_PWD` are environment variables. Never print them, log them or write them to a file.
- Never put secrets in `.env`. Do not touch `.env.old`.
- **Devices:** only read-only `show` commands. No config mode, no `write`, no `clear`, no `reload`, nothing that changes state. Run them only when the user asks for information from the devices, and keep to the devices the question needs. **The one exception** is `ftd_capture_helper.py`, which may create, start, stop and remove packet captures on the `FTD_CAPTURE_HOSTS` firewalls under the rules in the `ftd-packet-captures` skill.
- **Every other system is read-only and goes through its helper, which only sends `GET`** (Catalyst Center also POSTs for its auth token). Never send `POST`, `PUT` or `DELETE` to Meraki, Catalyst Center, ISE, Ordr or CDO/FMC unless the user explicitly asks for that specific change and confirms it. That includes Catalyst Command Runner, templates, provisioning, reboots and syncs; ISE CoA, reauthenticate or disconnect (`/admin/API/mnt/CoA/...`); and Ordr's alarm, vulnerability, asset, onboarding and user write endpoints.
- **No ad-hoc snippets.** Use the helpers. If one can't do what's needed, extend it (and its doc), test it, then use it.
- **NetBox is the source of truth for inventory.** Look devices up there first.

## Vault login

The helpers reuse `VAULT_TOKEN` or `~/.vault-token`. If neither is valid, they open a browser OIDC login and save the new token to `~/.vault-token`. The Vault address always comes from `VAULT_ADDR` in `.env`.

**If the normal login picks the wrong Microsoft account** (for example a Sapphire account, which fails with `samaccountname not found`), use the private-browser login scripts. They are interactive, so ask the user to run them (or run one only when the user asks):

```
powershell -ExecutionPolicy Bypass -File .\vault_login.ps1      # Windows: Edge InPrivate (-Browser chrome|firefox, -Prompt login, -NoPersist)
./vault_login.sh                                               # macOS / Linux: Chrome incognito (-b edge|firefox, -p login, -n)
python vault_list.py --private --prompt login                  # sign in as a different account
```

Known problem: `claim "samaccountname" not found in token` means the account has no on-prem sAMAccountName in LCMC's tenant (a guest or B2B account such as a Sapphire account). Sign in with an LCMC account. Do not change the code to work around it.

## Setup

```
python -m pip install -r requirements.txt
python cisco_helper.py list
git config core.hooksPath .githooks     # once per clone: the leak-guard pre-commit hook
python -m pytest -q                     # offline tests; run them after changing a parser
```

**Before committing:** the repo is public. The pre-commit hook refuses commits that contain internal addresses or secrets. Use placeholders in examples (`192.0.2.x`, `198.51.100.x`, `<vault-host>`). Never bypass it with `--no-verify`.

If Vault or NetBox use an internal CA, `truststore` lets Python use the Windows certificate store. Otherwise set `VAULT_CACERT`.

### LCMC internal CA (ISE and Catalyst Center)

ISE (`umc-ise-pan-01`) and Catalyst Center (`ej-dnac-01`) use certificates from LCMC's internal PKI (root `EPIC-CA`, intermediates `EPIC-ICA01` and `EPIC-ICA02`), which isn't trusted on this Sapphire laptop. Vault, NetBox, Meraki and Ordr use public certificates. The root's SHA-256 fingerprint is `7A553FD7BE90FF6293A808BCF9FDF4230A2F622C70C8621C109B484BA6B4A0A4`, valid to 2064. Either install EPIC-CA as a trusted root for the current user, or set `LCMC_CACERT` (in `.env`) to the EPIC-CA PEM (`ISE_CACERT` and `CAT_CACERT` still work for one helper each). Never turn off certificate verification.
