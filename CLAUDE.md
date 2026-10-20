# claude-network

Network operations toolkit for LCMC Health. It answers questions about routers, switches, WLCs, sites, IPs and endpoints using NetBox (inventory), the devices themselves (NETCONF or SSH), Catalyst Center, ISE, Meraki and Ordr. All credentials come from HashiCorp Vault.

## Ground rules (read first)

1. **Every task goes through a `*_helper.py` script.** For anything the user asks, use the matching helper. **If the helper can't do what's needed, update the helper first.** Add the command or option, test it read-only, document it (in its skill), then use it to do the task. Never work around a helper with ad-hoc Python, netmiko or `requests` snippets. Edit files with the Edit tool, not Python run from a shell heredoc (escapes break).
2. **NetBox is the inventory.** Use `netbox_helper.py` (or `cisco_helper.py`, which resolves devices through NetBox) to find devices, sites, management IPs, roles, models, serials, IP assignments and prefixes. Catalyst Center, ISE, Meraki and Ordr have their own device lists. Use them for their own data (assurance, sessions, Meraki networks, endpoint identity), not as the inventory. If they disagree with NetBox, say so; don't silently prefer them.
3. **Load the skill for the task** (table below). The commands and procedures live there, not here. The NetBox commands are in `device-lookup`.
4. **Don't use the `netbox-netmiko-mcp` MCP tools** (`mcp__netbox-netmiko-mcp__*`), even if they're connected. That server is abandoned, and this repo replaces it.

## Skills

Each task's guide is a project skill under `.claude/skills/`. Load it before doing the task.

| Skill | Helper | Use it for |
|---|---|---|
| `device-lookup` | `netbox_helper.py`, `cisco_helper.py locate`, `endpoint_helper.py` | NetBox inventory (sites, devices, stacks, IPs, prefixes); find a device or endpoint by name/IP/MAC; which system to ask first; trace an IP or MAC to its switchport |
| `cisco-devices` | `cisco_helper.py`, `netconf_helper.py` | Any show command on a router/switch/WLC (NETCONF first, then SSH); route questions; VRFs on the cores; 9800 and AireOS SSIDs, clients and EAP types; adding a platform |
| `network-reports` | `endpoint_helper.py`, `audit_helper.py`, `report_helper.py` | `whois` an IP/MAC, `path` between two IPs through the firewalls, NetBox drift audits, the daily health brief |
| `meraki` | `meraki_helper.py` | Meraki networks, devices, APs, clients, SSIDs, wireless health, MX WAN/VPN/VLANs/firewall, MS ports, events, change log, licenses |
| `ordr` | `ordr_helper.py` | What an endpoint is: identity, manufacturer, profile, risk, alarms, vulnerabilities (first stop for a non-Cisco device) |
| `catalyst-center` | `catalyst_helper.py` | Managed device inventory and assurance: health, issues, configs, where a client MAC is connected |
| `ise` | `ise_helper.py` | Authentication: where and how a MAC/IP/user authenticated, failures, NADs, policy sets; fastest EAP-TLS vs PEAP split per SSID |
| `cdo-firewall-policy` | `cdo_helper.py` | FTD config and policy: does a prefilter/access rule allow this, NAT, interfaces, routes, objects |
| `ftd-packet-captures` | `ftd_capture_helper.py` | Live "is this traffic allowed?" captures on the FTDs (the only write action) |
| `thousandeyes` | `thousandeyes_helper.py` | ThousandEyes tests, agents, alerts, account groups (token in env var `TE_API`) |
| `bgp-community` | `bgp_community.py` | BGP communities and AS per WAN router; the site/router map in `bgp_community.txt` |

**"TE" means ThousandEyes** (use the `thousandeyes` skill and `thousandeyes_helper.py`).

Every helper takes `--json` and `-o FILE [--append]`. The bulk list commands take `--summary` (counts instead of rows) and `--limit N`. Start with `--summary` when a list could be large. `cisco_helper.py --json` drops the raw device output when parsed fields exist (`--raw` keeps it).

## Files

| File | Role |
|---|---|
| `netbox_helper.py` | **The inventory.** Also `get_devices()` and `PLATFORM_MAP` (NetBox platform slug to netmiko device_type) |
| `cisco_helper.py` (+ `cisco_common.py`, `cisco_parse.py`, `cisco_wlc.py`) | Read-only commands on Cisco devices, NETCONF first when TCP 830 is open, else SSH; `route`, `locate`, WLC/SSID commands. `cisco_common.py` has the read-only guard (`validate_show`) and secret masking |
| `netconf_helper.py` | Read-only NETCONF (`get`, `get-config`, `get-schema`) for IOS-XE: `probe`, `caps`, `get`, `schema`, `list`, and the NETCONF versions of built-in commands |
| `catalyst_helper.py`, `ise_helper.py`, `ordr_helper.py`, `meraki_helper.py`, `cdo_helper.py`, `thousandeyes_helper.py` | Read-only clients and CLIs for each system (see their skills) |
| `ftd_capture_helper.py` | Packet captures on any NetBox platform-`ftd` firewall, active unit only; `vpn` shows RA VPN sessions (read-only). **The only helper that changes anything on a device.** Logs every change to `captures/audit.log` |
| `endpoint_helper.py`, `audit_helper.py`, `report_helper.py` | Combined read-only answers: `whois`, `path`, NetBox drift audits, `daily` brief (`--no-cdo` skips your personal CDO key) |
| `bgp_community.py` | Reads each router's BGP outbound route-map and writes `bgp_community.txt` |
| `vault_helper.py`, `vault_login.ps1` / `.sh`, `vault_list.py` | Vault login (`VAULT_TOKEN`, then `~/.vault-token`, then OIDC browser login), `get_secrets()`; private-browser login scripts; list visible secrets |
| `helper_common.py` | Shared output code: `table()`, `to_json()`, `Out` (for `-o FILE`), MAC formatting. New helpers use it |
| `tools/leak_check.py`, `.githooks/pre-commit` | Leak guard: blocks commits containing `.env` values, personal secrets, or token/key patterns |
| `tests/` | Offline tests: `python -m pytest -q`. `.github/workflows/checks.yml` runs them, the leak check and gitleaks on every push |
| `docs/setup.md` | Vault login trouble (wrong Microsoft account, `samaccountname`) and the LCMC internal CA for ISE and Catalyst Center. Read it only when login or certificates fail |
| `.env` | `VAULT_ADDR`, `VAULT_MOUNT`, `VAULT_PATH`, `CDO_URL`, optional `LCMC_CACERT` (none are secrets). **The only place the Vault address is kept**, and it wins over a `VAULT_ADDR` environment variable. Never hard-code the address in a tracked file |
| `.env.old` | Backup. Do not read it, use it or change it |

Vault secrets at `VAULT_MOUNT`/`VAULT_PATH`: `ansible_user`, `ansible_password`, `ansible_become_password`, `netbox_url`, `netbox_token`, `meraki_api`, `ORDR_URL`, `ORDR_USER`, `ORDR_PASSWORD`, `ORDR_TENANTGUID`, `ise_url`, `ise_user`, `ise_password`, `cat_url`, `cat_user`, `cat_password`.

## Rules

- Never print, log or write the credentials (`ansible_*`, `netbox_token`, `meraki_api`, `ORDR_*`, `ise_*`, `cat_*`, or the other keys at the Vault path) or a Vault token. Do not run `vault_list.py --show-values` unless the user explicitly asks.
- `TE_API`, `CDO_UUID`, `CDO_API`, `CISCO_SRV_ACCOUNT` and `CISCO_SRV_PWD` are environment variables. Never print them, log them or write them to a file.
- Never put secrets in `.env`. Do not touch `.env.old`.
- **Devices:** only read-only `show` commands over SSH, and NETCONF `get`, `get-config` and `get-schema` (never `edit-config`, `commit`, `lock` or other RPCs). `cisco_helper.py` checks TCP 830 before it runs a command and uses NETCONF when the command has a NETCONF version (`--transport auto|netconf|ssh`), else SSH. No config mode, no `write`, no `clear`, no `reload`, nothing that changes state. Run them only when the user asks for information from the devices, and keep to the devices the question needs. **The one exception** is `ftd_capture_helper.py`, which may create, start, stop and remove packet captures on any firewall with platform `ftd` in NetBox (no separate allow list) under the rules in the `ftd-packet-captures` skill.
- **Every other system is read-only and goes through its helper, which only sends `GET`** (Catalyst Center also POSTs for its auth token). Never send `POST`, `PUT` or `DELETE` to Meraki, Catalyst Center, ISE, Ordr or CDO/FMC unless the user explicitly asks for that specific change and confirms it. That includes Catalyst Command Runner, templates, provisioning, reboots and syncs; ISE CoA, reauthenticate or disconnect (`/admin/API/mnt/CoA/...`); and Ordr's alarm, vulnerability, asset, onboarding and user write endpoints.

## Setup

```
python -m pip install -r requirements.txt
python cisco_helper.py list
git config core.hooksPath .githooks     # once per clone: the leak-guard pre-commit hook
python -m pytest -q                     # offline tests; run them after changing a parser
```

Vault login or certificate problems: see `docs/setup.md`. If Vault or NetBox use an internal CA, `truststore` lets Python use the Windows certificate store; otherwise set `VAULT_CACERT`.

**Before committing:** the repo is public. The pre-commit hook refuses commits that contain internal addresses or secrets. Use placeholders in examples (`192.0.2.x`, `198.51.100.x`, `<vault-host>`). Never bypass it with `--no-verify`.
