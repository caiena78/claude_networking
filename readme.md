# claude-network

Read-only network tools for LCMC Health. Each `*_helper.py` script covers one system:

| Helper | System | Used for |
|---|---|---|
| `netbox_helper.py` | NetBox | **The inventory**: sites, devices, IPs and prefixes |
| `cisco_helper.py` | Cisco devices over SSH | Show commands, route lookups, WLAN/SSID config |
| `catalyst_helper.py` | Catalyst Center | Inventory sync, interfaces, clients, site and device health, issues |
| `ise_helper.py` | Cisco ISE | Endpoints, sessions, authentications, network devices, policy sets |
| `meraki_helper.py` | Meraki Dashboard | Networks, devices, SSIDs, subnets |
| `ordr_helper.py` | Ordr | What an endpoint is: classification, risk, alarms, vulnerabilities |
| `vault_helper.py` | HashiCorp Vault | Login and credentials for all of the above (used by the other helpers) |

Every helper is read-only. All credentials come from Vault; nothing is stored in this folder. Add `--json` to most commands for machine-readable output, and `-h` to any command for its options.

The examples below use placeholder names and addresses (`site1-wan-rtr-01`, `192.0.2.x`, `00:11:22:33:44:55` and so on). Replace them with your own.

## Setup

1. Install the Vault CLI:
   - Windows: https://developer.hashicorp.com/vault/install
   - macOS: `brew tap hashicorp/tap && brew install hashicorp/tap/vault`
2. Install the Python packages:

       python -m pip install -r requirements.txt

3. Set the Vault address once (Windows), or export `VAULT_ADDR` in your shell profile (macOS):

       powershell -ExecutionPolicy Bypass -File .\set_vault_addr.ps1

4. Create `.env` with `VAULT_ADDR`, `VAULT_MOUNT`, `VAULT_PATH` and `LCMC_CACERT=certs/lcmc-epic-ca.pem`. The CA file lets Python trust the internal certificates that ISE and Catalyst Center use.

## Logging in to Vault

A token lasts about 32 days, and every helper reuses it from `~/.vault-token`.

    vault login -method=oidc

If the browser signs in with the wrong Microsoft account (for example a xyzcorp account, which fails with `claim "samaccountname" not found`), log in from a private window instead:

    powershell -ExecutionPolicy Bypass -File .\vault_login.ps1     # Windows (Edge InPrivate)
    chmod +x vault_login.sh && ./vault_login.sh                   # macOS (Chrome incognito)
    python vault_list.py --private --prompt login                 # any OS, also lists your Vault secrets (values hidden)

## netbox_helper.py — inventory

    python netbox_helper.py sites --name Site                        # sites whose name contains "Site"
    python netbox_helper.py devices --site "Site 1" --tag wan_router # devices with management IP, role, model, platform
    python netbox_helper.py devices --site "Site 1" --name wlc
    python netbox_helper.py device site1-wlc-01                      # full record: model, serial, platform, IP, tags
    python netbox_helper.py ip 192.0.2.21                            # which device and interface has an IP
    python netbox_helper.py prefix 192.0.2.25                        # prefixes containing an IP (site, VLAN, VRF)
    python netbox_helper.py tags

## cisco_helper.py — show commands on Cisco devices

Choose devices with `-d <name or IP>` (repeatable), `--site`, `--tag` or `--name`. Names are looked up in NetBox. Only `show` commands are sent, and passwords, keys and communities are masked in config output.

    python cisco_helper.py list                                       # all built-in commands
    python cisco_helper.py uptime --site "Site 1" --tag wan_router
    python cisco_helper.py version -d site1-wan-rtr-01
    python cisco_helper.py interfaces -d site1-wan-rtr-01             # show ip interface brief
    python cisco_helper.py interface Te0/1/0 -d site1-wan-rtr-01
    python cisco_helper.py errors -d site1-wan-rtr-01                 # CRC / input / output errors
    python cisco_helper.py section "router bgp" -d site1-wan-rtr-01   # one config section
    python cisco_helper.py run -d site1-wan-rtr-01 -o site1-config.txt   # full config, saved to a file
    python cisco_helper.py log -d site1-wan-rtr-01 --lines 100
    python cisco_helper.py bgp --tag wan_router                       # also: ospf, eigrp, standby, vrrp
    python cisco_helper.py cdp -d site1-wan-rtr-01                    # also: cdp-detail, lldp
    python cisco_helper.py arp 192.0.2.10 -d site1-wan-rtr-01         # also: mac <mac>
    python cisco_helper.py cpu -d site1-wan-rtr-01                    # also: memory, env, inventory, transceivers, ntp
    python cisco_helper.py interfaces -d site1-wan-rtr-01 --parse --json   # structured output (TextFSM)
    python cisco_helper.py show "show ip nat translations total" -d site1-wan-rtr-01   # any single show command

Route lookups run on every WAN router (NetBox tag `wan_router`) unless you pick devices. The summary shows the prefix, protocol, next hops and outgoing interfaces:

    python cisco_helper.py route 192.0.2.1
    python cisco_helper.py route 192.0.2.0/24 --site "Site 1" --vrf CORP
    python cisco_helper.py route 192.0.2.1 --json

Wireless (Catalyst 9800 controllers):

    python cisco_helper.py wlans -d site1-wlc-01                      # WLAN / SSID summary
    python cisco_helper.py ssid CORP-DATA -d site1-wlc-01 -o site1-ssids.txt            # all config for one SSID
    python cisco_helper.py ssid CORP-VOICE -d site1-wlc-01 -o site1-ssids.txt --append

## catalyst_helper.py — Catalyst Center

    python catalyst_helper.py count                                 # devices in inventory
    python catalyst_helper.py devices --hostname "SITE1-.*"         # hostname filters are case-sensitive
    python catalyst_helper.py devices --family "Switches and Hubs" --limit 50   # exact family name
    python catalyst_helper.py devices --reachability Unreachable
    python catalyst_helper.py device site1-wan-rtr-01               # by hostname, IP, serial or id
    python catalyst_helper.py interfaces 192.0.2.51
    python catalyst_helper.py config site1-wan-rtr-01               # config as collected by Catalyst Center
    python catalyst_helper.py client 00:11:22:33:44:55              # where a client is connected (AP/switch, SSID, VLAN)
    python catalyst_helper.py sites
    python catalyst_helper.py health                                # site health
    python catalyst_helper.py device-health --health POOR
    python catalyst_helper.py issues --priority P1
    python catalyst_helper.py get network-device/count              # any Intent API path

## ise_helper.py — Cisco ISE

    python ise_helper.py lookup 0011.2233.4455                      # endpoint record + live session for a MAC
    python ise_helper.py session 192.0.2.65                         # live session by MAC, IP or username
    python ise_helper.py auth 00:11:22:33:44:55 --hours 24          # recent authentications, including failures
    python ise_helper.py active --count                             # number of active sessions
    python ise_helper.py active --protocols                         # sessions by EAP-TLS / PEAP / MAB
    python ise_helper.py nad 192.0.2.51                             # network device by IP or name
    python ise_helper.py nads --name WAN
    python ise_helper.py groups                                     # endpoint identity groups
    python ise_helper.py nodes                                      # deployment nodes and roles
    python ise_helper.py policy-sets
    python ise_helper.py ers sgt                                    # any ERS resource (-f name.CONTAINS.x)

## meraki_helper.py — Meraki Dashboard

    python meraki_helper.py sites                                   # networks with device and online counts
    python meraki_helper.py devices --network Branch-01
    python meraki_helper.py devices --type appliance
    python meraki_helper.py offline                                 # devices that aren't online
    python meraki_helper.py ssids                                   # SSIDs and how many APs broadcast them
    python meraki_helper.py ssids --by-network --network Branch
    python meraki_helper.py get "organizations/{org}/clients/search" -p mac=00:11:22:33:44:55 --one-page
    python meraki_helper.py get networks/<networkId>/appliance/vlans   # any API path (no leading slash)

## ordr_helper.py — Ordr

    python ordr_helper.py device 00:11:22:33:44:55                  # by MAC (any format), IP, or short hostname
    python ordr_helper.py device 192.0.2.25 --include connectivity-info
    python ordr_helper.py devices --group Workstations --risk HIGH --limit 50
    python ordr_helper.py devices --conn-status ONLINE_IN_LAST_24_HRS --limit 0
    python ordr_helper.py alarms --severity high --limit 20
    python ordr_helper.py vulns --mac 00:11:22:33:44:55
    python ordr_helper.py summary                                   # alarm and vulnerability summaries
    python ordr_helper.py profiles
    python ordr_helper.py get Rest/Devices -p mfg=Philips --all     # any API path

## Other scripts

    python bgp_community.py                                         # BGP community each WAN router sets -> bgp_community.txt
    python vault_list.py --reuse-token                              # list the Vault secrets you can see (values hidden)

## Notes

- Output files (`*.txt`) and `.env` are excluded by `.gitignore`. Never commit router configs or secrets.
- If a helper can't do something you need, extend the helper rather than writing a one-off script. `CLAUDE.md` has the full details for each helper.
