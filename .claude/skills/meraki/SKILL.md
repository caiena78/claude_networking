---
name: meraki
description: Cisco Meraki Dashboard through meraki_helper.py: Meraki networks/sites (PUC_*, LRPG *, CHMPC *, CC_*, hospital guest MXs, UMC concentrators), devices and APs, clients, SSIDs, wireless health and rogues, MX WAN uplinks, AutoVPN, VLANs, firewall/NAT, MS switch ports, events, alerts, config change log, licenses. Use for any Meraki question.
---

# Cisco Meraki

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
python meraki_helper.py licenses --devices LIC-MX-L-E      # which MX/Z devices use a license class (also MX-M, 'MX Small', Z) + its seats
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

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).
