---
name: device-lookup
description: Finding a device or endpoint and where it is plugged in - by name, IP, MAC or site. Covers which system to ask first (NetBox for Cisco gear; Ordr, ISE, Catalyst Center, Meraki for PCs, printers, phones, medical/IoT devices) and tracing an IP or MAC to its switchport with cisco_helper.py locate. Use for "where is 10.x.x.x plugged in", "what port is this IP/MAC on", "find device X", "what is this MAC", "which switch/AP is it on".
---

# Finding a device

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

## Finding the switchport for an IP

"Where is 10.x.x.x plugged in", "what port is this IP on": trace it through the network with `cisco_helper.py locate`:

```
python cisco_helper.py locate <ip>                         # full trace; --json for every step
python cisco_helper.py locate <mac> -d <router or switch>  # MAC trace from a starting device (e.g. the core)
```

`locate` does what you would do by hand, using only `show` commands:

1. **NetBox** `prefix <ip>`: the subnet, its site, VLAN and VRF. NetBox's prefix list is the subnet-to-site map, and `netbox_helper.py prefixes --site X` lists a site's subnets. A subnet can appear twice, once with the site in the global VRF and once in VRF `buyer` with no site, and the helper takes the site from the row that has one. `ip <ip>`: whether the IP is assigned to a device.
2. **Route lookup on the `wan_router` devices** at that site (or on every `wan_router` if the site has none, or none of them has a specific route, because NetBox's site can be stale). Then follow the next hop router by router, finding each next hop's device in NetBox, until a device has the subnet **directly connected**. That device is the gateway, usually the site core.
3. **`show ip arp <ip>`** on the gateway gives the MAC and the SVI.
   If that finds nothing, the subnet may be an **isolated network**. The helper then asks the cores at Lakeview Hospital, Lakeside and Tulane directly in VRF `div` and in the global table, starting with NetBox's site (see "VRFs on the cores" in the `cisco-devices` skill).
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

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).
