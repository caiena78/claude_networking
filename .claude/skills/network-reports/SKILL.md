---
name: network-reports
description: Combined, read-only answers across every system - "whois" for an IP or MAC (what it is and where it's plugged in), "path" between two IPs through the firewalls (which FTD, which rule decides), NetBox drift audits (prefixes, devices, Meraki VLANs vs what the network shows), and the daily network health brief. Use for "what/where is this device", "can A reach B on port N", "is NetBox right", or "how is the network today".
---

# Combined reports

These helpers call the other helpers and add nothing that writes. Use them first for these questions, and use the single-system helpers when the user wants more detail on one part.

## whois: what and where is an IP or MAC

```
python endpoint_helper.py whois 10.158.0.139            # IP: NetBox, switchport trace, then identity
python endpoint_helper.py whois ac:b4:80:b9:a0:1f       # MAC (any format)
python endpoint_helper.py whois <ip|mac> --all          # ask Ordr, ISE and Catalyst even after one answered
python endpoint_helper.py whois <ip> --no-trace         # skip the switchport trace (faster)
```

1. **NetBox:** the prefix (site, VLAN, VRF) and any device the IP is assigned to.
2. **Where it's plugged in (IP only):** `cisco_helper.py locate`, which follows the WAN routers to the gateway, then ARP, the MAC table and CDP, to the access switchport. Meraki sites are skipped here.
3. **What it is,** in the team's lookup order, stopping at the first system that knows it: **Ordr**, then **ISE**, then **Catalyst Center**.
4. **Meraki:** used if the prefix is at a Meraki site, if nothing above knew the MAC, or with `--all`.

Each system that is down is reported and skipped. Report the location, the identity and any mismatch between the systems. For example, compare the switchport from `locate` with Ordr's `nwEquipHostname`/`nwEquipInterface` and with ISE's NAS and port. If `locate` says the MAC has aged out but Ordr or ISE still names a port, say so.

## path: can A reach B on a port, and which firewall rule decides

```
python endpoint_helper.py path 155.58.39.10 10.194.2.10 --port 443 [--proto tcp|udp|icmp]
python endpoint_helper.py path ... --all-firewalls      # also evaluate the "possible" firewalls
```

- Finds every **CDO-managed FTD** where the two ends sit behind different interfaces, using connected subnets first, then the most specific static route.
  - **"on path":** both ends are known specifically. These firewalls are fully evaluated.
  - **"possible":** one end is known only through a default route, typically an internet firewall that summarises RFC1918 inside. These are listed but not evaluated unless you pass `--all-firewalls`.
- **Verdicts follow evaluation order:**
  1. The **prefilter policy** goes first. FASTPATH means allowed with the access policy skipped, and BLOCK means denied.
  2. Otherwise the **access control policy** decides: the first matching rule, or the policy's default action.
  3. Any NAT rule that rewrites the destination is shown.
- **What it doesn't evaluate:** zones and interfaces on rules, and app/URL/user conditions. Rules with those conditions are listed as "passed over" and may match first in practice.
- **What it can't see:** Meraki MXs and non-Cisco firewalls.
- **To prove a verdict** with live traffic, use the `ftd-packet-captures` skill.
- **Timing:** about 40 seconds, most of it loading CDO objects.

## NetBox drift audits

```
python audit_helper.py prefixes --site "Lakeview Hospital"   # NetBox prefixes vs subnets connected on the site's cores
python audit_helper.py devices [--source catalyst|meraki|all] # devices NetBox lacks (by serial) or names differently
python audit_helper.py meraki-vlans [--network PUC]           # Meraki MX VLAN subnets with no NetBox prefix
```

- **`prefixes`:**
  - Runs `show ip route connected` on the site's cores, in the global table and, for the `CORE_VRFS` sites, in VRFs `buyer` and `div` too.
  - Lists subnets connected but missing from NetBox, subnets NetBox places at another site, and NetBox prefixes (with a VLAN) that aren't connected on any core.
  - It takes about 30 seconds.
  - **Known finding (2026-10-12):** 57 subnets connected on the Lakeview core (10.67.240-246.x, 10.69.64-79.x, in the global table and VRF `div`) are recorded at Tulane in NetBox. These are probably the isolated Tulane networks carried on the Lakeview core, so ask before calling them errors.
- **`devices`:**
  - Compares Catalyst Center (without APs) and Meraki serials with NetBox.
  - Names are compared ignoring case, domain and NetBox's `(n)` stack-member suffix.
  - It takes about 70 seconds.
  - **Results on 2026-10-12:** 20 of 333 Catalyst devices were missing from NetBox, and 1 had a real name difference (`CHN-ERTWR-...` vs `chn-ETWR-...`). NetBox tracks **no** Meraki devices, so all 219 show as one line.
- **`meraki-vlans`:**
  - Compares every MX VLAN subnet with NetBox prefixes (exact match).
  - On 2026-10-12, 63 of the 189 subnets were missing from NetBox.

These only report. NetBox changes are the user's to make. Present each list as "fixes to consider".

## Daily health brief

```
python report_helper.py daily [-o brief.txt] [--no-cdo] [--json]
```

- **Meraki:** devices offline or alerting, WAN uplinks down, online MXs with unreachable AutoVPN peers, critical alerts from the last 7 days, and subscriptions that aren't active.
- **Catalyst Center:** unreachable switches, routers and WLCs (listed), unreachable APs (as a count), active P1 issues, and P2 issues grouped by type.
- **ISE:** the active session count.
- **CDO:** firewalls whose health isn't green.

It takes about 15 seconds. CDO uses the **personal** CDO key of whoever runs it, so pass `--no-cdo` for a shared or scheduled run if that matters. To run it every morning, use Windows Task Scheduler with `python <repo>\report_helper.py daily -o <file>`. It runs as the person who scheduled it.

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).
