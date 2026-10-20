---
name: nmap
description: Ping sweeps and port scans of internal addresses through nmap_helper.py - which addresses in a subnet answer, which of them NetBox doesn't know, which TCP/UDP ports are open on a host or range. Use for "ping sweep 10.x.x.0/24", "what's alive in this subnet", "is port 443 open on these hosts", "scan these IPs for open ports".
---

# nmap (nmap_helper.py)

**Use `nmap_helper.py` for any nmap scan.** Never run `nmap` directly. The helper looks for `nmap` on PATH first and stops with `nmap not found` if it isn't there; tell the user to install nmap and add it to PATH (don't go looking for it elsewhere). It only offers ping sweeps and port scans, on private (internal) IPv4 targets, and is polite by default. If you need something it doesn't do, tell the user; don't work around it.

```
python nmap_helper.py sweep 10.158.8.0/24                       # which addresses answer
python nmap_helper.py sweep 10.158.8.0/24 --netbox              # and which NetBox device has each one ("-" = NetBox doesn't know it)
python nmap_helper.py sweep 10.158.8.0/24 --tcp-ping 22,443     # also probe TCP ports, for hosts that drop ICMP
python nmap_helper.py ports 10.158.8.21 --ports 22,80,443,8443  # TCP connect scan of chosen ports
python nmap_helper.py ports 10.158.8.0/28 --top 100             # the N most common ports (10,20,50,100,200,500,1000)
python nmap_helper.py ports lakeview-wlc-ha01 --ports all       # all TCP ports (16 addresses at most)
python nmap_helper.py ports 10.158.8.21 --ports 161 --udp       # UDP: admin rights, 64 addresses and 100 ports at most
python nmap_helper.py sweep 10.158.8.0/24 --dry-run             # show targets and the nmap command, scan nothing
```

Targets: an IP, a CIDR, a range (`10.1.1.10-50` or `10.1.1.10-10.1.2.20`) or an exact NetBox device name (resolved to its management IP). `--exclude TARGET` (repeatable) leaves addresses out. Other options: `--syn` (SYN scan, admin rights), `--no-ping` (`-Pn`), `--all-states` (also closed/filtered), `--dns`, `--json`, `-o FILE [--append]`.

## Rules

- **Run a scan only when the user asks for one, on the addresses they name.** Scans send real traffic. Fragile hospital and medical devices can misbehave under scanning, so prefer the smallest range and port list that answers the question, and run `--dry-run` first for anything over a /24 and tell the user the size before running it.
- **Limits the helper enforces (don't try to get around them):** private IPv4 only (no public, loopback, link-local or multicast addresses); 1,024 addresses per scan (`--max-targets`, hard limit 4,096); 300 packets/s by default (`--rate`, max 1,000); nmap timing `-T3` at most; scans of more than 1,024 ports limited to 16 addresses; UDP limited to 64 addresses and 100 ports.
- **Not available, on purpose:** NSE scripts, OS and version detection, and any spoofing, decoy, fragmentation or other evasion option. Don't add them.
- Every scan is logged to `scans/audit.log` (git-ignored): UTC time, local user, targets and the exact command.
- A host that doesn't answer discovery is reported as down. If the user expects it up, retry with `--tcp-ping` or `--no-ping`, and say that a silent result is not proof the address is unused (firewalls drop probes).
- NetBox is still the inventory: to say what a responding address is, use `--netbox`, then `netbox_helper.py`, `ordr_helper.py` or `whois` (network-reports skill).

Follow the ground rules and the Rules section in CLAUDE.md.
