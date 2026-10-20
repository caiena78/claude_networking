# NETCONF first (cisco_helper.py and netconf_helper.py)

Before a command runs on an IOS/IOS-XE device, `cisco_helper.py` checks TCP 830. If it is open and the command has a NETCONF version, it queries over NETCONF (`get` only) and prints the same kind of table; otherwise it uses SSH.

- The header shows `[netconf]` or `[ssh]`. `--json` has `transport`, `netconf_port` and, after a failed attempt, `netconf_error`.
- `--transport ssh` skips the NETCONF check; `--transport netconf` fails instead of falling back.
- Commands with a NETCONF version: `python netconf_helper.py list` (version, uptime, clock, interfaces, interface, errors, cpu, memory, arp, cdp, lldp, ntp, wlans).
- Everything else stays on SSH: `show "..."`, `run`, `section`, `log`, `route`, `locate`, `bgp`, `ospf`, `wclient`, `ssid`, `ssid-count`, `ssid-clients`, `ssid-auth` (the YANG client model has no EAP type), `--parse`, AireOS WLCs and devices with 830 closed.
- NETCONF output is a rendered table, not the CLI text. `interface` over NETCONF needs the full interface name (`TenGigabitEthernet0/1/0`); abbreviations fall back to SSH.
- The WLAN PSK comes back in clear text over NETCONF, so the helper never selects it and masks it in `netconf_helper.py get`.

Exploring a device before adding a command (all read-only):

```
python netconf_helper.py probe  -d tls-wan-rtr-01
python netconf_helper.py caps   -d tls-wan-rtr-01 --filter oper
python netconf_helper.py schema -d tls-wan-rtr-01 --module Cisco-IOS-XE-arp-oper     # the YANG model
python netconf_helper.py get    -d tls-wan-rtr-01 --xpath "<arp-data xmlns='http://cisco.com/ns/yang/Cisco-IOS-XE-arp-oper'/>"
```

`get` takes an XPath or, when it starts with `<`, a subtree filter. Output is cut at `--max-chars` (default 20000). To add a command, add an entry to `RENDERERS` in `netconf_helper.py` (filter + renderer) and a test in `tests/test_netconf_helper.py`. Not every model exists on every device: a failed query falls back to SSH.
