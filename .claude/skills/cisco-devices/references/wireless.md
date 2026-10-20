# Wireless controllers (cisco_helper.py: 9800 and AireOS)

9800 WLCs are IOS-XE (`cisco_xe`) in NetBox, e.g. `lakeview-wlc-ha01`. AireOS WLCs (NetBox platform `airos`: 5508, 5520, 8540, 3504) use netmiko `cisco_wlc_ssh`. Code: `cisco_wlc.py` (parsers, per-SSID collectors) and `AIREOS_COMMANDS` in `cisco_helper.py`.

```
python cisco_helper.py wlans -d lakeview-wlc-ha01                 # WLAN/SSID summary
python cisco_helper.py ssid-count -d <wlc>                        # clients per SSID (two commands, fast); no -d = every WLC
python cisco_helper.py ssid-clients LCMC-IOTS -d <wlc> -o macs.txt   # client MACs on an SSID
python cisco_helper.py ssid-auth LCMC-VOIP -d <wlc>               # clients on an SSID by EAP type (slow, see below)
python cisco_helper.py ssid LCMC-DATA -d lakeview-wlc-ha01 -o ssid.txt   # all config for an SSID
python cisco_helper.py wclient 78:02:8b:19:63:0e                  # one client on every WLC: AP, SSID, VLAN, IP, user
python cisco_helper.py wclient <mac> -d umc-wlc-8540-01           # one controller; anchor/foreign mobility is shown
```

- **Manufacturers on an SSID:** `ssid-clients ... -o macs.txt`, then `python ordr_helper.py devices --macs-file macs.txt --limit 0 --summary` (the manufacturer names are Ordr's, and it reports MACs it doesn't know).
- **`ssid-auth`** reads `EAP Type` from each client's detail, one command per client: about 3 minutes for 226 clients, and the 5520's big client table needs `--timeout 120`. Faster for the same split: `python ise_helper.py active --protocols --ssid <ssid>`. EAP type `Not Applicable` (9800) or `Unknown` (AireOS) means no 802.1x EAP (PSK, open, or an anchor stub).
- **`ssid <name>`** on a 9800 matches the SSID or the WLAN profile name, so it handles one SSID on several profiles. It collects the `wlan` config, the policy tags that map it, each policy profile, and `show wlan name`. PSKs (`set-key`) are masked. On AireOS it runs `show wlan <id>` for each match.
- **`--cache SECONDS`** reuses the WLC's `show` output for `ssid-count`, `ssid-clients` and `ssid-auth` if it is that fresh (stored in `.cache/`, which is in `.gitignore`); the default is always live.
- **`--json`** drops the raw `output` for `wclient` and the `ssid-*` commands (the parsed fields are there); add `--raw` to keep it.
- **AireOS built-ins:** `version`/`uptime` (`show sysinfo`), `interfaces`, `interface <name>`, `inventory`, `cdp`, `cdp-detail`, `cpu`, `memory`, `clock`/`ntp` (`show time`), `license`, `users`, `wlans`, `run`, plus the commands above. Any other built-in is refused and the error lists the supported ones. AireOS has no NETCONF.
- **Double counting:** an AireOS client summary also lists anchored and foreign clients (`Role` column), so one client can be counted on both the anchor and the foreign WLC. Counts are live snapshots of the controller's client table, whatever the client state.
- To add an AireOS command, add a mapping to `AIREOS_COMMANDS`.
