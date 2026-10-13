---
name: ise
description: Cisco ISE through ise_helper.py: where a MAC, IP or user is authenticated (switch/port or WLC), 802.1X vs MAB, policy/authorization profile/VLAN/SGT, recent auth failures, active sessions, network devices (NADs), policy sets.
---

# Cisco ISE

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
python ise_helper.py active --limit 20                # sample of active sessions (default 50, 0 = all)
python ise_helper.py active --summary [--limit 10]    # totals (sessions, with user, with IP), counts by PSN and by NAS IP
python ise_helper.py nad 10.158.136.51                # network device by IP, or name substring
python ise_helper.py nads --name wan [--limit N]       # list NADs (id, name)
python ise_helper.py nads --summary --name tls        # counts by device group (Location, Device Type, IPSEC, DNAC), profile, model
python ise_helper.py groups                           # endpoint identity groups
python ise_helper.py nodes                            # deployment nodes and roles
python ise_helper.py policy-sets [--device-admin]
python ise_helper.py ers sgt                          # any ERS resource; -f name.CONTAINS.x ; --id <uuid>
python ise_helper.py mnt Session/ActiveCount          # any MnT path
python ise_helper.py api deployment/node              # any OpenAPI path
```

- Every command takes `-o FILE` (also write the output to a file) and `--append`; `--json`, `-o` and `--append` work before or after the subcommand.
- `active --summary` covers all active sessions. The active list only has user, MAC, framed IP, NAS IP and PSN (`server`), so it counts by PSN and NAS IP; `--limit` caps the rows per count. For auth protocol/method use `active --protocols` (one lookup per session, slower).
- `nads --summary` fetches each NAD's full record (one ERS call each; there are about 1,200 NADs, so narrow with `--name` or `--limit`). Group values are the tail of the NDG path, e.g. `Location#All Locations#TLS` -> `TLS`.
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

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).
