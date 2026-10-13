---
name: ordr
description: Ordr endpoint identity through ordr_helper.py: what a device is (group, profile, manufacturer, model, OS), risk, security alarms, vulnerabilities, where Ordr saw it, flows. Especially medical and IoT devices. First stop for a non-Cisco device.
---

# Ordr

Use Ordr for questions about what an endpoint **is**: device identity and classification (group, profile, manufacturer, model, OS), risk, security alarms, vulnerabilities, where a device sits on the network, and its flows and applications. It is especially useful for medical and IoT devices. Use Meraki for Meraki network and client state, and `cisco_helper.py route` for routing.

**Always use `ordr_helper.py` for Ordr.** Don't write ad-hoc `requests` calls. It reads `ORDR_URL`, `ORDR_USER`, `ORDR_PASSWORD` and `ORDR_TENANTGUID` from Vault in one call (`vault_helper.get_secret_values()`), uses HTTP basic auth, adds `tenantGuid` to every request (the API requires it), follows `MetaData.next` pagination, and retries on `429`. It only sends `GET` requests.

Command line (start with these):

```
python ordr_helper.py device 00:11:22:33:44:55         # by MAC (any format), IP, or device name
python ordr_helper.py device 10.158.10.25 --include connectivity-info   # switch/port/AP details
python ordr_helper.py devices --profile "<profile>" --limit 50
python ordr_helper.py devices --group "<group>" --risk High
python ordr_helper.py devices --conn-status ONLINE_IN_LAST_24_HRS --limit 0   # 0 = all
python ordr_helper.py alarms --severity high --limit 20
python ordr_helper.py alarms --mac 00:11:22:33:44:55
python ordr_helper.py vulns --ip 10.158.10.25
python ordr_helper.py summary                          # alarm + vulnerability summaries
python ordr_helper.py devices --group "<group>" --summary --limit 0   # counts instead of rows
python ordr_helper.py alarms --summary --limit 500 -o alarms.txt      # -o FILE also saves the output (--append adds)
python ordr_helper.py reports medical                  # list report names containing "medical" (no login needed)
python ordr_helper.py report high-risk-devices
python ordr_helper.py get Rest/Locations
python ordr_helper.py get Rest/Devices -p mfg=Philips --all
```

- `devices`, `alarms` and `vulns` return 100 rows by default. Use `--limit 0` for everything, but that can be slow for all devices.
- **`--summary`** on `devices`, `alarms` and `vulns` counts the fetched rows instead of listing them. `devices`: by `Group`, `Profile`, `MfgName`, `RiskState`, `connStatus`, `OsType`. `alarms`: by `severityLevel`, `category`, `alarm_type`. `vulns`: by `severityLevel`, `category`, `vulnId`. It counts only the rows `--limit` fetched (it says so when the limit was hit), so use `--limit 0` for true totals. `--top N` shows the N most common values per field (default 20, 0 = all). With `--json` it gives `{"rows": N, "summary": {field: [{value, count}]}}`.
- **`-o FILE`** (any command, before or after the subcommand) also writes the output to a file; `--append` adds to it.
- Add `--json` to `device`, `devices`, `alarms` or `vulns` to get every field. The table shows only the main columns. `summary`, `report`, `locations` and `get` always print JSON.
- `devices` filters match the API query parameters. For others, use `get Rest/Devices -p <param>=<value>`. Examples: `os-type`, `serial`, `vulnIds`, `appName`, `sensorName`, `include=clinical-info`, `openPorts=true`, `weakPassword=true`.
- Useful device fields: `MacAddress`, `IpAddress`, `dhcpHostname`, `Group`, `Profile`, `MfgName`, `ModelNameNo`, `OsType`, `Vlan`, `RiskState`, `riskScore`, `connStatus`, `deviceLocation`, `nwEquipHostname`, `nwEquipInterface`, `essid`, `hasPhi`, `fdaClass`, `firstSeen`, `lastSeen`.
- **Reports don't work on this tenant.** The spec lists about 290 reports (`Rest/Reports/...`, browse them with `reports <text>`), but as of 2026-10 every one returns `400 Unknown report`. Build the answer from `devices`, `alarms` and `vulns` instead, for example with `devices --summary`.
- Paging is verified: `--limit N` asks Ordr for up to N per page and follows `MetaData.next` (`clientMacToken`) until N rows are collected.
- Name lookups (`device <name>`) match the short hostname in any case, so `uws-dt5-lan046` works and the helper strips any domain. They are slow, about a minute, so prefer MAC or IP when you have one. One name can return several devices, for example wired and wireless NICs.
- MAC filters are case-sensitive in Ordr (uppercase only). The helper normalizes MACs for you, so use it rather than raw `get`. A device that isn't found returns an empty list.
- Severity: the `severity-level` filter takes lowercase values (`normal`, `low`, `medium`, `high`, `critical`), but results show them in uppercase (`HIGH`). Alarm categories look like `KNOWN_VULN_CONFIRMED_HIGH`.
- API reference: https://api.ordr.net/api-docs/index.html (spec: https://api.ordr.net/api-docs/OrdrRestAPI.json).

In Python:

```python
from ordr_helper import Ordr

o = Ordr()
o.device("00:11:22:33:44:55")                          # list of matching devices
o.devices(max_items=50, group="<group>", riskState="High")
o.alarms(max_items=20, **{"severity-level": "high"})
o.vulnerabilities(ip="10.158.10.25")
o.alarm_summary(); o.vulnerability_summary(); o.locations(); o.profiles()
o.applications(mac="00:11:22:33:44:55"); o.flows(srcIp="10.158.10.25")
o.report("24-hour/device-count-by-type")
o.get("Rest/Devices", mac="00:11:22:33:44:55"); o.get_all("Rest/Devices", max_items=500, mfg="Philips")
```

Summarize the results for the user. Show raw JSON only when they ask for it. Device records can include patient-related fields (`hasPhi`, clinical info), so only include those when they're relevant to the question.

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).
