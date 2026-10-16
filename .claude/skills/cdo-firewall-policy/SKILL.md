---
name: cdo-firewall-policy
description: Cisco CDO / cloud-delivered FMC through cdo_helper.py: FTD devices, HA pairs, interfaces, static routes, objects, assigned policies; whether a prefilter or access control rule allows src -> dst on a port (Vendor-Prefilter-Policy rule lookups, pasted CSV/spreadsheet requests); NAT rules for an IP.
---

# Cisco CDO (cloud-delivered FMC)

Use CDO for **firewall policy and config** on the FTDs it manages: devices, HA pairs, interfaces, static routes, network objects, and prefilter policies and rules. Use `ftd_capture_helper.py` to see what the firewall *actually does* with live traffic.

**Always use `cdo_helper.py` for CDO.** Don't write ad-hoc `requests` calls. It sends only `GET` requests, pages with `limit`/`offset`, and retries on `429`, because FMC allows about 120 requests a minute.

**Settings (an exception to "credentials come from Vault"):** each team member has their **own** CDO API key and FTD account, so these are per-user environment variables by design. Don't move them to the shared Vault path.
- `CDO_URL`: the tenant URL. It's in `.env`, because it isn't a secret.
- `CDO_UUID` (the FMC domain UUID) and `CDO_API` (the bearer token): **environment variables**. Never put them in `.env` or any file, and never print them.
- The helper exits if any of the three is missing.

```
python cdo_helper.py devices                       # managed FTDs: model, version, health, device group
python cdo_helper.py ha                            # FTD HA pairs
python cdo_helper.py interfaces <device>           # all interfaces: nameif, IP, security zone
python cdo_helper.py routes <device>               # IPv4 static routes
python cdo_helper.py objects <name-or-value>       # network objects
python cdo_helper.py prefilter-rules [--policy NAME]   # rules in order (default Vendor-Prefilter-Policy)
python cdo_helper.py prefilter-check --src <ip|cidr|a-b> --dst <ip|cidr|a-b> --ports 443,tcp/22,udp/1194,8000-8010,icmp
python cdo_helper.py prefilter-check --input <file> [--summary]   # pasted CSV / spreadsheet rows
python cdo_helper.py get object/networkgroups -p expanded=true    # any GET path under the domain
python cdo_helper.py policies <device>             # policies assigned to it (access, NAT, prefilter, platform, VPN, health)
python cdo_helper.py acp-check --src <ip> --dst <ip> --ports 443,udp/53 (--device <name> | --policy <name>)
python cdo_helper.py nat-check <ip> (--device <name> | --policy <name>) [--include-any]
```

- **`policies <device>`:** policies can be assigned to the device itself, its HA pair or its device group (e.g. `EPIC`), and the helper checks all three. `PrefilterPolicy` comes from the access policy's prefilter setting.
- **`acp-check`:** evaluates the **access control policy**, first match by `ruleIndex`.
  - `ALLOW` and `TRUST` allow. The other actions deny.
  - `MONITOR` rules only log, so evaluation continues past them.
  - Rules with application, URL, user, VLAN-tag, SGT, dynamic-object or source-port conditions can't be decided from IPs and ports. They're listed as "passed over" and may match first in practice.
  - With no match, the policy's **default action** applies (for `UMC-FTD-VENDOR-POLICY` that's BLOCK).
  - **Remember the order:** the prefilter policy runs **first**. Traffic it FASTPATHs or BLOCKs never reaches the access policy, so a `DEFAULT BLOCK` from `acp-check` doesn't mean the traffic is blocked if a prefilter rule fastpaths it. For the combined answer, use `endpoint_helper.py path` (the `network-reports` skill).
- **`nat-check`:** lists the manual and auto NAT rules whose original or translated objects contain the IP. Catch-all objects (`any-ipv4`, `0.0.0.0/0`) are ignored unless you pass `--include-any`, because they match everything.

## Rule lookup ("does a rule already allow this?")

The user gives a source, a destination and one or more destination ports. `prefilter-check` searches `Vendor-Prefilter-Policy` (use `--policy` for another) and reports whether an existing **enabled** rule already allows the traffic. It is read-only and never creates or changes rules. Report only what would need to change. It takes about 12 seconds.

- **Ports:** `443` (TCP), `tcp/443`, `udp/53`, `any/443` (any protocol), `8000-8010` (a TCP range) and `icmp`. Without `--ports`, it lists every rule whose source and destination match, including disabled and BLOCK rules (both flagged), with each rule's ports.
- **Matching:**
  - Only enabled rules count.
  - `FASTPATH` and `ANALYZE` allow traffic. A matching `BLOCK` denies it.
  - Rules are evaluated top-down by `metadata.ruleIndex`, and the first match wins.
  - A rule matches only if its object **fully contains** the requested network. Rules that cover only part of it are listed under "PARTIAL IP OVERLAP".
  - Empty networks or ports on a rule mean any.
  - FQDN objects can't be checked against an IP and are flagged.
  - Interfaces aren't part of the match, but they're reported.
- **Pasted CSV / spreadsheet rows** have three columns (source, destination, ports). Cells are often quoted, span several lines and mix labels with values. Save the text to a scratchpad file exactly as pasted and use `--input`. The parser:
  - splits on tabs, then commas, and falls back to cells taken three at a time;
  - folds an optional 4th protocol column into the ports;
  - pulls every IP, CIDR and range out of the text (`10.194.23.197-200` expands to a full range);
  - reads ports line by line, applying a `TCP`/`UDP` on a line to every port on it, and defaults to TCP;
  - checks every source × destination pair.
- **What to report:**
  - Which rule and object covers each destination and port.
  - Which ports are **MISSING**, with the port objects on the closest matching rule. Point out an object that has the right numbers but the wrong protocol.
  - What to change: add a port object to an existing rule (preferred), change a shared object (warn that this affects other rules), or create a new rule.
  - Present it as a short summary, then a table per matching rule.

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).

## RA VPN session history

`python cdo_helper.py vpn-sessions [--days 14] [--device ACB] [--user NAME] [--status ACTIVE|TERMINATED] [--summary]` lists AnyConnect logins (user, login time, last active, public IP, assigned IP, device) from the Security Cloud Control API `GET /v1/vpnsessions`, using the same `CDO_API` token. The base URL is `CDO_SCC_URL` (default the US region). The API has no time filter and its tenant-wide paging is unstable, so the helper queries each device on its own and filters by `loginTime` itself. `lastActiveTime` is the nearest thing to a logout time. For live sessions on the firewall itself, use `ftd_capture_helper.py vpn`.
