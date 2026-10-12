---
name: ftd-packet-captures
description: Packet captures on FTD firewalls through ftd_capture_helper.py - the ONLY write action in this repo. Use when the user asks whether traffic is actually allowed through a firewall (live verdict), wants a packet capture, or asks about leftover CLAUDE_* captures. Covers the confirm-first rules, interface choice, verdicts and cleanup.
---

# FTD packet captures

`ftd_capture_helper.py` runs packet captures over SSH on the FTD firewalls listed in `.env`. It's the **only write action** allowed in this repo, and it may only create, start, stop and remove packet captures. Everything else stays read-only.

**Which firewalls:** only the units in `FTD_CAPTURE_HOSTS` in `.env`. The helper refuses to connect to anything else.
- **Format:** units of one HA pair are separated by commas, and firewalls are separated by semicolons. A unit can carry an optional label, as `ip=name`. For example: `FTD_CAPTURE_HOSTS=<unit1-ip>=NAME-01,<unit2-ip>=NAME-02;<other-pair-ip1>,<other-pair-ip2>`.
- **Choosing a firewall:** with more than one configured, pass `--fw <ip or label>`.
- **Standalone firewall:** a group with one IP is a standalone unit. It must report failover Off.
- **Adding a firewall:** add its IPs to `FTD_CAPTURE_HOSTS`. Never hard-code unit IPs in tracked files, because the repo is public.
- **Currently configured:** the `UMC-FTD-2130-VENDOR-HA` pair (Firepower 2130, FTD 7.4.4). On 2026-10-12 the Secondary (`-02`) was Active. Never assume this; the helper checks every time.

**Credentials:** the environment variables `CISCO_SRV_ACCOUNT` and `CISCO_SRV_PWD` (not Vault, not `.env`). They're per user, because every team member has their own FTD account, and captures run as that person. Never hard-code, print or log them, and never ask the user to paste a password into the chat.

**Connecting:** netmiko with `device_type="cisco_ftd"` and generous timeouts, because some units are slow to show the prompt. The netmiko session log is off, since it would record the login. The helper stays at the `>` CLISH prompt and never enters `expert` mode or `configure`.

## Rules

1. **Active unit only.** Before every capture, the helper runs `show failover` on both units of the pair. It continues only if exactly one unit is `Active` and the other is `Standby Ready`, and it captures on the active unit only. If the state is unclear (both or neither active, a unit unreachable, or failover not `On`), **don't capture**. Show the user the output and stop.
2. **Confirm first.** Before starting a capture, show the plan (`start` or `capture` **without** `--yes`) and wait for a yes for that specific capture: the active unit and IP, the `nameif`s, the match filter, the buffer and the exact commands. Approval for one capture doesn't carry over to the next. **Exception:** when the user asks whether specific traffic is allowed (below), the request plus their interface choices count as approval.
3. **Always filter and limit.** Every capture has a `match` with a source and a destination, plus a `buffer` (default 1 MB, at most 32 MB), and never uses `circular-buffer`. Trace captures set `trace-count` (default 20, at most 100). `asp-drop` captures also need a `match`.
4. **Reuse before creating.** If an existing capture (anyone's) already has the required settings, it's used instead of a new one. A stopped one is started with `no capture <name> stop` and stopped again when finished. A running one is left running. Tell the user which existing capture is being used.
5. **Naming.** Every capture Claude creates is named `CLAUDE_<DESC>_<IN|OUT|DROP>`. `DESC` comes from the protocol, port and destination, or from `--name`, and is at most 20 characters. The helper checks for name clashes.
6. **Clean up.** When done, the output is saved under `captures/` (git-ignored) and the `CLAUDE_*` captures are removed. Only ever remove `CLAUDE_*` captures. Never remove, clear or reconfigure anyone else's; the only thing allowed on them is starting and stopping them (rule 4). After an interrupted session, check for leftover `CLAUDE_*` captures (`cleanup`) and offer to remove them.
7. **Allowed commands only:** `show ...`, `capture CLAUDE_* ...`, `no capture CLAUDE_*`, and `capture <name> stop` / `no capture <name> stop`. Never config changes, `clear`, failover commands, `reload` or `copy`. The helper enforces this with an allowlist.
8. **No packet-tracer.** It doesn't evaluate prefilter rules, so its verdict is wrong for `Vendor-Prefilter-Policy` traffic. Verdicts come only from live trace captures.

```
python ftd_capture_helper.py status                               # failover state of the units
python ftd_capture_helper.py interfaces [--src <ip> --dst <ip>] [--refresh]   # cached nameifs; marks route-suggested ones
python ftd_capture_helper.py list                                 # all captures on the active unit
python ftd_capture_helper.py start --src <ip|cidr> --dst <ip|cidr> [--proto tcp|udp|icmp|ip] [--port 53|8000-8010] \
       --ingress <nameif> --egress <nameif> [--name <DESC>] [--buffer 1048576] [--trace-count 20]   # PLAN only
python ftd_capture_helper.py start ... --yes                      # create / reuse captures and leave them RUNNING
python ftd_capture_helper.py check [--name <DESC>]                # allowed or denied, and by which rule (read-only)
python ftd_capture_helper.py stop  [--name <DESC>] [--stop-only]  # remove new captures (or just stop them), re-stop reused ones
python ftd_capture_helper.py sessions                             # open sessions
python ftd_capture_helper.py capture ... --ingress X --egress Y [--duration 60] [--yes] [--keep]   # one-shot
python ftd_capture_helper.py cleanup [--yes]                      # leftover CLAUDE_* captures
```

**Audit log:** every command that changes a device (`capture`, `no capture`, and starting or stopping a capture) is appended to `captures/audit.log` before it's sent. The log is git-ignored and local to each person, and each line records the UTC time, the local user, the FTD account, the unit and the exact command. `show` commands aren't logged. If someone asks who ran a capture, look there.

**Sessions and output:**
- `start` records the session in `captures/sessions.json`: the firewall, active unit, capture names, what was reused or started, and each capture's packet count at the start.
- `check` analyses only the packets added since `start`. Capture timestamps aren't used, because they don't match `show time`.
- If a failover happened since `start`, `check` and `stop` stop and say so.
- Interface lists are cached per firewall in `ftd_interfaces.json` (git-ignored) for 7 days.

## Is this traffic allowed?

When the user asks whether specific traffic is allowed (for example "is 10.1.1.1 to 10.9.9.9 on udp 53 allowed?"):

1. **Choose interfaces.** Run `ftd_capture_helper.py interfaces --src <src> --dst <dst>` and show the table. Ask for the **source (ingress)** and **destination (egress)** interfaces with `AskUserQuestion`: two questions, with the route-suggested interface first and marked "(Recommended)". Never pick them for the user.
2. **Start the capture.** Run `start ... --ingress <src-if> --egress <dst-if>`, then the same with `--yes` (the request is the approval). Show the plan, the captures created and any `USING EXISTING CAPTURE` lines. If no protocol was given, use `tcp`.
3. **Check the policy.** Also run `cdo_helper.py prefilter-check` for the same source, destination and port. It shows which rule *should* match.
4. **Ask exactly: "do you want me to check for traffic?"**, then wait. The user may need time to generate the traffic.
5. **If yes,** run `check --name <DESC>`. Report **ALLOWED / DENIED / NOT SEEN / UNCLEAR**, the matched `RULE:` line compared with `prefilter-check`, and the drop reason if it was denied. If the result is NOT SEEN, offer to check again later.
6. **Ask whether to disable the capture** (`AskUserQuestion`): "Yes, remove it (Recommended)" runs `stop`, "Stop it but keep it" runs `stop --stop-only`, and "No, leave it running" does nothing, but remind the user that `sessions` lists it. Ask this after the check, and also if the user says no to checking.

For a plain capture request (not "is it allowed?"), choose interfaces the same way, show the `capture ...` plan **without** `--yes`, and run it with `--yes` only after the user approves.

**Verdicts:**

| What the captures show | Verdict |
|---|---|
| `_IN` trace `Action: allow`, packets in `_OUT`, and a reply | **ALLOWED**, and the destination replied |
| `_IN` trace `Action: allow`, packets in `_OUT`, no reply | **ALLOWED by the firewall, no reply.** The problem is past it (server, host firewall or return routing) |
| `_IN` trace `Action: drop`, or the flow is in `_DROP` | **DENIED.** Report the drop reason (`acl-drop`, `no-route`, `rpf-violated`, ...) |
| Nothing in `_IN` | **NOT SEEN.** The traffic never reached the firewall, or wasn't generated during the capture |
| Seen on `_IN`, not `_OUT`, no drops | **UNCLEAR.** Review the saved output |

`Vendor-Prefilter-Policy` rules use FASTPATH, so allowed traffic should show the prefilter rule and fastpath. A capture only sees traffic sent **while it runs**, so ask the user to generate it.

**FTD CLI quirks the helper handles:**
- `show capture` can list names as `NAME%intf=<nameif>%`. The suffix is part of the real name.
- There's no `show clock`; use `show time`.
- When the CLI rejects a command, it leaves the text on the line, so the helper clears the line with Ctrl+U and stops.
- Long `capture` commands wrap on the terminal, so they're sent without echo verification and then confirmed with `show capture`.
- A reused capture whose packet count doesn't move gives no data. Prefer a new `CLAUDE_` capture in that case.

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).
