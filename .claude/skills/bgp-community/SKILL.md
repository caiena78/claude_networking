---
name: bgp-community
description: BGP communities the WAN routers set on the routes they advertise, and the site/router/AS map in bgp_community.txt, via bgp_community.py. Use for "what community does site X use", "which router tags routes with 65000:123", "what AS is router Y", "list the WAN routers per site with their BGP AS", or when bgp_community.txt is missing or stale.
---

# BGP communities (bgp_community.py)

`bgp_community.py` asks every NetBox device tagged `wan_router` for its BGP outbound route-maps and their `set community` lines. It uses one read-only command per router (`show running-config | include ^router bgp|^route-map|set community|neighbor .* route-map .* out`), with the SSH credentials from Vault, and writes a table to `bgp_community.txt`:

```
Site  Router  Router IP  BGP AS  BGP Community
```

```
python bgp_community.py                                  # every wan_router -> bgp_community.txt
python bgp_community.py --site lakeside                  # one NetBox site (slug)
python bgp_community.py --device tls-wan --output tls.txt   # routers whose name contains the text
python bgp_community.py --tag wan_router --workers 10 --timeout 30
```

- **Read the existing `bgp_community.txt` first.** Only re-run the script when the file is missing (it is git-ignored, so a new clone doesn't have it), when the user asks for fresh data, or when a router isn't in it. A full run logs in to every WAN router.
- The file is also the quick map of site to router name to AS. The router name prefixes (`tls-*` = Lakeside, `lvr-*` = Lakeview, `ej-*` = East Jefferson, and so on) come from it.
- A row with `ERROR: ...` in the community column means that router didn't answer or rejected the command. The rest of the table is still valid.
- Only the communities set by **outbound** route-maps (`neighbor ... route-map X out`) are listed. `match community` lines are ignored. If a router has no outbound route-map on any neighbor, the script falls back to every route-map's `set community`.
- For live routing (who has a route to X), use `cisco_helper.py route` (the `cisco-devices` skill). For the full BGP config on one router, use `python cisco_helper.py section "router bgp" -d <router>`.

Follow the ground rules and the Rules section in CLAUDE.md (helpers only, read-only, never print credentials).
