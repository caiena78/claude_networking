# Route questions and VRFs on the cores

## Answering route questions

Requests like "show me routes for 10.158.8.1", "where is 10.x.x.x routed" or "which router has a route to 10.158.8.0/24" mean:

```
python cisco_helper.py route <ip-or-prefix> --json
```

With no device options, this runs on every NetBox device tagged `wan_router`. Add `--site <name>`, `-d <device>` or `--vrf <name>` only when the user asks for them. On the Lakeview Hospital, Lakeside and Tulane cores, route lookups use VRF `buyer` automatically (see below), and each result's `vrf` says which VRF was used. In the JSON, each result's `route_result` is `found`, `not found` or `error`, and `output` holds the router's output. Found routes also have `route_detail`: `prefix`, `protocol`, `distance`, `metric` and `next_hops` (`next_hop`, `interface`, `active`). For recursive routes such as BGP, the helper looks up the route to the next hop on the same router to fill in the real outgoing interface, and records how it got there in `resolved_via` (e.g. `198.18.255.32/32 ospf 500 -> 198.18.0.30`). The text output's Summary shows all of this on one line per router.

To name the devices behind the destination and the next hops, look the IPs up in NetBox: `python netbox_helper.py ip <ip>` (device and interface) and `python netbox_helper.py prefix <ip>` (site, VLAN, VRF).

Then summarize for the user:
- which routers have the route, and for each one the matched prefix, the next hop, the outgoing interface, the protocol (BGP, OSPF, static, connected and so on) and the AD/metric if shown;
- whether any router only matched the default route (0.0.0.0/0), and say so explicitly;
- which routers did not have it, and any errors or skipped devices.

Show the full raw output only if the user asks for it (it is in `output`, or in the text sections above the Summary).

## VRFs on the cores

At **Lakeview Hospital, Lakeside and Tulane**, user and server subnets live in VRF **`buyer`**, and **only on the core switches** (NetBox role `Core`, e.g. `lv-mdf-core-9500(1)`, `ls-mdf-core-9500(1)`, `tul-mdf-core-9606(1)`). The WAN routers at those sites use the global table. `cisco_helper.py` handles this for you (`CORE_VRFS` in `cisco_route.py`): route and ARP lookups on those cores use VRF `buyer` only and skip every other VRF, unless you pass `--vrf`. In the global table those cores show other routes, such as a static route to a firewall for the server VLAN, and those routes are wrong for this purpose. To add a site, add it to `CORE_VRFS` in `cisco_route.py`.

On those same cores, **VRF `div` and the global (default) table are for isolated networks**, which aren't routed to the WAN. `locate` looks there only after the normal trace finds nothing (`CORE_ISOLATED_VRFS`), and labels the result `isolated`. To look in one of them yourself, pass `--vrf div`, or `--vrf global` for the global table: `python cisco_helper.py route 10.67.240.11 -d "lv-mdf-core-9500(1)" --vrf global`.
