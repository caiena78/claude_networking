import argparse
import ipaddress

import pytest

import ftd_capture_helper as f


@pytest.mark.parametrize("cmd,ok", [
    ("show capture", True),
    ("capture CLAUDE_X_IN buffer 1 interface Inside1 match ip any any", True),
    ("no capture CLAUDE_X_IN", True),
    ("no capture LSU_2_EPIC%intf=Inside1% stop", True),      # start someone else's capture (reuse)
    ("capture LSU_2_EPIC stop", True),                        # stop it again
    ("no capture LSU_2_EPIC", False),                         # never remove someone else's
    ("capture OTHER buffer 1 interface X match ip any any", False),
    ("clear capture CLAUDE_X_IN", False),
    ("configure terminal", False),
    ("packet-tracer input Inside1 tcp 1.1.1.1 1 2.2.2.2 443", False),
    ("expert", False),
])
def test_allowlist(cmd, ok):
    assert bool(f.ALLOWED.match(cmd)) is ok


SHOW_CAPTURE = """capture LSU_2_EPIC%intf=Inside1% type raw-data trace interface Inside1 [Capturing - 1628926 bytes]
  match ip 155.58.39.0 255.255.255.0 10.194.0.0 255.255.0.0
capture CLAUDE_TCP443_10-194-2-10_DROP type asp-drop all buffer 1048576 [Capturing - 0 bytes]
  match tcp host 10.194.23.182 host 10.194.2.10 eq https
capture FULL type raw-data interface EPIC_DMZ [Buffer Full - 524288 bytes]
  match ip any any
"""


def flow(src="155.58.39.10", dst="10.194.2.10", proto="tcp", port="443"):
    return argparse.Namespace(src=ipaddress.ip_network(src), dst=ipaddress.ip_network(dst), proto=proto, port=port)


def test_parse_captures_and_reuse():
    caps = f.parse_captures(SHOW_CAPTURE)
    assert [c["name"] for c in caps] == ["LSU_2_EPIC%intf=Inside1%", "CLAUDE_TCP443_10-194-2-10_DROP", "FULL"]
    assert caps[0]["trace"] and caps[0]["interfaces"] == ["Inside1"] and caps[2]["state"] == "Buffer Full"
    assert f.find_reusable(caps, "IN", "Inside1", flow())["name"] == "LSU_2_EPIC%intf=Inside1%"
    assert f.find_reusable(caps, "OUT", "EPIC_DMZ", flow()) is None          # the only one is Buffer Full
    assert f.find_reusable(caps, "IN", "Inside1", flow(src="10.9.9.9")) is None


def test_match_port_names_are_not_trusted():
    # "eq https" isn't a number, so the helper can't prove the port matches: don't reuse.
    assert not f.covers({"matches": ["match tcp host 10.194.23.182 host 10.194.2.10 eq https"]},
                        flow(src="10.194.23.182"))
    assert f.covers({"matches": ["match tcp host 10.194.23.182 host 10.194.2.10 eq 443"]}, flow(src="10.194.23.182"))
    assert f.covers({"matches": ["match tcp host 10.194.2.10 eq 443 host 10.194.23.182"]}, flow(src="10.194.23.182"))


def test_auto_desc_and_match_clause():
    a = flow(dst="10.194.2.10", port="443")
    assert f.auto_desc(a) == "TCP443_10-194-2-10"
    assert f.match_clause(a) == "match tcp 155.58.39.10 255.255.255.255 host 10.194.2.10 eq 443".replace(
        "155.58.39.10 255.255.255.255", "host 155.58.39.10")
    assert f.match_clause(flow(port="8000-8010")).endswith("range 8000 8010")


def test_parse_trace_and_directions():
    trace = """Phase: 4
Type: ACCESS-LIST
Result: ALLOW
Additional Information:
 access-list CSM_FW_ACL_ advanced trust ip ifc Inside1 any ifc EPIC_DMZ any rule-id 268437505
 access-list CSM_FW_ACL_ remark rule-id 268437505: PREFILTER POLICY: Vendor-Prefilter-Policy
 access-list CSM_FW_ACL_ remark rule-id 268437505: RULE: L_2_E_PRESENTATION_TIER_TRAFFIC
input-interface: Inside1
output-interface: EPIC_DMZ
Action: allow
"""
    t = f.parse_trace(trace)
    assert t["action"] == "allow" and t["in"] == "Inside1" and t["out"] == "EPIC_DMZ"
    assert t["rules"] == ["PREFILTER POLICY: Vendor-Prefilter-Policy", "RULE: L_2_E_PRESENTATION_TIER_TRAFFIC"]
    pkts = [(1, "155.58.39.10.51000 > 10.194.2.10.443: S 1:1(0)"), (2, "10.194.2.10.443 > 155.58.39.10.51000: S 1:1(0) ack")]
    assert f.directions(pkts, ipaddress.ip_network("155.58.39.10/32"), ipaddress.ip_network("10.194.2.10/32")) == ([1], [2])
