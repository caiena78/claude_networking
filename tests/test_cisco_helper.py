import ipaddress

import pytest

import cisco_helper as c

ROUTE_OSPF = """Routing entry for 10.158.0.0/23
  Known via "ospf 30", distance 110, metric 2, type intra area
  Routing Descriptor Blocks:
  * 10.143.100.1, from 10.143.1.22, 1w0d ago, via TenGigabitEthernet0/1/0
      Route metric is 2, traffic share count is 1
    10.143.100.5, from 10.143.1.21, 1w0d ago, via TenGigabitEthernet0/1/1
      Route metric is 2, traffic share count is 1
"""
ROUTE_STATIC = """Routing entry for 10.158.10.0/23
  Known via "static", distance 1, metric 0
  Redistributing via ospf 1, bgp 10350
  Routing Descriptor Blocks:
  * 10.75.71.84
      Route metric is 0, traffic share count is 1
"""
ROUTE_CONNECTED = """Routing entry for 10.158.0.0/23
  Known via "connected", distance 0, metric 0 (connected, via interface)
  Routing Descriptor Blocks:
  * directly connected, via Vlan103
      Route metric is 0, traffic share count is 1
"""


def test_parse_route_ospf_two_next_hops():
    d = c.parse_route(ROUTE_OSPF)
    assert d["prefix"] == "10.158.0.0/23"
    assert (d["protocol"], d["distance"], d["metric"]) == ("ospf 30", "110", "2")
    assert d["next_hops"] == [
        {"next_hop": "10.143.100.1", "interface": "TenGigabitEthernet0/1/0", "active": True},
        {"next_hop": "10.143.100.5", "interface": "TenGigabitEthernet0/1/1", "active": False},
    ]


def test_parse_route_static_without_from():
    # Regression: static next hops have no ", from ..." part.
    assert c.parse_route(ROUTE_STATIC)["next_hops"] == [{"next_hop": "10.75.71.84", "interface": "", "active": True}]


def test_parse_route_connected():
    assert c.parse_route(ROUTE_CONNECTED)["next_hops"] == [
        {"next_hop": "connected", "interface": "Vlan103", "active": True}]


@pytest.mark.parametrize("text,result", [
    (ROUTE_OSPF, "found"), ("% Network not in table", "not found"), ("% Subnet not in table", "not found"),
    ("", "not found"), ("% Invalid input detected at '^' marker.", "error"),
])
def test_classify_route(text, result):
    assert c.classify_route(text) == result


def test_route_command_platforms():
    net = ipaddress.ip_network("10.158.8.0/24")
    ip = ipaddress.ip_address("10.158.8.1")
    assert c.route_command("cisco_xe", ip) == "show ip route 10.158.8.1"
    assert c.route_command("cisco_xe", ip, "buyer") == "show ip route vrf buyer 10.158.8.1"
    assert c.route_command("cisco_ios", net) == "show ip route 10.158.8.0 255.255.255.0"
    assert c.route_command("cisco_nxos", ip, "x") == "show ip route 10.158.8.1 vrf x"


def test_default_vrf_only_on_listed_cores():
    assert c.default_vrf({"role": "Core", "site": "Lakeview Hospital"}) == "buyer"
    assert c.default_vrf({"role": "wan", "site": "Lakeview Hospital"}) is None
    assert c.default_vrf({"role": "Core", "site": "Touro"}) is None
    assert c.default_vrf({"site": "Lakeside"}) is None


@pytest.mark.parametrize("cmd", ["conf t", "show run\nreload", "show run | redirect flash:x", "reload", "clear arp"])
def test_validate_show_refuses(cmd):
    with pytest.raises(c.CiscoError):
        c.validate_show(cmd)


def test_mask_secrets():
    text = "username admin secret 9 $9$abc\n description my password is in here\n snmp-server community S3cret RO\n" \
           " security wpa psk set-key ascii 8 SuperKey"
    masked = c.mask_secrets(text)
    assert "$9$abc" not in masked and "S3cret" not in masked and "SuperKey" not in masked
    assert "description my password is in here" in masked  # descriptions are left alone


def test_parse_arp_ios_and_nxos():
    ios = "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n" \
          "Internet  10.158.0.139           12   acb4.80b9.a01f  ARPA   Vlan103"
    assert c.parse_arp(ios, "10.158.0.139") == {"mac": "acb4.80b9.a01f", "interface": "Vlan103"}
    nxos = "10.1.1.5        00:01:02  0011.2233.4455  Vlan10"
    assert c.parse_arp(nxos, "10.1.1.5") == {"mac": "0011.2233.4455", "interface": "Vlan10"}
    assert c.parse_arp(ios, "10.158.0.13") is None  # no partial-IP match


def test_parse_mac_table_skips_cpu():
    out = """          Mac Address Table
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 103    acb4.80b9.a01f    DYNAMIC     Po101
 All    acb4.80b9.a01f    STATIC      CPU
"""
    assert c.parse_mac_table(out, "acb4.80b9.a01f") == [{"vlan": "103", "port": "Po101", "type": "dynamic"}]
    nx = "* 103     acb4.80b9.a01f   dynamic  0         F      F    Eth1/13"
    assert c.parse_mac_table(nx, "acb4.80b9.a01f")[0]["port"] == "Eth1/13"


def test_parse_port_channel_members_wrapped():
    out = """Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
5      Po5(SU)         LACP        Twe1/0/11(P)    Twe2/0/11(P)
101    Po101(SU)       LACP        Twe1/0/17(P)    Twe2/0/17(D)
                                   Twe1/0/18(P)
"""
    assert c.parse_port_channel_members(out, "Po5") == ["Twe1/0/11", "Twe2/0/11"]
    assert c.parse_port_channel_members(out, "Port-channel101") == ["Twe1/0/17", "Twe1/0/18"]


CDP = """-------------------------
Device ID: LV-MDF-9300-1.mgmt.medcity.net
Entry address(es):
  IP address: 10.158.8.30
Platform: cisco C9300-48U,  Capabilities: Router Switch IGMP
Interface: TwentyFiveGigE1/0/17,  Port ID (outgoing port): TenGigabitEthernet1/1/1
-------------------------
Device ID: SEPCC989155EB38
Entry address(es):
  IP address: 10.187.134.80
Platform: Cisco IP Phone 8851,  Capabilities: Host Phone Two-port Mac Relay
Interface: GigabitEthernet1/0/13,  Port ID (outgoing port): Port 1
"""


def test_parse_cdp_detail_and_kinds():
    n = c.parse_cdp_detail(CDP)
    assert [x["device_id"] for x in n] == ["LV-MDF-9300-1.mgmt.medcity.net", "SEPCC989155EB38"]
    assert n[0]["ip"] == "10.158.8.30" and n[0]["remote_port"] == "TenGigabitEthernet1/1/1"
    assert [c.cdp_neighbor_kind(x) for x in n] == ["switch", "phone"]
    assert c.cdp_neighbor_kind({"platform": "Meraki MR44 Cloud Managed AP", "capabilities": ""}) == "meraki"
    assert c.cdp_neighbor_kind({"platform": "cisco C9120AXI-B", "capabilities": "Trans-Bridge"}) == "ap"


@pytest.mark.parametrize("text,mac", [
    ("ac:b4:80:b9:a0:1f", "acb4.80b9.a01f"), ("AC-B4-80-B9-A0-1F", "acb4.80b9.a01f"),
    ("acb4.80b9.a01f", "acb4.80b9.a01f"), ("10.158.0.139", None), ("zz:b4:80:b9:a0:1f", None),
])
def test_parse_mac(text, mac):
    assert c.parse_mac(text) == mac


def test_parse_wireless_client_9800():
    out = """Client MAC Address : 7802.8b19.630e
Client IPv4 Address : 10.158.88.66
Client Username : tulv.jamf
AP Name: LVRMIDFRAD-AP007
Wireless LAN Network Name (SSID): LCMC-VOIP
VLAN : LCMC-VOIP-V1022
Client State : Associated
Mobility Role : Local
"""
    w = c.parse_wireless_client(out)
    assert (w["ap"], w["ssid"], w["vlan"], w["ip"], w["user"], w["state"]) == (
        "LVRMIDFRAD-AP007", "LCMC-VOIP", "LCMC-VOIP-V1022", "10.158.88.66", "tulv.jamf", "Associated")


def test_parse_wireless_client_aireos_anchor():
    out = """Client MAC Address............................... 08:b6:1f:9b:56:b4
AP Name.......................................... 10.21.64.16
Client State..................................... Associated
Wireless LAN Network Name (SSID)................. LCMC-IoT
IP Address....................................... 10.21.8.159
Mobility State................................... Anchor
Mobility Foreign IP Address...................... 10.21.64.16
VLAN............................................. 21
"""
    w = c.parse_wireless_client(out)
    assert w["mobility"] == "Anchor" and w["foreign_wlc"] == "10.21.64.16" and w["ssid"] == "LCMC-IoT"
    assert c.parse_wireless_client("Client not found") == {}


WLAN_SUMMARY = """ID   Profile Name                     SSID                             Status Security
----------------------------------------------------------------------------------------------------
11   LCMC-DATA_profile                LCMC-DATA                        UP     [WPA2][FT + 802.1x][AES]
13   LCMC-VOIP_profile                LCMC-VOIP                        UP     [WPA2 + WPA3][FT + 802.1x][AES]
2416 EJGH Voice 8821                  EJGH-VOICE                       UP     [WPA2][FT + 802.1x][AES]
"""
CLIENT_SUMMARY = """MAC Address    AP Name         Type ID   State             Protocol Method     Role
-------------------------------------------------------------------------------
0017.2388.7FAA EJ-5-OUTED-AP08 WLAN 13   Run               11ac     Dot1x      Local
6887.c64f.a5ba EJ-3FL-NORTH    WLAN 2416 Run               11ac     Dot1x      Local
aaaa.bbbb.cccc EJ-3FL-NORTH    WLAN 11   Run               11ac     Dot1x      Local
"""


def test_ssid_auth_parsers():
    assert c.wlan_ids_for_ssid(WLAN_SUMMARY, "lcmc-voip") == ["13"]
    assert c.wlan_ids_for_ssid(WLAN_SUMMARY, "EJGH Voice 8821") == ["2416"]
    assert c.wlan_ids_for_ssid(WLAN_SUMMARY, "nope") == []
    assert c.clients_on_wlans(CLIENT_SUMMARY, ["13", "2416"]) == ["0017.2388.7faa", "6887.c64f.a5ba"]
    assert c.parse_eap_type("Policy Type : WPA2\nEAP Type : EAP-TLS\nVLAN : x\n") == "EAP-TLS"
    assert c.parse_eap_type("Client State : Associated\n") == "(none)"
