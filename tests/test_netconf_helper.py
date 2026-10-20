import pytest
from lxml import etree

import netconf_helper as n

DATA = etree.fromstring(
    """<data><arp-data xmlns="x"><arp-vrf><vrf>Default</vrf><arp-oper><address>10.0.0.1</address>
    <hardware>aa:bb:cc:dd:ee:01</hardware><interface>Vlan1</interface></arp-oper></arp-vrf>
    <arp-vrf><vrf>buyer</vrf><arp-oper><address>10.0.0.2</address><hardware>aa:bb:cc:dd:ee:02</hardware>
    <interface>Vlan2</interface></arp-oper></arp-vrf></arp-data></data>""")


def test_mask_xml_hides_psk_and_passwords():
    xml = "<a><psk>SECRET</psk><enable-password>pw</enable-password><ssid>LCMC</ssid></a>"
    out = n.mask_xml(xml)
    assert "SECRET" not in out and "pw<" not in out
    assert "<ssid>LCMC</ssid>" in out


def test_arp_filters_by_ip_and_core_vrf():
    assert "10.0.0.2" in n._arp(DATA, None, {"role": "Access Switch"}) and "10.0.0.1" in n._arp(DATA, None, {})
    core = {"role": "Core", "site": "Lakeview Hospital"}
    out = n._arp(DATA, None, core)  # cores show only their routed VRF (buyer)
    assert "10.0.0.2" in out and "10.0.0.1" not in out
    assert "10.0.0.1" not in n._arp(DATA, "10.0.0.2", {})


def test_uptime_and_unsupported():
    s = {"now": "2026-10-20T12:00:00+00:00", "boot": "2026-10-18T10:30:00+00:00"}
    assert n._uptime(s).startswith("2 days, 1 hours, 30 minutes")
    with pytest.raises(n.NetconfUnsupported):
        n.query("192.0.2.1", {}, "bgp", None, {})
