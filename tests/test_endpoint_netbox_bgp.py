import pytest

import bgp_community
import catalyst_helper
import endpoint_helper
import ise_helper
import meraki_helper
import netbox_helper
import ordr_helper

MAC = "aa:bb:cc:dd:ee:01"


# --- whois lookup order: Ordr -> ISE -> Catalyst -> Meraki, stopping at the first that knows the MAC ---

@pytest.fixture
def systems(monkeypatch):
    """Fake every system; set .known[name] to make one of them know the MAC, .broken to make it raise."""
    calls: list[str] = []
    state = {"known": set(), "broken": set()}

    def answer(name, value):
        calls.append(name)
        if name in state["broken"]:
            raise RuntimeError(f"{name} down")
        return value if name in state["known"] else None

    class FakeOrdr:
        def device(self, value):
            return answer("ordr", [{"MacAddress": MAC, "Group": "PC"}]) or []

    class FakeISE:
        def lookup(self, mac):
            hit = answer("ise", {"mac": mac, "profileId": "p1"})
            return {"endpoint": hit, "session": None}

        def auth_status(self, mac, hours=24, records=1):
            return []

    class FakeCatalyst:
        def client(self, mac):
            return answer("catalyst", {"name": "host1", "connectedNetworkDevice": {}})

    class FakeMeraki:
        def client_search(self, mac):
            return {"records": answer("meraki", [{"network": {"name": "PUC_Kenner"}, "ip": "192.0.2.5"}]) or []}

    monkeypatch.setattr(ordr_helper, "Ordr", FakeOrdr)
    monkeypatch.setattr(ise_helper, "ISE", FakeISE)
    monkeypatch.setattr(catalyst_helper, "Catalyst", FakeCatalyst)
    monkeypatch.setattr(meraki_helper, "Meraki", FakeMeraki)
    state["calls"] = calls
    return state


def test_whois_stops_at_ordr(systems):
    systems["known"] = {"ordr"}
    res = endpoint_helper.whois(MAC)
    assert systems["calls"] == ["ordr"]
    assert res["identity"]["ordr"][0]["Group"] == "PC"
    assert res["meraki"] is None


def test_whois_falls_through_to_ise(systems):
    systems["known"] = {"ise"}
    res = endpoint_helper.whois(MAC)
    assert systems["calls"] == ["ordr", "ise"]
    assert res["identity"]["ise"]["endpoint"]["profileId"] == "p1"


def test_whois_nobody_knows_it_asks_meraki(systems):
    res = endpoint_helper.whois(MAC)
    assert systems["calls"] == ["ordr", "ise", "catalyst", "meraki"]
    assert res["meraki"] is None


def test_whois_all_asks_everyone(systems):
    systems["known"] = {"ordr"}
    endpoint_helper.whois(MAC, ask_all=True)
    assert systems["calls"] == ["ordr", "ise", "catalyst", "meraki"]


def test_whois_failing_system_is_reported_not_fatal(systems):
    systems["broken"] = {"ordr"}
    systems["known"] = {"ise"}
    res = endpoint_helper.whois(MAC)
    assert systems["calls"] == ["ordr", "ise"]
    assert any(e.startswith("Ordr:") for e in res["errors"])


def test_whois_rejects_garbage():
    with pytest.raises(SystemExit):
        endpoint_helper.whois("not-an-ip")


# --- NetBox ---

def test_netbox_count_by():
    rows = [{"role": "Access Point", "model": "A"}, {"role": "Access Point", "model": "A"},
            {"role": "WLC", "model": None}]
    assert netbox_helper.count_by(rows, ["role", "model"]) == [
        {"role": "Access Point", "model": "A", "count": 2},
        {"role": "WLC", "model": "", "count": 1},
    ]


def test_netbox_device_type_for(capsys):
    assert netbox_helper.device_type_for("ios-xe") == "cisco_xe"
    assert netbox_helper.device_type_for("AIROS") == "cisco_wlc_ssh"
    assert netbox_helper.device_type_for("mystery", "dev1") == "cisco_ios"
    assert "mystery" in capsys.readouterr().err


def test_netbox_device_entry_strips_prefix_length():
    raw = {"name": "r1", "primary_ip4": {"address": "192.0.2.1/24"}, "platform": {"slug": "ios"},
           "site": {"name": "Lakeside"}, "status": {"value": "active"}, "role": {"slug": "router"},
           "device_type": {"slug": "isr4451"}}
    entry = netbox_helper._device_entry(raw, "r1")
    assert entry["host"] == "192.0.2.1" and entry["device_type"] == "cisco_ios" and entry["site"] == "Lakeside"


# --- Meraki ---

def test_meraki_count_by():
    rows = [{"productType": "wireless", "status": "online"}] * 3 + [{"productType": "appliance", "status": "dormant"}]
    assert meraki_helper.count_by(rows, ["productType"]) == [
        {"productType": "wireless", "count": 3}, {"productType": "appliance", "count": 1}]


# --- BGP communities ---

def test_bgp_parse_outbound_communities():
    output = """router bgp 65010
 neighbor 198.51.100.1 route-map TO-WAN out
 neighbor 198.51.100.2 route-map FROM-WAN in
route-map TO-WAN permit 10
 set community 65010:100 65010:200 additive
route-map FROM-WAN permit 10
 set community 65000:999
"""
    assert bgp_community.parse_communities(output) == ("65010", ["65010:100", "65010:200"])


def test_bgp_parse_no_outbound_map_uses_all_maps():
    output = "router bgp 65020\nroute-map A permit 10\n set community 65020:1\n"
    assert bgp_community.parse_communities(output) == ("65020", ["65020:1"])
