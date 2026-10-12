import helper_common as hc
import meraki_helper
import netbox_helper
import audit_helper
import report_helper


def test_table_and_dig():
    rows = [{"name": "a", "ip": {"address": "10.0.0.1"}, "tags": ["x", "y"], "pct": 0.12345}]
    out = hc.table(rows, ["name", "addr=ip.address", "tags", "pct"])
    assert out.splitlines()[0].split() == ["name", "addr", "tags", "pct"]
    assert "10.0.0.1" in out and "x y" in out and "0.12" in out
    assert hc.table([], ["x"]) == "(none)"
    assert hc.dig({"a": {"b": 1}}, "a.c") is None


def test_mac_helpers():
    assert hc.mac_colon("ACB4.80B9.A01F") == "ac:b4:80:b9:a0:1f"
    assert hc.mac_cisco("ac-b4-80-b9-a0-1f") == "acb4.80b9.a01f"
    assert not hc.is_mac("10.158.0.139")


def test_meraki_mask_scrubs_secrets_everywhere():
    data = {"name": "LCMC-IOTS", "psk": "hunter2", "authMode": "psk",
            "radiusServers": [{"host": "1.1.1.1", "secret": "s3"}], "snmp": {"communityString": "public"},
            "enabled": True, "encryptionMode": "wpa"}
    m = meraki_helper.mask(data)
    assert m["psk"] == m["radiusServers"][0]["secret"] == m["snmp"]["communityString"] == "*****"
    assert m["authMode"] == "psk" and m["enabled"] is True and m["encryptionMode"] == "wpa"


def test_netbox_prefix_row_reads_without_lazy_load():
    # A plain dict stands in for the pynetbox record: _prefix_row must only read what the API sent.
    raw = {"prefix": "10.158.0.0/23", "status": {"value": "active"}, "scope_type": "dcim.site",
           "scope": {"name": "Lakeview Hospital"}, "vlan": {"vid": 103, "name": "Data"}, "vrf": None,
           "role": None, "tenant": None, "description": "1st floor"}
    row = netbox_helper._prefix_row(raw)
    assert row == {"prefix": "10.158.0.0/23", "status": "active", "site": "Lakeview Hospital", "vlan": "103 Data",
                   "vrf": "", "role": "", "tenant": "", "description": "1st floor"}


def test_parse_connected():
    out = """      10.0.0.0/8 is variably subnetted, 120 subnets, 8 masks
C        10.158.0.0/23 is directly connected, Vlan103
L        10.158.0.1/32 is directly connected, Vlan103
C        10.67.240.0/27 is directly connected, Vlan700
"""
    assert audit_helper.parse_connected(out) == [("10.158.0.0/23", "Vlan103"), ("10.67.240.0/27", "Vlan700")]


def test_report_issue_grouping():
    assert report_helper._issue_kind("citrix Health Degradation") == "Application health degradation (any app)"
    assert report_helper._issue_kind("No activity on 6 GHz radio 2 on EJ-MOBI-5FL-AP-19.") == \
        report_helper._issue_kind("No activity on 6 GHz radio 2 on TRO-TMOB-TASC-FL1-AP04.")
    assert report_helper._ms(1791820348561).startswith("2026-")
