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


def test_catalyst_issue_type_groups_names():
    import catalyst_helper as cat
    assert cat.issue_type("No activity on 6 GHz radio 2 on EJ-EJN6-AP2.") == "No activity on N GHz radio N on <AP>."
    assert cat.issue_type("ldap Health Degradation") == "<app> Health Degradation"
    assert cat.issue_type("High input/output discard on interface 'GigabitEthernet1/0/6' (Interface description: --)") \
        == "High input/output discard on interface 'X'"
    assert cat.issue_type("Low receive power on transceiver interface TwentyFiveGigE1/0/2") \
        == "Low receive power on transceiver interface X"
    rows = cat.issue_summary([{"priority": "P2", "name": "a Health Degradation"},
                              {"priority": "P2", "name": "b Health Degradation"},
                              {"priority": "P1", "name": 'Device "x" down'}])
    assert rows == [{"priority": "P1", "count": 1, "issue": 'Device "X" down'},
                    {"priority": "P2", "count": 2, "issue": "<app> Health Degradation"}]


def test_meraki_license_class():
    import meraki_helper as mh
    assert mh.license_class("LIC-MX-L-E") == "MX-L"
    assert mh.license_class("lic-mx-xl-a") == "MX-XL"
    assert mh.license_class("MX Large") == "MX-L"
    assert mh.license_class("mx-m") == "MX-M"
    assert mh.APPLIANCE_LICENSE_CLASS["MX105"] == "MX-L"
