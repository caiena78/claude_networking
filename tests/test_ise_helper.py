import argparse
import xml.etree.ElementTree as ET

import pytest

import helper_common as hc
import ise_helper as ih


def test_normalize_and_classify_mac():
    assert ih.normalize_mac("0011.2233.44aa") == "00:11:22:33:44:AA"
    assert ih.normalize_mac("00-11-22-33-44-aa") == "00:11:22:33:44:AA"
    assert ih.normalize_mac("0011223344aa") == "00:11:22:33:44:AA"
    with pytest.raises(ih.ISEError):
        ih.normalize_mac("00:11:22")
    assert ih.is_mac("00:11:22:33:44:55") and ih.is_mac("0011.2233.4455")
    assert not ih.is_mac("10.1.1.1") and not ih.is_mac("jdoe")
    assert ih.is_ip("192.0.2.10") and not ih.is_ip("0011.2233.4455")


def test_xml_to_dict_repeats_become_lists():
    xml = ("<activeList noOfActiveSession='2'>"
           "<activeSession><user_name>a</user_name><server>PSN1</server></activeSession>"
           "<activeSession><user_name>b</user_name><framed_ip_address/></activeSession>"
           "</activeList>")
    d = ih.xml_to_dict(ET.fromstring(xml))
    assert d["noOfActiveSession"] == "2"
    assert [s["user_name"] for s in d["activeSession"]] == ["a", "b"]
    assert d["activeSession"][1]["framed_ip_address"] is None
    single = ih.xml_to_dict(ET.fromstring("<x><activeSession><user_name>a</user_name></activeSession></x>"))
    assert single["activeSession"] == {"user_name": "a"}


def test_session_view_keeps_key_fields():
    s = {"user_name": "u", "calling_station_id": "AA", "acs_session_id": "zzz", "posture_status": ""}
    assert ih._session_view(s, False) == {"user_name": "u", "calling_station_id": "AA"}
    assert ih._session_view(s, True) is s
    assert ih._session_view(None, False) is None


SESSIONS = [
    {"user_name": "u1", "calling_station_id": "A", "nas_ip_address": "192.0.2.1", "server": "PSN-01", "framed_ip_address": "198.51.100.1"},
    {"user_name": None, "calling_station_id": "B", "nas_ip_address": "192.0.2.1", "server": "PSN-02"},
    {"user_name": "u3", "calling_station_id": "C", "nas_ip_address": "192.0.2.2", "server": "PSN-01", "framed_ip_address": "198.51.100.3"},
    {"user_name": "u4", "calling_station_id": "D", "server": "PSN-01"},
]


def test_count_by_orders_and_limits():
    assert ih.count_by(SESSIONS, "server") == [{"value": "PSN-01", "count": 3}, {"value": "PSN-02", "count": 1}]
    rows = ih.count_by(SESSIONS, "nas_ip_address")
    assert rows[0] == {"value": "192.0.2.1", "count": 2}
    assert {"value": "(none)", "count": 1} in rows
    assert len(ih.count_by(SESSIONS, "nas_ip_address", limit=1)) == 1
    assert ih.count_by(SESSIONS, lambda r: r["calling_station_id"].lower(), 2) == [
        {"value": "a", "count": 1}, {"value": "b", "count": 1}]


def test_summarize_sessions():
    s = ih.summarize_sessions(SESSIONS)
    assert (s["active_sessions"], s["with_user"], s["with_ip"]) == (4, 3, 2)
    assert s["by_server"][0] == {"value": "PSN-01", "count": 3}
    assert ih.summarize_sessions([])["by_nas_ip"] == []


NADS = [
    {"name": "tls-sw1", "profileName": "Cisco", "modelName": "",
     "NetworkDeviceGroupList": ["Location#All Locations#TLS", "Device Type#All Device Types#Switches", "DNAC#DNAC Devices"]},
    {"name": "tls-rtr", "profileName": "Cisco", "modelName": "ISR4451",
     "NetworkDeviceGroupList": ["Location#All Locations#TLS", "Device Type#All Device Types#Routers"]},
    {"name": "umc-wlc", "profileName": "Cisco",
     "NetworkDeviceGroupList": ["Location#All Locations#UMC#Tower", "Device Type#All Device Types#WLC"]},
    {"name": "bare"},
]


def test_nad_groups():
    assert ih.nad_groups(NADS[0]) == {"Location": "TLS", "Device Type": "Switches", "DNAC": "DNAC Devices"}
    assert ih.nad_groups(NADS[2])["Location"] == "UMC#Tower"
    assert ih.nad_groups(NADS[3]) == {}


def test_summarize_nads():
    s = ih.summarize_nads(NADS)
    assert s["nads"] == 4
    assert s["by_location"][0] == {"value": "TLS", "count": 2}
    assert {"value": "(none)", "count": 1} in s["by_location"]
    assert {"value": "Routers", "count": 1} in s["by_device_type"]
    assert s["by_dnac"][0] == {"value": "(none)", "count": 3}
    assert s["by_profile"][0] == {"value": "Cisco", "count": 3}
    assert {"value": "ISR4451", "count": 1} in s["by_model"]


def test_emit_and_summary_output(capsys, tmp_path):
    args = argparse.Namespace(json=False)
    out = hc.Out()
    ih._emit(out, args, SESSIONS, ["user_name", "server"])
    ih._emit(out, args, {"a": 1})
    ih._emit_summary(out, args, ih.summarize_sessions(SESSIONS))
    text = out.text()
    assert "user_name" in text and "PSN-01" in text and '"a": 1' in text
    assert "active_sessions=4" in text and "===== by_server" in text
    path = tmp_path / "o.txt"
    out.save(str(path))
    out.save(str(path), append=True)
    assert path.read_text(encoding="utf-8").count("===== by_server") == 2
    jout = hc.Out()
    ih._emit_summary(jout, argparse.Namespace(json=True), {"nads": 0, "by_model": []})
    assert '"nads": 0' in jout.text()


def test_cert_days():
    from ise_helper import ISE
    assert ISE._cert_days({"expirationDate": "Fri Nov 02 15:22:22 UTC 2001"}) < 0
    assert ISE._cert_days({"expirationDate": "Fri Nov 02 15:22:22 UTC 2999"}) > 10000
    assert ISE._cert_days({"expirationDate": "garbage"}) is None
