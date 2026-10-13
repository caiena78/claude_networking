"""Offline tests for ordr_helper.py (no network, Vault or Ordr)."""
import argparse

import pytest

import helper_common as hc
import ordr_helper as oh


def _client():
    return oh.Ordr(url="ordr.example.com", user="u", password="p", tenant_guid="tg")


@pytest.mark.parametrize("mac", ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff"])
def test_normalize_mac(mac):
    assert oh.normalize_mac(mac) == "AA:BB:CC:DD:EE:FF"


def test_mac_regex():
    assert oh.MAC_RE.match("aa:bb:cc:dd:ee:ff") and oh.MAC_RE.match("aabb.ccdd.eeff")
    assert not oh.MAC_RE.match("192.0.2.10") and not oh.MAC_RE.match("uws-dt5-lan046")


def test_url_and_tenant():
    o = _client()
    assert o.base_url == "https://ordr.example.com"
    assert o._url("Devices") == o._url("/Rest/Devices") == "https://ordr.example.com/Rest/Devices"
    assert o._with_tenant(o._url("Devices"), {"mac": "x"})[1] == {"mac": "x", "tenantGuid": "tg"}
    assert "tenantGuid" not in o._with_tenant(o._url("Devices") + "?tenantGuid=tg", None)[1]


def test_device_lookup_picks_filter(monkeypatch):
    o = _client()
    seen = []
    monkeypatch.setattr(o, "devices", lambda **f: seen.append(f) or [])
    o.device("aabb.ccdd.eeff")
    o.device("192.0.2.10")
    o.device("UWS-DT5-LAN046.example.org")
    assert seen == [{"mac": "AA:BB:CC:DD:EE:FF"}, {"ip": "192.0.2.10"}, {"deviceName": "UWS-DT5-LAN046"}]


def test_get_all_paginates_and_limits(monkeypatch):
    o = _client()
    pages = [{"Devices": [{"n": 1}, {"n": 2}], "MetaData": {"next": "/Rest/Devices?clientMacToken=x"}},
             {"Devices": [{"n": 3}], "MetaData": {}}]

    class Resp:
        def __init__(self, data):
            self.data = data

        def json(self):
            return self.data

    calls = []
    monkeypatch.setattr(o, "_request", lambda url, q=None: calls.append(url) or Resp(pages[len(calls) - 1]))
    assert [d["n"] for d in o.get_all("Devices")] == [1, 2, 3]
    assert calls[1] == "https://ordr.example.com/Rest/Devices?clientMacToken=x"
    calls.clear()
    assert len(o.get_all("Devices", max_items=2)) == 2 and len(calls) == 1


def test_get_all_not_found_and_flat(monkeypatch):
    o = _client()
    for data, expected in (({"error": "not found"}, []), ({"MacAddress": "AA"}, [{"MacAddress": "AA"}])):
        monkeypatch.setattr(o, "_request", lambda url, q=None, d=data: type("R", (), {"json": lambda self: d})())
        assert o.get_all("Devices") == expected


DEVICES = [
    {"Group": "Medical Devices", "MfgName": "GE", "RiskState": "High", "connStatus": "ONLINE"},
    {"Group": "Medical Devices", "MfgName": "Philips", "RiskState": "Low", "connStatus": "ONLINE"},
    {"Group": "Printers", "MfgName": "HP", "RiskState": None, "connStatus": "OFFLINE"},
]


def test_summarize_counts_most_common_first():
    s = oh.summarize(DEVICES, ["Group", "RiskState", "Profile"])
    assert s["Group"] == [{"value": "Medical Devices", "count": 2}, {"value": "Printers", "count": 1}]
    assert {"value": "(none)", "count": 1} in s["RiskState"]
    assert s["Profile"] == [{"value": "(none)", "count": 3}]
    assert oh.summarize(DEVICES, ["MfgName"], top=1)["MfgName"] == [{"value": "GE", "count": 1}]
    assert oh.summarize([], ["Group"]) == {"Group": []}


def test_summary_fields_exist_in_columns_or_docs():
    alarms = [{"severityLevel": "HIGH", "category": "KNOWN_VULN_CONFIRMED_HIGH", "alarm_type": "x"},
              {"severityLevel": "HIGH", "category": "c2", "alarm_type": "x"}]
    s = oh.summarize(alarms, oh.ALARM_SUMMARY_FIELDS)
    assert s["severityLevel"] == [{"value": "HIGH", "count": 2}]
    assert set(oh.ALARM_SUMMARY_FIELDS) <= set(oh.ALARM_COLUMNS)


def _args(**kw):
    base = {"json": False, "summary": False, "top": 20, "limit": 100}
    base.update(kw)
    return argparse.Namespace(**base)


def test_emit_rows_table_summary_and_json(capsys):
    out = hc.Out()
    oh._emit_rows(out, _args(), DEVICES, ["Group", "MfgName"], oh.DEVICE_SUMMARY_FIELDS)
    assert out.chunks[0].splitlines()[0].split() == ["Group", "MfgName"]

    out = hc.Out()
    oh._emit_rows(out, _args(summary=True, limit=3), DEVICES, oh.DEVICE_COLUMNS, ["Group"])
    text = out.text()
    assert "3 row(s) counted" in text and "--limit 0" in text and "===== by Group" in text

    out = hc.Out()
    oh._emit_rows(out, _args(summary=True, json=True), DEVICES, oh.DEVICE_COLUMNS, ["Group"])
    assert '"rows": 3' in out.text() and '"Medical Devices"' in out.text()


def test_out_save(tmp_path, capsys):
    out = hc.Out()
    oh._emit(out, _args(), {"a": 1})
    path = tmp_path / "o.txt"
    out.save(str(path))
    out.save(str(path), append=True)
    assert path.read_text(encoding="utf-8").count('"a": 1') == 2
