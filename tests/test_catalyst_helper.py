"""Offline tests for catalyst_helper.py output and summaries (no network, Vault or Catalyst Center)."""
import argparse

import catalyst_helper as cat
from helper_common import Out


def test_count_by_most_common_first_and_none():
    rows = [{"family": "Switches and Hubs", "reachabilityStatus": "Reachable"},
            {"family": "Switches and Hubs", "reachabilityStatus": "Reachable"},
            {"family": "Unified AP", "reachabilityStatus": "Unreachable"},
            {"family": None, "reachabilityStatus": "Reachable"}]
    assert cat.count_by(rows, cat.DEVICE_SUMMARY_KEYS) == [
        {"family": "Switches and Hubs", "reachabilityStatus": "Reachable", "count": 2},
        {"family": "(none)", "reachabilityStatus": "Reachable", "count": 1},
        {"family": "Unified AP", "reachabilityStatus": "Unreachable", "count": 1},
    ]


def test_health_bucket():
    assert cat.health_bucket(10) == "GOOD"
    assert cat.health_bucket(8) == "GOOD"
    assert cat.health_bucket(7) == "FAIR"
    assert cat.health_bucket(4) == "FAIR"
    assert cat.health_bucket(3) == "POOR"
    assert cat.health_bucket(1) == "POOR"
    assert cat.health_bucket(-1) == "NO DATA"
    assert cat.health_bucket(None) == "NO DATA"
    assert cat.health_bucket("x") == "NO DATA"


def test_device_health_summary():
    rows = [{"overallHealth": 10, "deviceType": "C9300"}, {"overallHealth": 9, "deviceType": "C9300"},
            {"overallHealth": 2, "deviceType": "AP"}, {"overallHealth": -1, "deviceType": "AP"}]
    assert cat.device_health_summary(rows) == [
        {"health": "GOOD", "deviceType": "C9300", "count": 2},
        {"health": "NO DATA", "deviceType": "AP", "count": 1},
        {"health": "POOR", "deviceType": "AP", "count": 1},
    ]


def _args(**kw):
    return argparse.Namespace(json=False, **kw)


def test_emit_table_keeps_long_issue_names(capsys):
    name = "High input/output discard on interface 'X' on a device with a fairly long description text here"
    assert 50 < len(name) < 100
    out = Out()
    cat._emit(out, _args(), [{"priority": "P2", "count": 3, "issue": name}], ["priority", "count", "issue"], width=110)
    assert name in out.text()
    assert "1 row(s)" in capsys.readouterr().err


def test_emit_json_string_and_dict(tmp_path):
    out = Out()
    cat._emit(out, _args(), "hostname X\n!")            # config: raw text
    cat._emit(out, _args(), {"a": 1}, cat.DEVICE_COLUMNS)  # one device: JSON
    cat._emit(out, argparse.Namespace(json=True), [{"hostname": "h"}], cat.DEVICE_COLUMNS)
    text = out.text()
    assert "hostname X\n!" in text and '"a": 1' in text and '"hostname": "h"' in text
    path = tmp_path / "o.txt"
    out.save(str(path))
    out.save(str(path), append=True)
    assert path.read_text(encoding="utf-8").count("hostname X") == 2
