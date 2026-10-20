import ipaddress

import pytest

import nmap_helper as n

XML = """<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/>
<address addr="10.1.1.5" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Cisco"/>
<hostnames><hostname name="sw1.example"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>
<host><status state="down" reason="no-response"/><address addr="10.1.1.6" addrtype="ipv4"/></host>
<runstats><finished elapsed="1.5"/><hosts up="1" down="1" total="2"/></runstats></nmaprun>"""


def test_targets_private_only():
    assert n.count_addresses(n.parse_targets(["10.1.1.0/24", "10.2.2.10-20"])) == 256 + 11
    assert n.parse_target("10.1.1.5-10.1.1.9") == list(ipaddress.summarize_address_range(
        ipaddress.IPv4Address("10.1.1.5"), ipaddress.IPv4Address("10.1.1.9")))
    for bad in ("8.8.8.8", "10.0.0.0/7", "127.0.0.1", "169.254.1.1", "224.0.0.1", "10.1.1.300", "host.example"):
        with pytest.raises(n.ScanError):
            n.parse_target(bad)


def test_netbox_name_resolved_through_callback():
    assert n.parse_target("sw1", lambda name: "10.9.9.9") == [ipaddress.IPv4Network("10.9.9.9/32")]
    with pytest.raises(n.ScanError):
        n.parse_target("sw1", lambda name: "8.8.8.8")


def test_ports_and_limits():
    assert n.validate_ports("22,80,8000-8100") == ("22,80,8000-8100", 103)
    assert n.validate_ports("all") == ("1-65535", 65535)
    for bad in ("22;ls", "0", "70000", "90-80", "T:22", ""):
        with pytest.raises(n.ScanError):
            n.validate_ports(bad)
    n.check_limits("sweep", 1024, 1024)
    with pytest.raises(n.ScanError):
        n.check_limits("sweep", 1025, 1024)
    with pytest.raises(n.ScanError):
        n.check_limits("sweep", 10, 5000)
    with pytest.raises(n.ScanError):
        n.check_limits("ports", 17, 1024, ports=65535)
    with pytest.raises(n.ScanError):
        n.check_limits("ports", 65, 1024, ports=10, udp=True)


def test_build_command_has_only_known_flags():
    nets = n.parse_targets(["10.1.1.0/30"])
    cmd = n.build_command("nmap", "ports", nets, [], ports="22,443", syn=True)
    assert cmd[:3] == ["nmap", "-oX", "-"] and "-T3" in cmd and "-sS" in cmd and "--open" in cmd and cmd[-1] == "10.1.1.0/30"
    assert "-sn" in n.build_command("nmap", "sweep", nets, [], tcp_ping="22,443") and "-PS22,443" in n.build_command(
        "nmap", "sweep", nets, [], tcp_ping="22,443")
    for kw in ({"timing": 4}, {"rate": 5000}, {"timing": 0}):
        with pytest.raises(n.ScanError):
            n.build_command("nmap", "sweep", nets, [], **kw)


def test_parse_xml():
    r = n.parse_xml(XML)
    assert r["up"] == 1 and r["total"] == 2 and r["seconds"] == 1.5 and len(r["hosts"]) == 1
    h = r["hosts"][0]
    assert h["ip"] == "10.1.1.5" and h["mac"] == "aa:bb:cc:dd:ee:ff" and h["vendor"] == "Cisco" and h["hostname"] == "sw1.example"
    assert h["ports"] == [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}]


def test_nmap_not_found(monkeypatch, capsys):
    monkeypatch.setattr(n.shutil, "which", lambda name: None)
    with pytest.raises(n.ScanError, match="nmap not found"):
        n.find_nmap()
    monkeypatch.setattr(n.sys, "argv", ["nmap_helper.py", "sweep", "lakeview-wlc-ha01"])  # a NetBox name: must not reach NetBox
    assert n.main() == 2
    assert "nmap not found" in capsys.readouterr().err


def test_nmap_found_on_path(monkeypatch):
    monkeypatch.setattr(n.shutil, "which", lambda name: "/usr/bin/nmap")
    assert n.find_nmap() == "/usr/bin/nmap"


def test_icmp_only_replaces_default_probes():
    nets = n.parse_targets(["10.1.1.0/30"])
    cmd = n.build_command("nmap", "sweep", nets, [], icmp_only=True, tcp_ping="22")
    assert "-sn" in cmd and "-PE" in cmd and not any(c.startswith("-PS") for c in cmd)
    assert "-PE" not in n.build_command("nmap", "sweep", nets, [])
