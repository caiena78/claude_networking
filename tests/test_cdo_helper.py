import cdo_helper as c


def lit(value):
    return {"literals": [{"type": "Network", "value": value}]}


def ports(*items):
    return {"literals": [{"type": "PortLiteral", "protocol": p, "port": n} for p, n in items]}


def rule(idx, action, src=None, dst=None, port=None, enabled=True, **extra):
    return {"id": f"r{idx}", "name": f"rule{idx}", "action": action, "enabled": enabled, "ruleType": "PREFILTER",
            "metadata": {"ruleIndex": idx}, "sourceNetworks": src, "destinationNetworks": dst,
            "destinationPorts": port, **extra}


def test_targets_ranges_and_cidrs():
    assert c.Target("10.194.0.10-10.194.0.20").hi - c.Target("10.194.0.10-10.194.0.20").lo == 10
    big = [(4, *c.parse_net_value("10.194.0.0/16")[1:], "big")]
    assert c.net_match(c.Target("10.194.2.0/23"), big) == ["big"]
    assert c.net_match(c.Target("10.195.0.1"), big) == []
    assert c.net_overlap(c.Target("10.193.255.0-10.194.0.5"), big) == ["big"]


def test_requested_ports_and_matching():
    req = c.parse_requested_ports("443,udp/53,any/22,8000-8010,icmp")
    assert [r[3] for r in req] == ["TCP/443", "UDP/53", "any/22", "TCP/8000-8010", "ICMP"]
    elements = [("TCP", 443, 443, "https"), ("UDP", 16500, 16509, "citrix-udp"), ("TCP", 8000, 8100, "range")]
    assert c.port_match(req[0], elements) == ["https"]
    assert c.port_match(req[1], elements) == []                       # UDP 53 not there
    assert c.port_match(req[3], elements) == ["range"]                # range inside a range
    assert c.port_match(("TCP", 16500, 16500, "x"), elements) == []    # right number, wrong protocol
    assert c.port_match(req[0], None) == ["any"]


def test_parse_cells_from_pasted_spreadsheet():
    ips = c.parse_ip_cell("NetScaler:\n10.194.23.197-200\n10.194.23.209")
    assert [str(t) for t in ips] == ["10.194.23.197-10.194.23.200", "10.194.23.209"]
    assert c.parse_port_cell("80, 443, 1494, 2598 - TCP\n\n16500-16509 - UDP") == \
        "tcp/80,tcp/443,tcp/1494,tcp/2598,udp/16500-16509"
    rows = c.read_rows('"10.1.1.1"\t"10.2.2.2"\t"443"\tUDP\n')
    assert rows == [["10.1.1.1", "10.2.2.2", "443 - UDP"]]


def test_check_ports_first_match_wins(capsys):
    rules = [
        rule(1, "BLOCK", lit("10.1.1.0/24"), lit("10.2.2.0/24"), ports(("6", "22"))),
        rule(2, "FASTPATH", lit("10.1.0.0/16"), lit("10.2.0.0/16"), ports(("6", "22"), ("6", "443"))),
        rule(3, "FASTPATH", lit("10.1.0.0/16"), lit("10.2.0.0/16"), ports(("6", "8443")), enabled=False),
    ]
    hits = c.check_ports(rules, c.Target("10.1.1.5"), c.Target("10.2.2.5"),
                         c.parse_requested_ports("22,443,8443"))
    assert hits["TCP/22"][0]["name"] == "rule1"            # BLOCK above the allow
    assert hits["TCP/443"][0]["name"] == "rule2"
    assert hits["TCP/8443"] is None                       # only a disabled rule has it
    assert "DISABLED rules that would have matched" in capsys.readouterr().out


def test_acp_evaluate_monitor_conditional_and_default():
    rules = [
        rule(1, "MONITOR", lit("10.1.0.0/16"), None, None),
        rule(2, "ALLOW", lit("10.1.0.0/16"), None, ports(("6", "443")), applications={"applications": [{"name": "x"}]}),
        rule(3, "BLOCK", lit("10.1.0.0/16"), None, ports(("6", "443"))),
        rule(4, "TRUST", lit("10.1.0.0/16"), None, ports(("6", "22"))),
    ]
    res = c.acp_evaluate(rules, "BLOCK", c.Target("10.1.2.3"), c.Target("8.8.8.8"),
                         c.parse_requested_ports("443,22,3389"))
    assert res["TCP/443"]["verdict"] == "DENIED" and res["TCP/443"]["rule"]["name"] == "rule3"
    assert [s[0]["name"] for s in res["TCP/443"]["skipped"]] == ["rule1", "rule2"]
    assert res["TCP/22"]["verdict"] == "ALLOWED" and res["TCP/22"]["action"] == "TRUST"
    assert res["TCP/3389"]["action"] == "DEFAULT BLOCK" and res["TCP/3389"]["rule"] is None


def test_nat_matches_ignores_any(monkeypatch):
    c._cache.update({("Host", "h1"): {"value": "10.194.30.20"}, ("Network", "any"): {"value": "0.0.0.0/0"}})
    rules = [{"kind": "manual", "natType": "STATIC",
              "originalSource": {"type": "Network", "id": "any", "name": "any-ipv4"},
              "originalDestination": {"type": "Host", "id": "h1", "name": "DMZ_HOST"}}]
    hits = c.nat_matches(rules, c.Target("10.194.30.20"))
    assert len(hits) == 1 and hits[0]["matched"] == ["originalDestination"]
    assert c.nat_matches(rules, c.Target("10.9.9.9")) == []
    assert c.nat_matches(rules, c.Target("10.9.9.9"), include_any=True)[0]["matched"] == ["originalSource"]
