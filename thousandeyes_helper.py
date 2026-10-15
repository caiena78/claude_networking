"""Read-only access to the ThousandEyes v7 REST API (api.thousandeyes.com).

The credential is your personal bearer token in the environment variable TE_API (never Vault, never printed).
The client only issues GET requests, so it can't create, change or delete tests, agents or alert rules.

API reference: https://developer.cisco.com/docs/thousandeyes/

As a module:
    from thousandeyes_helper import ThousandEyes
    te = ThousandEyes()
    te.account_groups()
    te.tests(aid="1234")
    te.get("alerts", state="active")

From the command line:
    python thousandeyes_helper.py test                       # connectivity check
    python thousandeyes_helper.py groups                     # account groups (the aid values)
    python thousandeyes_helper.py tests [--aid ID] [--type http-server] [--name text]
    python thousandeyes_helper.py agents [--aid ID] [--type enterprise] [--name text]
    python thousandeyes_helper.py alerts [--aid ID] [--state active]
    python thousandeyes_helper.py status [--all]             # latest round per enabled test, problems only
    python thousandeyes_helper.py get tests/12345 [-p key=value]
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import requests

from helper_common import Out, table, to_json

BASE_URL = "https://api.thousandeyes.com/v7/"
MAX_RETRIES = 5

TEST_COLUMNS = ["testId", "testName", "type", "interval", "enabled", "server", "url", "createdDate"]
AGENT_COLUMNS = ["agentId", "agentName", "agentType", "location", "ipAddresses", "enabled", "agentState"]
ALERT_COLUMNS = ["alertId", "testName", "ruleName", "severity", "state", "startDate", "endDate"]
GROUP_COLUMNS = ["aid", "accountGroupName", "organizationName"]


class ThousandEyesError(Exception):
    """A ThousandEyes API call failed (status, path and the API's error text; never the token)."""


class ThousandEyes:
    """Minimal read-only ThousandEyes v7 client with _links.next pagination and 429 retry."""

    def __init__(self, token: str | None = None, timeout: int = 60):
        token = token or os.environ.get("TE_API")
        if not token:
            raise ThousandEyesError("TE_API environment variable is not set")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
        self.timeout = timeout

    def _get(self, url: str, params: dict | None = None) -> Any:
        for attempt in range(MAX_RETRIES):
            r = self.session.get(url, params=params, timeout=self.timeout)
            if r.status_code != 429:
                break
            time.sleep(float(r.headers.get("Retry-After", 2 ** attempt)))
        if not r.ok:
            raise ThousandEyesError(f"{r.status_code} on GET {url.replace(BASE_URL, '')}: {r.text[:300]}")
        return r.json()

    def get(self, path: str, **params: Any) -> Any:
        return self._get(BASE_URL + path.lstrip("/"), {k: v for k, v in params.items() if v is not None})

    def get_all(self, path: str, key: str, max_items: int | None = None, **params: Any) -> list:
        """Rows under `key`, following _links.next until max_items (None = all)."""
        data = self.get(path, **params)
        rows = list(data.get(key, []))
        while data.get("_links", {}).get("next", {}).get("href") and (not max_items or len(rows) < max_items):
            data = self._get(data["_links"]["next"]["href"])
            rows += data.get(key, [])
        return rows[:max_items] if max_items else rows

    def account_groups(self) -> list:
        return self.get("account-groups").get("accountGroups", [])

    def tests(self, aid: str | None = None, **filters: Any) -> list:
        return self.get_all("tests", "tests", aid=aid, **filters)

    def agents(self, aid: str | None = None, **filters: Any) -> list:
        return self.get_all("agents", "agents", aid=aid, **filters)

    def alerts(self, aid: str | None = None, **filters: Any) -> list:
        return self.get_all("alerts", "alerts", aid=aid, **filters)


RESULT_PATH = {"http-server": "http-server"}  # everything else (agent-to-server, agent-to-agent) is "network"


def test_status(te: ThousandEyes, test: dict) -> dict:
    """Latest round of one test: how many agents report a problem (loss or an HTTP error) and the worst one."""
    kind = RESULT_PATH.get(test["type"], "network")
    row = {"testId": test["testId"], "testName": test["testName"], "type": test["type"], "agents": 0, "bad": 0, "stale": 0, "worst": "", "latest": "", "created": (test.get("createdDate") or "")[:10]}
    try:
        results = te.get(f"test-results/{test['testId']}/{kind}").get("results", [])
    except ThousandEyesError as exc:
        return {**row, "worst": f"query failed: {str(exc)[:80]}"}
    now = datetime.now(timezone.utc)
    for r in results:
        row["agents"] += 1
        row["latest"] = max(row["latest"], r.get("date", ""))
        age = (now - datetime.fromisoformat(r["date"].replace("Z", "+00:00"))).total_seconds() if r.get("date") else 0
        if age > max(3 * (test.get("interval") or 300), 900):  # enabled but not reporting: stale beats "healthy"
            row["bad"] += 1
            row["stale"] += 1
            row["worst"] = row["worst"] or f"{(r.get('agent') or {}).get('agentName', '?')}: stale, last result {r['date']}"
            continue
        err = r.get("errorType") if kind == "http-server" and r.get("errorType") not in (None, "None") else None
        code = r.get("responseCode") or 0
        loss = r.get("loss") or 0
        if err or code >= 400 or loss > 0:
            row["bad"] += 1
            detail = err or (f"HTTP {code}" if code >= 400 else f"loss {loss:g}%")
            if not row["worst"] or loss == 100 or err:
                row["worst"] = f"{(r.get('agent') or {}).get('agentName', '?')}: {detail}"
    row["latest"] = row["latest"][:10]
    if not results:
        row["worst"] = "no results"
    return row


def _emit(out: Out, args: argparse.Namespace, data: Any, columns: list[str] | None = None) -> None:
    out.add(to_json(data) if args.json or not columns else table(data, columns))


def _match(rows: list, field: str, text: str | None) -> list:
    return [r for r in rows if text.lower() in str(r.get(field, "")).lower()] if text else rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only ThousandEyes helper (token in env var TE_API)")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("-o", "--output", help="also write the output to this file")
    parser.add_argument("--append", action="store_true", help="with -o: append")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("test", help="Check connectivity and the token")
    sub.add_parser("groups", help="Account groups (aid values)")
    for name, helptext in (("tests", "Tests"), ("agents", "Agents"), ("alerts", "Alerts")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--aid", help="Account group id (default: the token's own group)")
        if name != "alerts":
            p.add_argument("--type", help="Filter by type")
            p.add_argument("--name", help="Only names containing this text")
        else:
            p.add_argument("--state", help="e.g. active, cleared")
        p.add_argument("--limit", type=int, default=100, help="Max rows (default 100; 0 = all)")
    p = sub.add_parser("status", help="Latest results for every enabled test; problems first")
    p.add_argument("--aid", help="Account group id")
    p.add_argument("--all", action="store_true", help="Also list healthy tests")
    p.add_argument("--dead", action="store_true", help="Only tests where every agent's last result is old")
    p = sub.add_parser("get", help="GET any API path, e.g. tests/12345")
    p.add_argument("path")
    p.add_argument("-p", "--param", action="append", default=[], metavar="KEY=VALUE", help="Query parameter; repeat for more")

    # Accept --json/-o/--append after the subcommand too (SUPPRESS keeps a value given before it).
    for subparser in sub.choices.values():
        subparser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="print JSON")
        subparser.add_argument("-o", "--output", default=argparse.SUPPRESS, help="also write the output to this file")
        subparser.add_argument("--append", action="store_true", default=argparse.SUPPRESS, help="with -o: append")
    args = parser.parse_args()
    out = Out()
    te = ThousandEyes()
    limit = getattr(args, "limit", 0) or None

    if args.cmd == "test":
        groups = te.account_groups()
        out.add(f"OK: authenticated to ThousandEyes, {len(groups)} account group(s) visible")
        out.add(table(groups, GROUP_COLUMNS))
    elif args.cmd == "groups":
        _emit(out, args, te.account_groups(), GROUP_COLUMNS)
    elif args.cmd == "tests":
        rows = te.tests(args.aid, type=args.type)
        _emit(out, args, _match(rows, "testName", args.name)[:limit], TEST_COLUMNS)
    elif args.cmd == "agents":
        rows = te.agents(args.aid, agentType=args.type)
        _emit(out, args, _match(rows, "agentName", args.name)[:limit], AGENT_COLUMNS)
    elif args.cmd == "alerts":
        _emit(out, args, te.alerts(args.aid, max_items=limit, state=args.state), ALERT_COLUMNS)
    elif args.cmd == "status":
        tests = [t for t in te.tests(args.aid) if t.get("enabled")]
        with ThreadPoolExecutor(8) as pool:
            rows = list(pool.map(lambda t: test_status(te, t), tests))
        rows.sort(key=lambda r: (-r["bad"], r["testName"]))
        out.add(f"{len(rows)} enabled tests, {sum(r['bad'] > 0 for r in rows)} with problems on the latest round")
        if args.dead:
            rows = sorted((r for r in rows if r["agents"] and r["stale"] == r["agents"]), key=lambda r: r["latest"])
            _emit(out, args, rows, ["testId", "testName", "type", "agents", "created", "latest"])
        else:
            _emit(out, args, rows if args.all or args.json else [r for r in rows if r["bad"]],
                  ["testId", "testName", "type", "bad", "agents", "worst"])
    elif args.cmd == "get":
        _emit(out, args, te.get(args.path, **dict(kv.split("=", 1) for kv in args.param)))
    out.save(args.output, args.append)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ThousandEyesError as exc:
        sys.exit(f"ThousandEyes error: {exc}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
