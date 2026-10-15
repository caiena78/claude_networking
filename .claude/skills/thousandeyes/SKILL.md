---
name: thousandeyes
description: Cisco ThousandEyes through thousandeyes_helper.py: synthetic tests, enterprise/cloud agents, active alerts, account groups. Use for "is the ThousandEyes agent online", "what tests do we run to X", "any active TE alerts", or raw v7 API reads.
---

# ThousandEyes

Use ThousandEyes for synthetic-monitoring questions: which tests exist, which agents are online, which alerts are active. It is not the inventory (NetBox is).

**Always use `thousandeyes_helper.py`.** No ad-hoc `requests` calls. It reads your personal bearer token from the environment variable `TE_API` (not Vault; never print it, log it or write it to a file), calls the v7 API at `https://api.thousandeyes.com/v7/`, follows `_links.next` pagination and retries on `429`. It only sends `GET`.

```
python thousandeyes_helper.py test                         # connectivity + token check
python thousandeyes_helper.py groups                       # account groups (aid values)
python thousandeyes_helper.py tests --name EPIC --type agent-to-agent
python thousandeyes_helper.py agents --type enterprise --name DC
python thousandeyes_helper.py alerts --state active
python thousandeyes_helper.py get tests/<testId>           # any v7 path; -p key=value for query params
python thousandeyes_helper.py get test-results/<testId>/network
```

- Add `--json` for every field (the tables show the main columns). `-o FILE [--append]` also saves the output.
- `--aid <id>` selects an account group; the default is the token's own (LCMC HEALTH SYSTEM - 442, aid 289901).
- `tests`, `agents` and `alerts` return 100 rows by default; `--limit 0` returns all. `--name` is a client-side substring filter.
- Result endpoints (`test-results/...`, `agents/...`) go through `get`. Browse the API: https://developer.cisco.com/docs/thousandeyes/
- Never POST/PUT/DELETE (creating tests, agents or alert rules) unless the user explicitly asks for that change and confirms it. The helper can't do it anyway.
