# Setup notes (Vault login problems, internal CA)

Moved out of CLAUDE.md so it only loads when needed.

## Vault login

The helpers reuse `VAULT_TOKEN` or `~/.vault-token`. If neither is valid, they open a browser OIDC login and save the new token to `~/.vault-token`. The Vault address always comes from `VAULT_ADDR` in `.env`.

**If the normal login picks the wrong Microsoft account** (for example a Sapphire account, which fails with `samaccountname not found`), use the private-browser login scripts. They are interactive, so ask the user to run them (or run one only when the user asks):

```
powershell -ExecutionPolicy Bypass -File .\vault_login.ps1      # Windows: Edge InPrivate (-Browser chrome|firefox, -Prompt login, -NoPersist)
./vault_login.sh                                               # macOS / Linux: Chrome incognito (-b edge|firefox, -p login, -n)
python vault_list.py --private --prompt login                  # sign in as a different account
```

Known problem: `claim "samaccountname" not found in token` means the account has no on-prem sAMAccountName in LCMC's tenant (a guest or B2B account such as a Sapphire account). Sign in with an LCMC account. Do not change the code to work around it.

## LCMC internal CA (ISE and Catalyst Center)

ISE (`umc-ise-pan-01`) and Catalyst Center (`ej-dnac-01`) use certificates from LCMC's internal PKI (root `EPIC-CA`, intermediates `EPIC-ICA01` and `EPIC-ICA02`), which isn't trusted on this Sapphire laptop. Vault, NetBox, Meraki and Ordr use public certificates. The root's SHA-256 fingerprint is `7A553FD7BE90FF6293A808BCF9FDF4230A2F622C70C8621C109B484BA6B4A0A4`, valid to 2064. Either install EPIC-CA as a trusted root for the current user, or set `LCMC_CACERT` (in `.env`) to the EPIC-CA PEM (`ISE_CACERT` and `CAT_CACERT` still work for one helper each). Never turn off certificate verification.
