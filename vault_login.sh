#!/bin/bash
# Logs in to Vault with OIDC (Entra ID) using a private browser window on macOS, so the
# browser's existing Microsoft session (for example a Sapphire account) isn't reused.
#
# Usage:
#   chmod +x vault_login.sh            # once
#   ./vault_login.sh                   # Chrome incognito (falls back to Edge, then Firefox)
#   ./vault_login.sh -b edge           # browser: chrome | edge | firefox
#   ./vault_login.sh -p login          # prompt: select_account (default) | login | none
#   ./vault_login.sh -r <role>         # OIDC role, if not the default
#
# The token is saved to ~/.vault-token (the Vault CLI's default) and is never printed.
# Safari has no command-line private mode, so it isn't supported.

VAULT_ADDR="${VAULT_ADDR:-https://vault.lcmchealth.org:8200}"
export VAULT_ADDR
BROWSER="chrome"
PROMPT="select_account"
ROLE=""
TIMEOUT=300

while getopts "b:p:r:t:h" opt; do
    case "$opt" in
        b) BROWSER="$OPTARG" ;;
        p) PROMPT="$OPTARG" ;;
        r) ROLE="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        *) sed -n '2,14p' "$0"; exit 0 ;;
    esac
done

if ! command -v vault >/dev/null 2>&1; then
    echo "Vault CLI not found. Install it with: brew tap hashicorp/tap && brew install hashicorp/tap/vault" >&2
    exit 1
fi

OUT="$(mktemp -t vault_login)"
VAULT_PID=""
cleanup() {
    [ -n "$VAULT_PID" ] && kill "$VAULT_PID" 2>/dev/null
    rm -f "$OUT"
}
trap cleanup EXIT INT TERM

ARGS=(login -method=oidc -no-print skip_browser=true)
[ -n "$ROLE" ] && ARGS+=("role=$ROLE")

echo "Starting Vault login against $VAULT_ADDR ..."
vault "${ARGS[@]}" >"$OUT" 2>&1 &
VAULT_PID=$!

# Wait for Vault to print the Microsoft login URL.
URL=""
for _ in $(seq 1 60); do
    URL="$(grep -oE 'https://login\.microsoftonline\.com/[^[:space:]]+' "$OUT" | head -n 1)"
    [ -n "$URL" ] && break
    kill -0 "$VAULT_PID" 2>/dev/null || break
    sleep 0.5
done
if [ -z "$URL" ]; then
    cat "$OUT"
    echo "Vault did not print a login URL. Check VAULT_ADDR and that port 8250 is free." >&2
    exit 1
fi
[ "$PROMPT" != "none" ] && URL="${URL}&prompt=${PROMPT}"

open_private() {
    case "$1" in
        chrome)  [ -d "/Applications/Google Chrome.app" ]   && open -na "Google Chrome"  --args --incognito "$URL" ;;
        edge)    [ -d "/Applications/Microsoft Edge.app" ]  && open -na "Microsoft Edge" --args --inprivate "$URL" ;;
        firefox) [ -d "/Applications/Firefox.app" ]         && open -na "Firefox"        --args -private-window "$URL" ;;
        *) return 1 ;;
    esac
}

OPENED=""
for b in "$BROWSER" chrome edge firefox; do
    if open_private "$b"; then OPENED="$b"; break; fi
done
if [ -n "$OPENED" ]; then
    echo "Opened a private $OPENED window. Sign in with your LCMC account."
else
    echo "No supported browser found. Open this URL in a private window:"
    echo
    echo "    $URL"
    echo
fi

echo "Waiting for the login to complete (up to $TIMEOUT seconds, Ctrl+C to cancel)..."
waited=0
while kill -0 "$VAULT_PID" 2>/dev/null; do
    if [ "$waited" -ge "$TIMEOUT" ]; then
        echo "Timed out waiting for the browser login." >&2
        exit 1
    fi
    sleep 1
    waited=$((waited + 1))
done
wait "$VAULT_PID"
STATUS=$?
VAULT_PID=""

if [ "$STATUS" -eq 0 ]; then
    echo
    echo "Success: logged in to Vault. The token is saved in ~/.vault-token."
    vault token lookup -format=json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)["data"]
print("Account: %s   Expires in: %d hours" % (d.get("display_name"), d.get("ttl", 0) // 3600))' 2>/dev/null
else
    grep -v 'login.microsoftonline.com' "$OUT"
    echo "Vault login failed (exit code $STATUS)." >&2
    exit "$STATUS"
fi
