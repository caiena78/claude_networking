#!/bin/bash
# Logs in to Vault with OIDC (Entra ID) using a private browser window on macOS or Linux, so the
# browser's existing Microsoft session (for example a Sapphire account) isn't reused.
#
# Usage:
#   chmod +x vault_login.sh            # once
#   ./vault_login.sh                   # Chrome incognito (falls back to Edge, then Firefox)
#   ./vault_login.sh -b edge           # browser: chrome | edge | firefox
#   ./vault_login.sh -p login          # prompt: select_account (default) | login | none
#   ./vault_login.sh -r <role>         # OIDC role, if not the default
#   ./vault_login.sh -n                # don't save VAULT_ADDR to the shell profile
#
# The token is saved to ~/.vault-token (the Vault CLI's default) and is never printed.
# The Vault address (from .env) is also saved permanently as an "export VAULT_ADDR=..." line in your
# shell profile (~/.zshrc, ~/.bash_profile on macOS bash, ~/.bashrc on Linux bash, else ~/.profile),
# so the Vault CLI works in any new terminal. Use -n to skip that.
# Safari has no command-line private mode, so it isn't supported.

# The Vault address: VAULT_ADDR in .env next to this script (the source of truth; not committed to git),
# else $VAULT_ADDR from the environment.
ENV_FILE="$(dirname "$0")/.env"
if [ -f "$ENV_FILE" ]; then
    ENV_ADDR="$(grep -E '^[[:space:]]*VAULT_ADDR[[:space:]]*=' "$ENV_FILE" | head -n 1 | cut -d= -f2- \
        | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^["'\'']//' -e 's/["'\'']$//')"
    [ -n "$ENV_ADDR" ] && VAULT_ADDR="$ENV_ADDR"
fi
if [ -z "$VAULT_ADDR" ]; then
    echo "VAULT_ADDR is not set. Add it to .env (VAULT_ADDR=https://<vault-host>:8200)." >&2
    exit 1
fi
export VAULT_ADDR
BROWSER="chrome"
PROMPT="select_account"
ROLE=""
TIMEOUT=300
PERSIST=1
OS="$(uname -s)"   # Darwin or Linux

while getopts "b:p:r:t:nh" opt; do
    case "$opt" in
        b) BROWSER="$OPTARG" ;;
        p) PROMPT="$OPTARG" ;;
        r) ROLE="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        n) PERSIST=0 ;;
        *) sed -n '2,17p' "$0"; exit 0 ;;
    esac
done

# Save VAULT_ADDR permanently: one marked line in the shell profile, replaced only when the address changes.
PROFILE_MARK="# set by vault_login.sh"
profile_file() {
    case "$(basename "${SHELL:-}")" in
        zsh)  echo "$HOME/.zshrc" ;;
        bash) if [ "$OS" = "Darwin" ]; then echo "$HOME/.bash_profile"; else echo "$HOME/.bashrc"; fi ;;
        *)    echo "$HOME/.profile" ;;
    esac
}
persist_vault_addr() {
    local file line tmp
    file="$(profile_file)"
    line="export VAULT_ADDR=\"$VAULT_ADDR\"  $PROFILE_MARK"
    if [ -f "$file" ] && grep -qxF "$line" "$file"; then
        return 0  # already saved
    fi
    if [ -f "$file" ] && grep -qF "$PROFILE_MARK" "$file"; then
        # Replace the old line in place; "cat >" keeps the file's permissions and any symlink.
        tmp="$(mktemp "${TMPDIR:-/tmp}/vault_profile.XXXXXX")" || return 1
        grep -vF "$PROFILE_MARK" "$file" >"$tmp"
        printf '%s\n' "$line" >>"$tmp"
        cat "$tmp" >"$file" && rm -f "$tmp"
        echo "Updated the permanent VAULT_ADDR in $file."
    else
        printf '\n%s\n' "$line" >>"$file"
        echo "Saved VAULT_ADDR permanently in $file. New terminals will pick it up."
    fi
}
[ "$PERSIST" -eq 1 ] && persist_vault_addr

if ! command -v vault >/dev/null 2>&1; then
    if [ "$OS" = "Darwin" ]; then
        echo "Vault CLI not found. Install it with: brew tap hashicorp/tap && brew install hashicorp/tap/vault" >&2
    else
        echo "Vault CLI not found. Install it from https://developer.hashicorp.com/vault/install (apt, dnf or zip)." >&2
    fi
    exit 1
fi

OUT="$(mktemp "${TMPDIR:-/tmp}/vault_login.XXXXXX")"
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

# Run the first of these Linux browser commands that exists, detached from this terminal.
linux_launch() {
    local flag="$1" cmd
    shift
    for cmd in "$@"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            nohup "$cmd" "$flag" "$URL" >/dev/null 2>&1 &
            return 0
        fi
    done
    return 1
}

open_private() {
    if [ "$OS" = "Darwin" ]; then
        case "$1" in
            chrome)  [ -d "/Applications/Google Chrome.app" ]   && open -na "Google Chrome"  --args --incognito "$URL" ;;
            edge)    [ -d "/Applications/Microsoft Edge.app" ]  && open -na "Microsoft Edge" --args --inprivate "$URL" ;;
            firefox) [ -d "/Applications/Firefox.app" ]         && open -na "Firefox"        --args -private-window "$URL" ;;
            *) return 1 ;;
        esac
    else
        case "$1" in
            chrome)  linux_launch --incognito google-chrome google-chrome-stable chromium chromium-browser ;;
            edge)    linux_launch --inprivate microsoft-edge microsoft-edge-stable ;;
            firefox) linux_launch -private-window firefox ;;
            *) return 1 ;;
        esac
    fi
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
