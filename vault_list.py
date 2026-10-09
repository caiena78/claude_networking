"""Log in to Vault with OIDC (Entra ID) and list the secrets the token can see.

Usage:
    python vault_list.py                     # pick account, list secret keys (values masked)
    python vault_list.py --private --prompt login   # sign in as a different user in an Edge InPrivate window
    python vault_list.py --show-values       # print secret values too
    python vault_list.py --mount secret --path app/  # limit to one mount / path
    python vault_list.py --reuse-token       # use VAULT_TOKEN or ~/.vault-token instead of logging in

Settings are read from .env (VAULT_ADDR, VAULT_MOUNT, VAULT_PATH). Login code lives in vault_helper.py.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterator

import requests

from vault_helper import Vault, VaultError, cached_token, oidc_login, save_token


def secret_mounts(vault: Vault, only_mount: str | None = None) -> dict[str, str]:
    """Return {mount_path/: kv_version} for KV mounts the token can see."""
    if only_mount:
        mount = only_mount.strip("/") + "/"
        return {mount: vault.kv_version(mount)}

    try:
        mounts = vault.get_json("GET", "sys/internal/ui/mounts")["data"].get("secret", {})
    except VaultError as exc:
        print(f"Could not list mounts ({exc}). Use --mount to name one.")
        return {}
    return {
        path: str((info.get("options") or {}).get("version", "1"))
        for path, info in mounts.items()
        if info.get("type") in ("kv", "generic")
    }


def walk(vault: Vault, mount: str, version: str, path: str = "") -> Iterator[str]:
    """Yield secret paths (relative to the mount) under path."""
    list_path = f"{mount}metadata/{path}" if version == "2" else f"{mount}{path}"
    try:
        keys = vault.get_json("LIST", list_path)["data"]["keys"]
    except VaultError as exc:
        if exc.status != 404:
            print(f"  ! cannot list {mount}{path}: {exc.status} {'; '.join(exc.errors)}")
        return
    for key in keys:
        if key.endswith("/"):
            yield from walk(vault, mount, version, path + key)
        else:
            yield path + key


def read_secret(vault: Vault, mount: str, version: str, path: str) -> dict:
    read_path = f"{mount}data/{path}" if version == "2" else f"{mount}{path}"
    data = vault.get_json("GET", read_path)["data"]
    return data.get("data", {}) if version == "2" else data


def main() -> None:
    parser = argparse.ArgumentParser(description="Log in to Vault with OIDC and list available secrets.")
    parser.add_argument("--addr", default=os.environ.get("VAULT_ADDR"), help="Vault address (default: VAULT_ADDR)")
    parser.add_argument("--role", default=os.environ.get("VAULT_ROLE"), help="OIDC role (default: the auth mount's default role)")
    parser.add_argument("--auth-mount", default="oidc", help="Auth method mount path (default: oidc)")
    parser.add_argument("--port", type=int, default=8250, help="Local callback port (default: 8250)")
    parser.add_argument("--prompt", choices=["select_account", "login", "none"], default="select_account",
                        help="Entra prompt behavior: select_account (pick an account), login (always ask for "
                             "password), none (reuse current session)")
    parser.add_argument("--private", action="store_true", help="Open the login in an Edge InPrivate window")
    parser.add_argument("--no-browser", action="store_true", help="Only print the login URL")
    parser.add_argument("--reuse-token", action="store_true", help="Use VAULT_TOKEN or ~/.vault-token instead of logging in")
    parser.add_argument("--no-save", action="store_true", help="Don't save the new token to ~/.vault-token")
    parser.add_argument("--mount", default=os.environ.get("VAULT_MOUNT"), help="Only list this secrets mount (default: VAULT_MOUNT, else all)")
    parser.add_argument("--all-mounts", action="store_true", help="Ignore VAULT_MOUNT and list every mount")
    parser.add_argument("--path", default=os.environ.get("VAULT_PATH", ""), help="Start under this path in the mount (default: VAULT_PATH)")
    parser.add_argument("--show-values", action="store_true", help="Print secret values (masked by default)")
    parser.add_argument("--json", dest="json_out", metavar="FILE", help="Also write the results to a JSON file")
    parser.add_argument("--ca-cert", default=os.environ.get("VAULT_CACERT"), help="CA bundle for the Vault TLS certificate")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    args = parser.parse_args()

    if not args.addr:
        sys.exit("Set VAULT_ADDR in .env or pass --addr.")

    verify = False if args.insecure else (args.ca_cert or True)
    if args.insecure:
        requests.packages.urllib3.disable_warnings()

    vault = Vault(args.addr, verify)

    if args.reuse_token:
        vault.token = cached_token()
        if not vault.token:
            sys.exit("No VAULT_TOKEN or ~/.vault-token found.")
    else:
        vault.token = oidc_login(vault, args.auth_mount, args.role, args.port,
                                 args.prompt, args.private, not args.no_browser)
        if not args.no_save:
            save_token(vault.token)

    me = vault.get_json("GET", "auth/token/lookup-self")["data"]
    print(f"\nLogged in as: {me.get('display_name')}")
    print(f"Policies:     {', '.join(me.get('policies') or [])}")
    print(f"Token TTL:    {me.get('ttl')}s\n")

    mounts = secret_mounts(vault, None if args.all_mounts else args.mount)
    if not mounts:
        sys.exit("No KV secret mounts visible to this token.")

    start = args.path.strip("/") + "/" if args.path.strip("/") else ""
    results = {}

    for mount, version in sorted(mounts.items()):
        print(f"== {mount} (kv v{version}) ==")
        found = False
        for secret_path in walk(vault, mount, version, "" if args.all_mounts else start):
            found = True
            full = f"{mount}{secret_path}"
            try:
                data = read_secret(vault, mount, version, secret_path)
            except VaultError as exc:
                print(f"  {full}  (cannot read: {exc.status})")
                results[full] = None
                continue
            results[full] = data if args.show_values else sorted(data)
            print(f"  {full}")
            for key in sorted(data):
                value = data[key] if args.show_values else "********"
                print(f"      {key} = {value}")
        if not found:
            # VAULT_PATH may point at a single secret rather than a folder; try reading it directly.
            if start:
                try:
                    data = read_secret(vault, mount, version, start.rstrip("/"))
                    full = f"{mount}{start.rstrip('/')}"
                    results[full] = data if args.show_values else sorted(data)
                    print(f"  {full}")
                    for key in sorted(data):
                        value = data[key] if args.show_values else "********"
                        print(f"      {key} = {value}")
                    found = True
                except VaultError:
                    pass
            if not found:
                print("  (nothing listable here)")
        print()

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(results, indent=2))
        print(f"Wrote {args.json_out}")


if __name__ == "__main__":
    try:
        main()
    except VaultError as exc:
        sys.exit(f"Vault error: {exc}")
    except requests.exceptions.SSLError as exc:
        sys.exit(f"TLS error talking to Vault: {exc}\nTry: pip install truststore, or pass --ca-cert <bundle>.")
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
