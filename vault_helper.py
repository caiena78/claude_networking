"""Vault access shared by the scripts in this folder.

Login order:
    1. VAULT_TOKEN environment variable
    2. ~/.vault-token (written by `vault login` or by this module)
    3. OIDC (Entra ID) browser login, whose token is then saved to ~/.vault-token

Secret values are never printed or logged by this module.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

try:
    # Use the OS certificate store so an internal CA on the Vault server is trusted.
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass

HERE = Path(__file__).resolve().parent
load_dotenv(HERE / ".env")

# CA bundle paths in .env may be relative to this folder; make them absolute so scripts work from any directory.
for _var in ("LCMC_CACERT", "ISE_CACERT", "CAT_CACERT", "VAULT_CACERT"):
    if os.environ.get(_var) and not Path(os.environ[_var]).is_absolute():
        os.environ[_var] = str(HERE / os.environ[_var])

TOKEN_FILE = Path.home() / ".vault-token"
REQUIRED_SECRETS = (
    "ansible_user",
    "ansible_password",
    "ansible_become_password",
    "netbox_url",
    "netbox_token",
)


class VaultError(Exception):
    """A Vault API call failed. Holds the status, path and Vault's error text (never secret values)."""

    def __init__(self, status: int, path: str, errors: list[str]):
        self.status = status
        self.path = path
        self.errors = errors
        super().__init__(f"{status} on {path}: {'; '.join(errors) or 'no detail'}")


class Vault:
    """Minimal Vault HTTP client."""

    def __init__(self, addr: str | None = None, verify: bool | str | None = None, token: str | None = None):
        addr = addr or os.environ.get("VAULT_ADDR")
        if not addr:
            raise VaultError(0, "", ["VAULT_ADDR is not set (put it in .env)"])
        self.addr = addr.rstrip("/")
        self.verify = verify if verify is not None else (os.environ.get("VAULT_CACERT") or True)
        self.token = token

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        headers = kwargs.pop("headers", {})
        if self.token:
            headers["X-Vault-Token"] = self.token
        return requests.request(
            method, f"{self.addr}/v1/{path.lstrip('/')}",
            headers=headers, verify=self.verify, timeout=30, **kwargs,
        )

    def get_json(self, method: str, path: str, **kwargs: Any) -> dict:
        resp = self.request(method, path, **kwargs)
        if resp.status_code >= 400:
            try:
                errors = resp.json().get("errors", [])
            except ValueError:
                errors = [resp.text[:200]]
            raise VaultError(resp.status_code, path, errors)
        return resp.json() if resp.content else {}

    def token_valid(self) -> bool:
        if not self.token:
            return False
        try:
            self.get_json("GET", "auth/token/lookup-self")
            return True
        except (VaultError, requests.RequestException):
            return False

    def kv_version(self, mount: str) -> str:
        """Return '1' or '2' for a KV mount (defaults to '2' if it can't be detected)."""
        mount = mount.strip("/") + "/"
        try:
            info = self.get_json("GET", f"sys/internal/ui/mounts/{mount}")["data"]
            return str((info.get("options") or {}).get("version", "1"))
        except VaultError:
            return "2"

    def read_kv(self, mount: str, path: str) -> dict:
        mount = mount.strip("/") + "/"
        path = path.strip("/")
        if self.kv_version(mount) == "2":
            return self.get_json("GET", f"{mount}data/{path}")["data"].get("data", {})
        return self.get_json("GET", f"{mount}{path}")["data"]


# ---------------------------------------------------------------------------
# OIDC login
# ---------------------------------------------------------------------------

def find_edge() -> str | None:
    candidates = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft/Edge/Application/msedge.exe",
    ]
    return next((str(p) for p in candidates if p.exists()), None)


def oidc_login(
    vault: Vault,
    auth_mount: str = "oidc",
    role: str | None = None,
    port: int = 8250,
    prompt: str = "select_account",
    private: bool = False,
    open_browser: bool = True,
) -> str:
    """Run the OIDC browser login and return a Vault client token."""
    redirect_uri = f"http://localhost:{port}/oidc/callback"
    client_nonce = secrets.token_urlsafe(16)

    data = vault.get_json("POST", f"auth/{auth_mount}/oidc/auth_url", json={
        "role": role or "",
        "redirect_uri": redirect_uri,
        "client_nonce": client_nonce,
    })
    auth_url = data.get("data", {}).get("auth_url")
    if not auth_url:
        raise VaultError(0, f"auth/{auth_mount}/oidc/auth_url", [
            f"no auth_url returned; check the role name and that {redirect_uri} is an allowed redirect URI"])

    if prompt != "none":
        auth_url += f"&prompt={prompt}"

    result: dict[str, str] = {}
    done = threading.Event()

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/oidc/callback":
                self.send_response(404)
                self.end_headers()
                return
            result.update({k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h3>Vault login received. You can close this window.</h3>")
            done.set()

        def log_message(self, *args):
            pass

    server = HTTPServer(("localhost", port), CallbackHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print("\nComplete the Vault login in your browser. If it does not open, paste this URL "
          "into a private window:\n", file=sys.stderr)
    print(f"    {auth_url}\n", file=sys.stderr)

    if open_browser:
        edge = find_edge() if private else None
        if private and edge:
            subprocess.Popen([edge, "--inprivate", auth_url])
        else:
            if private:
                print("Edge not found; opening the default browser instead.", file=sys.stderr)
            webbrowser.open(auth_url)

    print("Waiting for OIDC authentication to complete (Ctrl+C to cancel)...", file=sys.stderr)
    try:
        while not done.wait(0.5):
            pass
    finally:
        server.shutdown()

    if "error" in result:
        raise VaultError(0, "oidc", [f"{result.get('error')}: {result.get('error_description', '')}"])

    data = vault.get_json("GET", f"auth/{auth_mount}/oidc/callback", params={
        "state": result.get("state", ""),
        "code": result.get("code", ""),
        "id_token": result.get("id_token", ""),
        "client_nonce": client_nonce,
    })
    return data["auth"]["client_token"]


def cached_token() -> str | None:
    """Return VAULT_TOKEN or the token in ~/.vault-token, if either exists."""
    token = os.environ.get("VAULT_TOKEN")
    if token:
        return token
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text().strip() or None
    return None


def save_token(token: str) -> None:
    """Save the token where the Vault CLI also looks for it."""
    TOKEN_FILE.write_text(token)


def get_token(vault: Vault, interactive: bool = True, **login_kwargs: Any) -> str:
    """Return a valid token: the cached one if it still works, otherwise a fresh OIDC login."""
    vault.token = cached_token()
    if vault.token_valid():
        return vault.token
    if not interactive:
        raise VaultError(403, "auth/token/lookup-self", [
            "no valid Vault token; run `vault login -method=oidc` first"])
    vault.token = None
    vault.token = oidc_login(vault, **login_kwargs)
    save_token(vault.token)
    return vault.token


def get_secret_values(keys: list[str] | tuple[str, ...], mount: str | None = None, path: str | None = None,
                      interactive: bool = True) -> dict[str, str]:
    """Log in if needed and return the given keys from VAULT_MOUNT/VAULT_PATH, failing if any are missing."""
    mount = mount or os.environ.get("VAULT_MOUNT")
    path = path or os.environ.get("VAULT_PATH")
    if not mount or not path:
        raise VaultError(0, "", ["VAULT_MOUNT and VAULT_PATH must be set in .env"])

    vault = Vault()
    get_token(vault, interactive=interactive)
    data = vault.read_kv(mount, path)
    missing = [key for key in keys if not data.get(key)]
    if missing:
        raise VaultError(0, f"{mount.strip('/')}/{path.strip('/')}", [f"missing secret keys: {', '.join(missing)}"])
    return {key: str(data[key]) for key in keys}


def get_secret(key: str, mount: str | None = None, path: str | None = None, interactive: bool = True) -> str:
    """Log in if needed and return one secret value from VAULT_MOUNT/VAULT_PATH (e.g. 'meraki_api')."""
    return get_secret_values([key], mount, path, interactive)[key]


def get_secrets(mount: str | None = None, path: str | None = None, interactive: bool = True) -> dict[str, str]:
    """Log in if needed and return the router and NetBox credentials stored at VAULT_MOUNT/VAULT_PATH."""
    mount = mount or os.environ.get("VAULT_MOUNT")
    path = path or os.environ.get("VAULT_PATH")
    if not mount or not path:
        raise VaultError(0, "", ["VAULT_MOUNT and VAULT_PATH must be set in .env"])

    vault = Vault()
    get_token(vault, interactive=interactive)
    data = vault.read_kv(mount, path)

    missing = [key for key in REQUIRED_SECRETS if not data.get(key)]
    if missing:
        raise VaultError(0, f"{mount.strip('/')}/{path.strip('/')}", [
            f"missing secret keys: {', '.join(missing)}"])
    return {key: str(data[key]) for key in REQUIRED_SECRETS}
