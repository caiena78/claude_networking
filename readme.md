
get the vault cli for windows
https://developer.hashicorp.com/vault/install

mac 
brew install vault-cli

## Usage

Install the Python packages:

    python -m pip install -r requirements.txt

Log in to Vault (once per token lifetime):

    $env:VAULT_ADDR = "https://vault.lcmchealth.org:8200"
    vault login -method=oidc

Sign in as a different account instead:

    python vault_list.py --private --prompt login

Look up a route on every NetBox device tagged wan_router:

    python route.py 10.158.8.1
    python route.py 10.158.8.0/24 --site <site-slug> --vrf <vrf>
    python route.py 10.158.8.1 --json


