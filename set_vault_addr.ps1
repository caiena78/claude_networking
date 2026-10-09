# Sets VAULT_ADDR permanently for the current Windows user, so `vault login -method=oidc`
# works in any new terminal without setting it first.
#
# Usage:  powershell -ExecutionPolicy Bypass -File .\set_vault_addr.ps1
#         powershell -ExecutionPolicy Bypass -File .\set_vault_addr.ps1 -Address https://other-vault:8200

param(
    [string]$Address = "https://vault.lcmchealth.org:8200"
)

$current = [Environment]::GetEnvironmentVariable("VAULT_ADDR", "User")
if ($current -eq $Address) {
    Write-Host "VAULT_ADDR is already set to $Address for user $env:USERNAME."
} else {
    if ($current) {
        Write-Host "Changing VAULT_ADDR from $current to $Address"
    }
    # User scope: persists across reboots and new terminals; no admin rights needed.
    [Environment]::SetEnvironmentVariable("VAULT_ADDR", $Address, "User")
    Write-Host "VAULT_ADDR set to $Address for user $env:USERNAME."
}

# Also set it in this session so it can be used right away.
$env:VAULT_ADDR = $Address

Write-Host ""
Write-Host "Open a new terminal (or restart VS Code) for other windows to pick it up, then run:"
Write-Host "    vault login -method=oidc"
