# Logs in to Vault with OIDC (Entra ID) using a private browser window, so the browser's
# existing Microsoft session (for example a Sapphire account) isn't reused.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\vault_login.ps1
#   powershell -ExecutionPolicy Bypass -File .\vault_login.ps1 -Prompt login        # always ask for password
#   powershell -ExecutionPolicy Bypass -File .\vault_login.ps1 -Browser chrome
#
# The token is saved to ~\.vault-token (the Vault CLI's default) and is never printed.

param(
    [string]$Address = $(if ($env:VAULT_ADDR) { $env:VAULT_ADDR } else { "https://vault.lcmchealth.org:8200" }),
    [ValidateSet("select_account", "login", "none")]
    [string]$Prompt = "select_account",
    [ValidateSet("edge", "chrome", "firefox")]
    [string]$Browser = "edge",
    [string]$Role = "",
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"

# Find the Vault CLI.
$vault = (Get-Command vault -ErrorAction SilentlyContinue).Source
if (-not $vault -and (Test-Path "C:\Program Files\vault\vault.exe")) { $vault = "C:\Program Files\vault\vault.exe" }
if (-not $vault) { Write-Error "Vault CLI not found. Install it from https://developer.hashicorp.com/vault/install" }

# Find the browser and its private-window flag.
$browsers = @{
    edge    = @{ Flag = "--inprivate";        Paths = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") }
    chrome  = @{ Flag = "--incognito";        Paths = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") }
    firefox = @{ Flag = "-private-window";    Paths = @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") }
}
$browserExe = $browsers[$Browser].Paths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

$env:VAULT_ADDR = $Address
$out = [System.IO.Path]::GetTempFileName()
$err = [System.IO.Path]::GetTempFileName()

$vaultArgs = @("login", "-method=oidc", "-no-print", "skip_browser=true")
if ($Role) { $vaultArgs += "role=$Role" }

Write-Host "Starting Vault login against $Address ..."
$proc = Start-Process -FilePath $vault -ArgumentList $vaultArgs -NoNewWindow -PassThru `
    -RedirectStandardOutput $out -RedirectStandardError $err
$null = $proc.Handle  # PowerShell 5.1 only reports ExitCode if the handle was opened before exit

try {
    # Wait for Vault to print the Microsoft login URL.
    $url = $null
    for ($i = 0; $i -lt 60 -and -not $url -and -not $proc.HasExited; $i++) {
        Start-Sleep -Milliseconds 500
        $text = (Get-Content $out, $err -Raw -ErrorAction SilentlyContinue) -join "`n"
        if ($text -match "(https://login\.microsoftonline\.com/\S+)") { $url = $Matches[1] }
    }
    if (-not $url) {
        Write-Host ((Get-Content $out, $err -Raw -ErrorAction SilentlyContinue) -join "`n")
        throw "Vault did not print a login URL. Check VAULT_ADDR and that port 8250 is free."
    }
    if ($Prompt -ne "none") { $url += "&prompt=$Prompt" }

    if ($browserExe) {
        Start-Process -FilePath $browserExe -ArgumentList $browsers[$Browser].Flag, "`"$url`""
        Write-Host "Opened a private $Browser window. Sign in with your LCMC account."
    } else {
        Write-Host "Could not find $Browser. Open this URL in a private/incognito window:"
        Write-Host ""
        Write-Host "    $url"
        Write-Host ""
    }

    Write-Host "Waiting for the login to complete (up to $TimeoutSeconds seconds, Ctrl+C to cancel)..."
    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $proc.Id -Force
        throw "Timed out waiting for the browser login."
    }

    if ($proc.ExitCode -eq 0) {
        Write-Host ""
        Write-Host "Success: logged in to Vault. The token is saved in $HOME\.vault-token."
        & $vault token lookup -format=json 2>$null | ConvertFrom-Json | ForEach-Object {
            Write-Host ("Account: {0}   Expires in: {1:N0} hours" -f $_.data.display_name, ($_.data.ttl / 3600))
        }
    } else {
        Write-Host ((Get-Content $err -Raw -ErrorAction SilentlyContinue))
        throw "Vault login failed (exit code $($proc.ExitCode))."
    }
}
finally {
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
}
