# Install the endpoint agent as a true Windows service (services.msc).
# Requires pywin32 (installed automatically below). Run in an elevated PowerShell.
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

$AppDir  = "C:\Program Files\sec-endpoint"
$ConfDir = "C:\ProgramData\sec-endpoint"
# repo/source root that contains the 'endpoint' package (2 levels up from here)
$Src = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not (Test-Path "$Src\endpoint\agent.py")) { throw "endpoint package not found next to this script." }
$py = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $py) { throw "Python 3 (python.exe) must be installed and on PATH." }

Write-Host "Installing agent files to $AppDir ..."
New-Item -ItemType Directory -Force -Path "$AppDir\endpoint", $ConfDir | Out-Null
Copy-Item "$Src\endpoint\*.py" "$AppDir\endpoint\" -Force
Copy-Item "$PSScriptRoot\win_service.py" "$AppDir\" -Force

if (-not (Test-Path "$ConfDir\agent.config.json")) {
  Copy-Item "$Src\endpoint\agent.config.example.json" "$ConfDir\agent.config.json"
  Write-Host ">> Edit $ConfDir\agent.config.json and set 'server_url' and 'token'." -ForegroundColor Yellow
}

Write-Host "Installing pywin32 ..."
& $py -m pip install --quiet --upgrade pywin32

[Environment]::SetEnvironmentVariable("SEC_AGENT_CONFIG", "$ConfDir\agent.config.json", "Machine")
$env:SEC_AGENT_CONFIG = "$ConfDir\agent.config.json"

& $py "$AppDir\win_service.py" --startup auto install
Write-Host ""
Write-Host "Installed. After editing the config, start it with:" -ForegroundColor Green
Write-Host "  python `"$AppDir\win_service.py`" start    (or via services.msc)"
Write-Host "Uninstall: python `"$AppDir\win_service.py`" stop; python `"$AppDir\win_service.py`" remove"
