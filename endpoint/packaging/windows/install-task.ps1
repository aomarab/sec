# Install the endpoint agent as a background Scheduled Task (no dependencies).
# Runs at startup as SYSTEM and auto-restarts — functionally a service, but
# needs no pywin32. Use this if you can't install extra Python packages.
# Run in an elevated PowerShell.
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

$AppDir  = "C:\Program Files\sec-endpoint"
$ConfDir = "C:\ProgramData\sec-endpoint"
$Src = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not (Test-Path "$Src\endpoint\agent.py")) { throw "endpoint package not found next to this script." }

Write-Host "Installing agent files to $AppDir ..."
New-Item -ItemType Directory -Force -Path "$AppDir\endpoint", $ConfDir | Out-Null
Copy-Item "$Src\endpoint\*.py" "$AppDir\endpoint\" -Force

if (-not (Test-Path "$ConfDir\agent.config.json")) {
  Copy-Item "$Src\endpoint\agent.config.example.json" "$ConfDir\agent.config.json"
  Write-Host ">> Edit $ConfDir\agent.config.json and set 'server_url' and 'token'." -ForegroundColor Yellow
}

$py = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command python.exe -ErrorAction SilentlyContinue).Source }
if (-not $py) { throw "Python 3 must be installed and on PATH." }

$action = New-ScheduledTaskAction -Execute $py `
  -Argument "-m endpoint.agent --config `"$ConfDir\agent.config.json`" --loop" `
  -WorkingDirectory $AppDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
  -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "SecEndpointAgent" -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null

Write-Host ""
Write-Host "Installed as Scheduled Task 'SecEndpointAgent' (runs as SYSTEM at startup)." -ForegroundColor Green
Write-Host "Start now:  Start-ScheduledTask -TaskName SecEndpointAgent"
Write-Host "Uninstall:  Unregister-ScheduledTask -TaskName SecEndpointAgent -Confirm:`$false"
