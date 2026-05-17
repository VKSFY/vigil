[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepoRoot)

$ErrorActionPreference = 'Stop'

$python = (Get-Command python).Source
if (-not $python) { throw 'python.exe not on PATH' }

# Run keys execute from %USERPROFILE% by default, so wrap in cmd /c and
# cd into the repo first. Both python.exe and $RepoRoot are quoted to
# survive spaces in the install path.
$cmd = "cmd.exe /c `"cd /d `"$RepoRoot`" && `"$python`" -m antivirus`""

$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name 'AVMonitor' -Value $cmd -Type String

Write-Host "  registered: HKCU\...\Run\AVMonitor = $cmd"
