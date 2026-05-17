[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepoRoot)

$ErrorActionPreference = 'Stop'

$programsDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$shortcutPath = Join-Path $programsDir 'Vigil.lnk'

$python = (Get-Command python).Source
if (-not $python) { throw 'python.exe not on PATH' }

$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut($shortcutPath)
$lnk.TargetPath        = $python
$lnk.Arguments         = '-m antivirus'
$lnk.WorkingDirectory  = $RepoRoot
$lnk.IconLocation      = $python + ',0'
$lnk.Description       = 'Vigil (tray + dashboard)'
$lnk.Save()

Write-Host "  created: $shortcutPath"
