# Fires the four behavior test scenarios as children, then exits. Kept in
# its own file so the parent wrapper's cmdline doesn't contain anything
# the rules would match -- only the real children trigger alerts.

$winword = Join-Path $PSScriptRoot 'winword.exe'
$startup = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\synthetic_evil.txt'
$blob = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes('Write-Host enc-fired; Start-Sleep 2')
)

Start-Sleep -Seconds 4
Write-Host "[$(Get-Date -Format HH:mm:ss)] T1 - encoded PowerShell"
Start-Process powershell.exe -ArgumentList @('-EncodedCommand', $blob) -WindowStyle Hidden | Out-Null

Start-Sleep -Seconds 5
Write-Host "[$(Get-Date -Format HH:mm:ss)] T2 - hidden PowerShell"
Start-Process powershell.exe -ArgumentList @('-WindowStyle','Hidden','-Command','Start-Sleep -Seconds 2; Get-Date') -WindowStyle Hidden | Out-Null

Start-Sleep -Seconds 5
Write-Host "[$(Get-Date -Format HH:mm:ss)] T3 - winword.exe spawns powershell"
Start-Process -FilePath $winword -ArgumentList @('/c','powershell.exe -Command "Start-Sleep -Seconds 2; Write-Host child"') -WindowStyle Hidden | Out-Null

Start-Sleep -Seconds 5
Write-Host "[$(Get-Date -Format HH:mm:ss)] T4 - cmd writes to user Startup folder"
$cmd = "timeout /t 1 > nul & echo placeholder > `"$startup`""
Start-Process cmd.exe -ArgumentList @('/c', $cmd) -WindowStyle Hidden | Out-Null

Write-Host "[$(Get-Date -Format HH:mm:ss)] all four fired"
