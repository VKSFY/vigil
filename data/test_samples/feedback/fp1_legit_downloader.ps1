# Legitimate corporate update fetcher — has Invoke-WebRequest + Start-Process
# which superficially look like a malware downloader, but the URL is an internal
# update server and there's no IEX, no AMSI patch, no obfuscation.

[CmdletBinding()]
param(
    [string]$Url = 'https://updates.corp.local/agents/latest/AgentSetup.msi',
    [string]$OutFile = "$env:TEMP\AgentSetup.msi"
)

$ErrorActionPreference = 'Stop'

Write-Host "Downloading $Url to $OutFile"
Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
$hash = (Get-FileHash -Path $OutFile -Algorithm SHA256).Hash
Write-Host "SHA256: $hash"

Write-Host "Installing silently..."
Start-Process msiexec.exe -ArgumentList @('/i', $OutFile, '/quiet', '/norestart') -Wait
Write-Host "Done."
