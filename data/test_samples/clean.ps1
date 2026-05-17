# Generate a small inventory CSV for the local machine.
# Pure read-only system telemetry — nothing malicious.

[CmdletBinding()]
param(
    [string]$OutPath = "$env:USERPROFILE\Desktop\inventory.csv"
)

function Get-DiskSummary {
    Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3" |
        ForEach-Object {
            [PSCustomObject]@{
                Drive  = $_.DeviceID
                SizeGB = [math]::Round($_.Size / 1GB, 1)
                FreeGB = [math]::Round($_.FreeSpace / 1GB, 1)
            }
        }
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
$disk = Get-DiskSummary

$report = [PSCustomObject]@{
    Hostname       = $env:COMPUTERNAME
    OperatingSystem = $os.Caption
    Build           = $os.BuildNumber
    Cpu             = $cpu.Name
    Cores           = $cpu.NumberOfCores
    LogicalCores    = $cpu.NumberOfLogicalProcessors
    Drives          = ($disk | ConvertTo-Json -Compress)
    GeneratedAt     = (Get-Date).ToString("s")
}

$report | Export-Csv -Path $OutPath -NoTypeInformation -Force
Write-Host "Inventory written to $OutPath"
