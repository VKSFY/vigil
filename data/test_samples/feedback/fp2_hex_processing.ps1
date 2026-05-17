# Legitimate hex-string parser for a CSV containing color codes and packet
# tags. Lots of hex literals (0x...) and Convert::ToInt32, which raises some
# of the same flags our scanner uses for obfuscation, but the script does
# only data transformation.

[CmdletBinding()]
param(
    [string]$InputCsv = 'C:\data\packet_log.csv'
)

function ConvertFrom-HexByte {
    param([string]$Hex)
    return [Convert]::ToInt32($Hex, 16)
}

$rows = Import-Csv -Path $InputCsv
$summary = foreach ($r in $rows) {
    [PSCustomObject]@{
        Timestamp = $r.Timestamp
        Source    = $r.Source
        Tag       = $r.Tag
        Color     = "0x$($r.Color)"
        ColorR    = ConvertFrom-HexByte ($r.Color.Substring(0, 2))
        ColorG    = ConvertFrom-HexByte ($r.Color.Substring(2, 2))
        ColorB    = ConvertFrom-HexByte ($r.Color.Substring(4, 2))
        Bytes     = 0x100, 0x200, 0x400, 0x800
    }
}
$summary | Format-Table -AutoSize
