[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $AdapterName,
    [Parameter(Mandatory = $true)] [string] $BackupPath,
    [Parameter(Mandatory = $true)] [string] $OperationScript,
    [Parameter(Mandatory = $true)] [string] $ResultPath
)

$ErrorActionPreference = 'Stop'
try {
    $output = & (Join-Path $PSScriptRoot 'Invoke-GuardedWifiChange.ps1') `
        -AdapterName $AdapterName `
        -BackupPath $BackupPath `
        -OperationScript $OperationScript `
        -IUnderstandThisMayInterruptWifi 2>&1
    [pscustomobject]@{ Succeeded = $true; Output = @($output | ForEach-Object { [string] $_ }); Error = $null } |
        ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}
catch {
    [pscustomobject]@{ Succeeded = $false; Output = @(); Error = $_.Exception.ToString() } |
        ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    throw
}
