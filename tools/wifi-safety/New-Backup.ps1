[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)] [string] $AdapterName,
    [Parameter(Mandatory = $true)] [string] $Destination,
    [string] $ResultPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'OpenAirdrop.WifiSafety.psm1') -Force
try {
    $manifest = New-WifiSafetyBackup -AdapterName $AdapterName -Destination $Destination -Confirm:$false -WhatIf:$WhatIfPreference
    if ($ResultPath) {
        [pscustomobject]@{ Succeeded = $true; Destination = $Destination; Error = $null } |
            ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    }
    $manifest
}
catch {
    if ($ResultPath) {
        [pscustomobject]@{ Succeeded = $false; Destination = $Destination; Error = $_.Exception.ToString() } |
            ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    }
    throw
}
