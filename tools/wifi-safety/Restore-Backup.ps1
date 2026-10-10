[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)] [string] $AdapterName,
    [Parameter(Mandatory = $true)] [string] $BackupPath,
    [switch] $IUnderstandThisRestartsWifi
)

$ErrorActionPreference = 'Stop'
if (-not $IUnderstandThisRestartsWifi) {
    throw 'Refusing live restore. Pass -IUnderstandThisRestartsWifi only with local recovery access available.'
}
Import-Module (Join-Path $PSScriptRoot 'OpenAirdrop.WifiSafety.psm1') -Force
Restore-WifiSafetyBackup -AdapterName $AdapterName -BackupPath $BackupPath -Confirm:$false -WhatIf:$WhatIfPreference
