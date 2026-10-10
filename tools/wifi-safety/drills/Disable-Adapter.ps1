[CmdletBinding()]
param([Parameter(Mandatory = $true)] [string] $AdapterName)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'OpenAirdrop.WifiSafety.psm1'
Import-Module $modulePath -Force
$record = Get-WifiAdapterRecord -AdapterName $AdapterName
Assert-Mt7925Record -Record $record
Disable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction Stop
