[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repositoryRoot 'tools\wifi-safety\OpenAirdrop.WifiSafety.psm1'
$drillPath = Join-Path $repositoryRoot 'tools\wifi-safety\Invoke-ReversibleDrill.ps1'
Import-Module $modulePath -Force

$passed = 0
function Assert-True {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
    $script:passed++
}

$goodRecord = [pscustomobject]@{ PnpDeviceId = 'PCI\VEN_14C3&DEV_7925'; FriendlyName = 'MediaTek Wi-Fi 7 MT7925 Wireless LAN Card'; AdapterName = 'Wi-Fi'; HardwareIds = @('PCI\VEN_14C3&DEV_7925') }
Assert-Mt7925Record -Record $goodRecord
Assert-True -Condition $true -Message 'MT7925 identity should be accepted'

$badRecord = [pscustomobject]@{ PnpDeviceId = 'USB\VID_0BDA&PID_8812'; FriendlyName = 'USB Wi-Fi adapter'; AdapterName = 'Wi-Fi 2'; HardwareIds = @('USB\VID_0BDA&PID_8812') }
$rejected = $false
try { Assert-Mt7925Record -Record $badRecord } catch { $rejected = $true }
Assert-True -Condition $rejected -Message 'Non-MT7925 targets must be rejected'

$evidenceDirectory = Join-Path $env:TEMP ('open-airdrop-test-evidence-' + [guid]::NewGuid().ToString('n'))
try {
    $evidencePath = & $drillPath -TimeoutSeconds 2 -EvidenceDirectory $evidenceDirectory
    Assert-True -Condition (Test-Path -LiteralPath $evidencePath -PathType Leaf) -Message 'Drill evidence should exist'
    $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
    Assert-True -Condition ($evidence.FinalState -eq 'healthy') -Message 'Drill must restore the harmless state'
    Assert-True -Condition ($evidence.WatchdogReport.Outcome -eq 'restored_after_timeout') -Message 'Drill must time out and restore'
    Assert-True -Condition ($evidence.ElapsedSeconds -ge 1.5) -Message 'Drill must respect its deadline'
}
finally {
    $expectedPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\open-airdrop-test-evidence-'
    $resolvedEvidenceDirectory = [IO.Path]::GetFullPath($evidenceDirectory)
    if ($resolvedEvidenceDirectory.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $evidenceDirectory)) { Remove-Item -LiteralPath $evidenceDirectory -Recurse -Force }
}

Write-Output "PASS: $passed assertions"
