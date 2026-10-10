[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $AdapterName,
    [Parameter(Mandatory = $true)] [string] $BackupPath,
    [Parameter(Mandatory = $true)] [string] $ResultPath,
    [switch] $IUnderstandThisMayInterruptWifi
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'OpenAirdrop.WifiSafety.psm1') -Force
$result = [ordered]@{
    SchemaVersion = 1
    StartedAtUtc = [DateTime]::UtcNow.ToString('o')
    FinishedAtUtc = $null
    Succeeded = $false
    BackupHashesVerified = $false
    RestorePointPresent = $false
    DriverVersion = $null
    RecoveryMode = 'AdapterStateOnly'
    AdapterStatusBefore = $null
    AdapterStatusAfter = $null
    PingBefore = @()
    PingAfter = @()
    GuardedRunnerExitCode = $null
    GuardedRunnerOutput = @()
    WatchdogReport = $null
    RawFramesSubmitted = 0
    Error = $null
}
try {
    if (-not $IUnderstandThisMayInterruptWifi) { throw 'Explicit live adapter-drill acknowledgement is required.' }
    Assert-IsAdministrator
    $manifest = Test-WifiSafetyBackup -BackupPath $BackupPath
    $result.BackupHashesVerified = $true
    $restorePoint = Get-ComputerRestorePoint -ErrorAction Stop |
        Where-Object { $_.SequenceNumber -eq $manifest.RestorePoint.SequenceNumber -and $_.Description -eq $manifest.RestorePoint.Description }
    if ($null -eq $restorePoint) { throw 'The recorded System Restore point no longer exists.' }
    $result.RestorePointPresent = $true
    $before = Get-WifiAdapterRecord -AdapterName $AdapterName
    Assert-Mt7925Record -Record $before
    if ($before.PnpDeviceId -ne $manifest.Adapter.PnpDeviceId -or
        $before.DriverVersion -ne $manifest.Adapter.DriverVersion -or
        $before.InfName -ne $manifest.Adapter.InfName) { throw 'The backup does not match the active adapter and driver package.' }
    $result.DriverVersion = $before.DriverVersion
    $result.AdapterStatusBefore = $before.Status
    if ($before.Status -ne 'Up') { throw 'Adapter is not Up before the drill.' }
    $result.PingBefore = @(& ping.exe -n 2 -w 1500 1.1.1.1 | ForEach-Object { [string] $_ })
    if ($LASTEXITCODE -ne 0) { throw 'Baseline internet ping failed.' }

    $runner = Join-Path $PSScriptRoot 'Invoke-GuardedWifiChange.ps1'
    $operation = Join-Path $PSScriptRoot 'drills\Disable-Adapter.ps1'
    # A separate process preserves the guarded runner's exit code (2 means the
    # requested disable was rolled back successfully, as required for this drill).
    $result.GuardedRunnerOutput = @(& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $runner `
        -AdapterName $AdapterName -BackupPath $BackupPath -OperationScript $operation `
        -RecoveryMode AdapterStateOnly -IUnderstandThisMayInterruptWifi 2>&1 | ForEach-Object { [string] $_ })
    $result.GuardedRunnerExitCode = $LASTEXITCODE
    $jsonOutput = ($result.GuardedRunnerOutput -join [Environment]::NewLine)
    $jsonStart = $jsonOutput.IndexOf('{')
    $jsonEnd = $jsonOutput.LastIndexOf('}')
    if ($jsonStart -ge 0 -and $jsonEnd -gt $jsonStart) {
        $result.WatchdogReport = $jsonOutput.Substring($jsonStart, $jsonEnd - $jsonStart + 1) | ConvertFrom-Json
    }
    $result.AdapterStatusAfter = [string](Get-NetAdapter -Name $AdapterName).Status
    $result.PingAfter = @(& ping.exe -n 3 -w 1500 1.1.1.1 | ForEach-Object { [string] $_ })
    $pingExit = $LASTEXITCODE
    if ($result.GuardedRunnerExitCode -ne 2 -or $null -eq $result.WatchdogReport) { throw 'The live drill did not produce a confirmed watchdog rollback.' }
    $report = $result.WatchdogReport
    if ($report.RecoveryMode -ne 'AdapterStateOnly' -or -not $report.RestoreAttempted -or
        -not $report.RestoreSucceeded -or -not $report.ConnectivityRestored -or
        -not $report.WorkersStoppedBeforeRestore -or $report.RecoveryReason -ne 'deadline_expired') {
        throw 'The watchdog report did not prove the required deadline-triggered recovery.'
    }
    if ($result.AdapterStatusAfter -ne 'Up' -or $pingExit -ne 0) { throw 'Post-drill adapter or internet ping is unhealthy.' }
    $result.Succeeded = $true
}
catch { $result.Error = $_.Exception.ToString() }
finally {
    $result.FinishedAtUtc = [DateTime]::UtcNow.ToString('o')
    Write-JsonFile -Value ([pscustomobject]$result) -Path $ResultPath
}
if (-not $result.Succeeded) { exit 1 }
exit 0
