[CmdletBinding()]
param([Parameter(Mandatory = $true)] [string] $RunDirectory)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-WatchdogJson {
    param([object] $Value, [string] $Path)
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath "$Path.tmp" -Encoding UTF8
    Move-Item -LiteralPath "$Path.tmp" -Destination $Path -Force
}

function Test-DrillHealth {
    param([object] $Config)
    if (-not (Test-Path -LiteralPath $Config.StatePath -PathType Leaf)) { return $false }
    return ((Get-Content -LiteralPath $Config.StatePath -Raw).Trim() -eq [string] $Config.HealthyContent)
}

$startedAt = [DateTime]::UtcNow
$reportPath = Join-Path $RunDirectory 'report.json'
$logPath = Join-Path $RunDirectory 'watchdog.log'
$report = [ordered]@{
    SchemaVersion = 1
    StartedAtUtc = $startedAt.ToString('o')
    FinishedAtUtc = $null
    Mode = $null
    OperationExitCode = $null
    ConnectivityRestored = $false
    RestoreAttempted = $false
    RestoreSucceeded = $false
    Outcome = 'running'
    Error = $null
}

try {
    $configPath = Join-Path $RunDirectory 'watchdog.json'
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $report.Mode = [string] $config.Mode
    if ([int] $config.TimeoutSeconds -lt 1 -or [int] $config.TimeoutSeconds -gt 30) {
        throw 'TimeoutSeconds must be between 1 and 30. Production configurations must use 30.'
    }
    "$(Get-Date -Format o) watchdog started in $($config.Mode) mode" | Set-Content -LiteralPath $logPath -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $RunDirectory 'ready.signal') -Value $startedAt.ToString('o') -Encoding ASCII

    $deadline = [DateTime]::UtcNow.AddSeconds([int] $config.TimeoutSeconds)
    if ($config.Mode -eq 'drill') {
        Set-Content -LiteralPath $config.StatePath -Value ([string] $config.BrokenContent) -Encoding ASCII
        $report.OperationExitCode = 0
    }
    elseif ($config.Mode -eq 'production') {
        if ([int] $config.TimeoutSeconds -ne 30) {
            throw 'Production watchdogs must use the fixed 30-second timeout.'
        }
        if (-not (Test-Path -LiteralPath $config.OperationScript -PathType Leaf)) {
            throw "Operation script is missing: $($config.OperationScript)"
        }
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $config.OperationScript -AdapterName $config.AdapterName
        $report.OperationExitCode = $LASTEXITCODE
    }
    else {
        throw "Unknown watchdog mode '$($config.Mode)'."
    }

    $healthy = $false
    $forceRestore = ($config.Mode -eq 'production' -and [int] $report.OperationExitCode -ne 0)
    while (-not $forceRestore -and [DateTime]::UtcNow -lt $deadline) {
        if ($config.Mode -eq 'drill') {
            $healthy = Test-DrillHealth -Config $config
        }
        else {
            Import-Module $config.ModulePath -Force
            $healthy = Test-InternetConnectivity -Endpoints @($config.Endpoints)
        }
        if ($healthy) { break }
        Start-Sleep -Milliseconds 500
    }

    if (-not $healthy -or $forceRestore) {
        $report.RestoreAttempted = $true
        if ($config.Mode -eq 'drill') {
            Set-Content -LiteralPath $config.StatePath -Value ([string] $config.HealthyContent) -Encoding ASCII
            $report.RestoreSucceeded = Test-DrillHealth -Config $config
        }
        else {
            Import-Module $config.ModulePath -Force
            Restore-WifiSafetyBackup -BackupPath $config.BackupPath -AdapterName $config.AdapterName -Confirm:$false
            $report.RestoreSucceeded = $true
        }
    }

    if ($config.Mode -eq 'drill') {
        $report.ConnectivityRestored = Test-DrillHealth -Config $config
    }
    else {
        Import-Module $config.ModulePath -Force
        $verificationDeadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not $report.ConnectivityRestored -and [DateTime]::UtcNow -lt $verificationDeadline) {
            $report.ConnectivityRestored = Test-InternetConnectivity -Endpoints @($config.Endpoints)
            if (-not $report.ConnectivityRestored) { Start-Sleep -Seconds 1 }
        }
    }

    if (-not $report.ConnectivityRestored) {
        $report.Outcome = 'restore_failed_connectivity_check'
        throw 'Connectivity verification failed after the restore attempt.'
    }
    if ($report.RestoreAttempted) {
        $report.Outcome = 'restored_after_timeout'
    }
    else {
        $report.Outcome = 'healthy_no_restore_needed'
    }
}
catch {
    if ($report.Outcome -eq 'running') { $report.Outcome = 'watchdog_error' }
    $report.Error = $_.Exception.ToString()
    "$(Get-Date -Format o) ERROR $($report.Error)" | Add-Content -LiteralPath $logPath -Encoding UTF8
}
finally {
    $report.FinishedAtUtc = [DateTime]::UtcNow.ToString('o')
    Write-WatchdogJson -Value ([pscustomobject] $report) -Path $reportPath
}

if ($report.Outcome -in @('watchdog_error', 'restore_failed_connectivity_check')) { exit 1 }
exit 0
