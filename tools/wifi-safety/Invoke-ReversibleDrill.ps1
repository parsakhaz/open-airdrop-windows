[CmdletBinding()]
param(
    [ValidateRange(1, 30)] [int] $TimeoutSeconds = 30,
    [string] $EvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $EvidenceDirectory = Join-Path $repositoryRoot 'evidence'
}
$drillId = [guid]::NewGuid().ToString('n')
$runDirectory = Join-Path $env:TEMP "open-airdrop-watchdog-drill-$drillId"
$statePath = Join-Path $runDirectory 'harmless-state.txt'
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null

try {
    Set-Content -LiteralPath $statePath -Value 'healthy' -Encoding ASCII
    [pscustomobject]@{
        SchemaVersion = 1
        Mode = 'drill'
        TimeoutSeconds = $TimeoutSeconds
        StatePath = $statePath
        HealthyContent = 'healthy'
        BrokenContent = 'temporarily-broken'
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runDirectory 'watchdog.json') -Encoding UTF8

    $watchdogPath = Join-Path $PSScriptRoot 'Watchdog.ps1'
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $watchdogPath),
        '-RunDirectory', ('"{0}"' -f $runDirectory)
    ) -WindowStyle Hidden -Wait -PassThru
    $stopwatch.Stop()

    $reportPath = Join-Path $runDirectory 'report.json'
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) { throw 'The watchdog process exited without producing a report.' }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $state = (Get-Content -LiteralPath $statePath -Raw).Trim()
    if ($process.ExitCode -ne 0) { throw "The watchdog exited with code $($process.ExitCode)." }
    if ($report.Outcome -ne 'restored_after_timeout') { throw "Unexpected watchdog outcome '$($report.Outcome)'." }
    if (-not $report.RestoreAttempted -or -not $report.RestoreSucceeded -or -not $report.ConnectivityRestored) { throw 'The watchdog report did not prove a successful restore and health verification.' }
    if ($state -ne 'healthy') { throw "The reversible state was not restored; current value is '$state'." }
    if ($stopwatch.Elapsed.TotalSeconds -lt ($TimeoutSeconds - 0.5)) { throw 'The watchdog restored before the configured timeout, so the deadline was not tested.' }

    New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
    $evidencePath = Join-Path $EvidenceDirectory "watchdog-drill-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')).json"
    [pscustomobject]@{
        SchemaVersion = 1
        DrillId = $drillId
        HarmlessAction = "Changed a temporary text file from 'healthy' to 'temporarily-broken'."
        TimeoutSeconds = $TimeoutSeconds
        ElapsedSeconds = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
        FinalState = $state
        WatchdogReport = $report
    } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
    Write-Output $evidencePath
}
finally {
    $expectedPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\open-airdrop-watchdog-drill-'
    $resolvedRunDirectory = [IO.Path]::GetFullPath($runDirectory)
    if ($resolvedRunDirectory.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $runDirectory)) {
        Remove-Item -LiteralPath $runDirectory -Recurse -Force
    }
}
