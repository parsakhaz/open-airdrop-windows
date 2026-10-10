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

# Exercise the actual production supervisor and its fixed 30-second deadline.
# The operation and module below only touch this test's temporary files. They do
# not import the real recovery module, inspect an adapter, or access the network.
$watchdogPath = Join-Path $repositoryRoot 'tools\wifi-safety\Watchdog.ps1'
$testDirectory = Join-Path $env:TEMP ('open-airdrop-worker-tests-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$fakeModulePath = Join-Path $testDirectory 'FakeRecovery.psm1'
$fakeOperationPath = Join-Path $testDirectory 'FakeOperation.ps1'
$fakeChildPath = Join-Path $testDirectory 'FakeChild.ps1'
$fakeMutexOwnerPath = Join-Path $testDirectory 'FakeMutexOwner.ps1'
$testProcesses = @()
$abandonedGuardObserver = $null
@'
function Test-InternetConnectivity {
    param([string[]] $Endpoints)
    $caseDirectory = $Endpoints[0]
    if (Test-Path -LiteralPath (Join-Path $caseDirectory 'restored.signal')) { return $true }
    $behavior = (Get-Content -LiteralPath (Join-Path $caseDirectory 'behavior.txt') -Raw).Trim()
    if ($behavior -eq 'hung-probe') {
        Set-Content -LiteralPath (Join-Path $caseDirectory 'probe.pid') -Value $PID
        while ($true) {
            Set-Content -LiteralPath (Join-Path $caseDirectory 'probe-heartbeat.txt') -Value ([DateTime]::UtcNow.Ticks)
            Start-Sleep -Milliseconds 100
        }
    }
    if ($behavior -eq 'failed-probe') { throw 'Intentional harmless probe error.' }
    return ((Get-Content -LiteralPath (Join-Path $caseDirectory 'state.txt') -Raw).Trim() -eq 'healthy')
}
function Restore-WifiSafetyBackup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string] $BackupPath, [string] $AdapterName, [switch] $AdapterStateOnly)
    if (-not $AdapterStateOnly) { throw 'Offline regression expected explicit adapter-only recovery.' }
    foreach ($pidName in @('operation.pid', 'child.pid', 'probe.pid')) {
        $pidPath = Join-Path $BackupPath $pidName
        if (Test-Path -LiteralPath $pidPath) {
            $workerId = [int](Get-Content -LiteralPath $pidPath -Raw)
            if (Get-Process -Id $workerId -ErrorAction SilentlyContinue) {
                throw "Restore overlapped live worker $pidName ($workerId)."
            }
        }
    }
    Set-Content -LiteralPath (Join-Path $BackupPath 'state.txt') -Value 'healthy'
    Set-Content -LiteralPath (Join-Path $BackupPath 'restored.signal') -Value ([DateTime]::UtcNow.ToString('o'))
}
Export-ModuleMember -Function Test-InternetConnectivity, Restore-WifiSafetyBackup
'@ | Set-Content -LiteralPath $fakeModulePath -Encoding UTF8
@'
param([string] $AdapterName)
$caseDirectory = $AdapterName
Set-Content -LiteralPath (Join-Path $caseDirectory 'operation.pid') -Value $PID
$behavior = (Get-Content -LiteralPath (Join-Path $caseDirectory 'behavior.txt') -Raw).Trim()
if ($behavior -eq 'healthy') {
    Start-Sleep -Seconds 2
    Set-Content -LiteralPath (Join-Path $caseDirectory 'operation-finished.signal') -Value 'done'
    exit 0
}
Set-Content -LiteralPath (Join-Path $caseDirectory 'state.txt') -Value 'broken'
if ($behavior -eq 'hung-operation') {
    $childPath = Join-Path (Split-Path -Parent $caseDirectory) 'FakeChild.ps1'
    $child = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $childPath), '-StateDirectory', ('"{0}"' -f $caseDirectory)
    ) -WindowStyle Hidden -PassThru
    Set-Content -LiteralPath (Join-Path $caseDirectory 'child.pid') -Value $child.Id
    while ($true) { Start-Sleep -Milliseconds 100 }
}
if ($behavior -eq 'failed-operation') { exit 7 }
exit 0
'@ | Set-Content -LiteralPath $fakeOperationPath -Encoding UTF8
@'
param([string] $StateDirectory)
while ($true) {
    Set-Content -LiteralPath (Join-Path $StateDirectory 'state.txt') -Value 'broken-by-child'
    Set-Content -LiteralPath (Join-Path $StateDirectory 'child-heartbeat.txt') -Value ([DateTime]::UtcNow.Ticks)
    Start-Sleep -Milliseconds 100
}
'@ | Set-Content -LiteralPath $fakeChildPath -Encoding UTF8
@'
param([string] $StateDirectory)
$guard = New-Object Threading.Mutex($false, 'Global\OpenAirdrop-WifiSafety-Guard')
if (-not $guard.WaitOne(0)) { throw 'Test guard is already owned.' }
Set-Content -LiteralPath (Join-Path $StateDirectory 'mutex-owner-ready.signal') -Value 'ready'
Start-Sleep -Seconds 90
'@ | Set-Content -LiteralPath $fakeMutexOwnerPath -Encoding UTF8

function New-OfflineWatchdogCase {
    param([string] $Name, [int] $TimeoutSeconds = 30)
    $caseDirectory = Join-Path $testDirectory $Name
    New-Item -ItemType Directory -Path $caseDirectory | Out-Null
    Set-Content -LiteralPath (Join-Path $caseDirectory 'state.txt') -Value 'healthy'
    Set-Content -LiteralPath (Join-Path $caseDirectory 'behavior.txt') -Value $Name
    [pscustomobject]@{
        SchemaVersion = 1
        Mode = 'production'
        TimeoutSeconds = $TimeoutSeconds
        RecoveryMode = 'AdapterStateOnly'
        AdapterName = $caseDirectory
        BackupPath = $caseDirectory
        OperationScript = $fakeOperationPath
        ModulePath = $fakeModulePath
        Endpoints = @($caseDirectory)
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $caseDirectory 'watchdog.json') -Encoding UTF8
    return $caseDirectory
}

function Start-OfflineWatchdogCase {
    param([string] $CaseDirectory)
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $watchdogPath), '-RunDirectory', ('"{0}"' -f $CaseDirectory)
    ) -WindowStyle Hidden -PassThru
    $script:testProcesses += $process
    return $process
}

function Complete-OfflineWatchdogCase {
    param([Diagnostics.Process] $Process, [string] $CaseDirectory)
    if (-not $Process.WaitForExit(45000)) {
        $Process.Kill()
        $null = $Process.WaitForExit(5000)
        throw "Offline watchdog case exceeded 45 seconds: $CaseDirectory"
    }
    $report = Get-Content -LiteralPath (Join-Path $CaseDirectory 'report.json') -Raw | ConvertFrom-Json
    return [pscustomobject]@{ ExitCode = $Process.ExitCode; Report = $report }
}

try {
    $invalidCase = New-OfflineWatchdogCase -Name 'invalid-timeout' -TimeoutSeconds 1
    $invalidResult = Complete-OfflineWatchdogCase -Process (Start-OfflineWatchdogCase -CaseDirectory $invalidCase) -CaseDirectory $invalidCase
    Assert-True ($invalidResult.ExitCode -ne 0) 'Production must reject a shortened deadline'
    Assert-True (-not $invalidResult.Report.RestoreAttempted) 'Invalid config must not run restoration'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $invalidCase 'operation.pid'))) 'Invalid config must not start an operation'

    $mutexOwnerProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $fakeMutexOwnerPath), '-StateDirectory', ('"{0}"' -f $testDirectory)
    ) -WindowStyle Hidden -PassThru
    $testProcesses += $mutexOwnerProcess
    $ownerReadyPath = Join-Path $testDirectory 'mutex-owner-ready.signal'
    $ownerReadyDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $ownerReadyPath) -and [DateTime]::UtcNow -lt $ownerReadyDeadline) { Start-Sleep -Milliseconds 100 }
    Assert-True (Test-Path -LiteralPath $ownerReadyPath) 'Harmless test process must hold the guard before abandonment'
    # Keep an observer handle open so the named object survives its owner's exit.
    $abandonedGuardObserver = [Threading.Mutex]::OpenExisting('Global\OpenAirdrop-WifiSafety-Guard')
    $mutexOwnerProcess.Kill()
    Assert-True ($mutexOwnerProcess.WaitForExit(5000)) 'Harmless mutex owner must exit'
    $abandonedCase = New-OfflineWatchdogCase -Name 'abandoned-mutex'
    $abandonedResult = Complete-OfflineWatchdogCase -Process (Start-OfflineWatchdogCase -CaseDirectory $abandonedCase) -CaseDirectory $abandonedCase
    Assert-True ($abandonedResult.ExitCode -ne 0) 'Abandoned guard must fail closed'
    Assert-True ($abandonedResult.Report.Error -match 'abandoned its guard') 'Abandoned guard must explain recovery requirement'
    Assert-True (-not $abandonedResult.Report.RestoreAttempted) 'Abandoned guard must not assume permission to restore'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $abandonedCase 'operation.pid'))) 'Abandoned guard must refuse a new operation'
    $abandonedGuardObserver.Dispose()
    $abandonedGuardObserver = $null

    $hungCase = New-OfflineWatchdogCase -Name 'hung-operation'
    $hungProcess = Start-OfflineWatchdogCase -CaseDirectory $hungCase
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath (Join-Path $hungCase 'child-heartbeat.txt')) -and [DateTime]::UtcNow -lt $readyDeadline) { Start-Sleep -Milliseconds 100 }
    Assert-True (Test-Path -LiteralPath (Join-Path $hungCase 'child-heartbeat.txt')) 'Hung operation must actually start its descendant'
    $contenderCase = New-OfflineWatchdogCase -Name 'mutex-contender'
    $contenderResult = Complete-OfflineWatchdogCase -Process (Start-OfflineWatchdogCase -CaseDirectory $contenderCase) -CaseDirectory $contenderCase
    Assert-True ($contenderResult.ExitCode -ne 0) 'Independent watchdog must refuse concurrent production operation'
    Assert-True (-not $contenderResult.Report.RestoreAttempted) 'Mutex refusal must not restore or interfere with the owner'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $contenderCase 'operation.pid'))) 'Mutex refusal must occur before operation starts'
    $hungResult = Complete-OfflineWatchdogCase -Process $hungProcess -CaseDirectory $hungCase
    Assert-True ($hungResult.ExitCode -eq 0) "Hung operation should restore successfully: $($hungResult.Report.Error)"
    Assert-True ($hungResult.Report.RecoveryMode -eq 'AdapterStateOnly') 'Recovery mode must be explicit and recorded'
    Assert-True $hungResult.Report.OperationCancelled 'Hung operation must be cancelled'
    Assert-True $hungResult.Report.WorkersStoppedBeforeRestore 'All operation descendants must exit before restoration'
    Assert-True ($hungResult.Report.RecoveryReason -eq 'deadline_expired') 'Hung operation must trigger the actual deadline'
    Assert-True ($hungResult.Report.DeadlineElapsedSeconds -ge 29.5 -and $hungResult.Report.DeadlineElapsedSeconds -lt 33) 'Hung operation must not block the 30-second deadline'
    $childHeartbeat = Get-Content -LiteralPath (Join-Path $hungCase 'child-heartbeat.txt') -Raw
    Start-Sleep -Milliseconds 500
    Assert-True ((Get-Content -LiteralPath (Join-Path $hungCase 'child-heartbeat.txt') -Raw) -eq $childHeartbeat) 'Cancelled descendant must stop writing after restoration'
    Assert-True ((Get-Content -LiteralPath (Join-Path $hungCase 'state.txt') -Raw).Trim() -eq 'healthy') 'Descendant must not corrupt restored state'

    foreach ($behavior in @('hung-probe', 'failed-operation', 'failed-probe', 'healthy')) {
        $caseDirectory = New-OfflineWatchdogCase -Name $behavior
        $caseElapsed = [Diagnostics.Stopwatch]::StartNew()
        $result = Complete-OfflineWatchdogCase -Process (Start-OfflineWatchdogCase -CaseDirectory $caseDirectory) -CaseDirectory $caseDirectory
        Assert-True ($result.ExitCode -eq 0) "$behavior case must finish successfully: $($result.Report.Error)"
        Assert-True $result.Report.ConnectivityRestored "$behavior case must verify healthy final state"
        if ($behavior -eq 'healthy') {
            Assert-True (-not $result.Report.RestoreAttempted) 'Successful operation must not restore'
            Assert-True (Test-Path -LiteralPath (Join-Path $caseDirectory 'operation-finished.signal')) 'Health must not complete before the operation exits'
            Assert-True ($caseElapsed.Elapsed.TotalSeconds -ge 2) 'Healthy initial state must not bypass a running operation'
        }
        else {
            Assert-True $result.Report.RestoreAttempted "$behavior case must attempt restoration"
            Assert-True $result.Report.WorkersStoppedBeforeRestore "$behavior workers must stop before restoration"
        }
        if ($behavior -eq 'hung-probe') {
            Assert-True (Test-Path -LiteralPath (Join-Path $caseDirectory 'probe-heartbeat.txt')) 'Hung connectivity probe must actually run'
            Assert-True ($result.Report.DeadlineElapsedSeconds -ge 29.5 -and $result.Report.DeadlineElapsedSeconds -lt 33) 'Hung probe must not block the 30-second deadline'
            Assert-True ($result.Report.RecoveryReason -eq 'deadline_expired') 'Hung probe must trigger deadline restoration'
        }
        if ($behavior -eq 'failed-operation') {
            Assert-True ($result.Report.OperationExitCode -eq 7) 'Operation failure exit code must be preserved'
            Assert-True ($caseElapsed.Elapsed.TotalSeconds -lt 15) 'Operation failure must restore promptly'
        }
        if ($behavior -eq 'failed-probe') {
            Assert-True ($result.Report.RecoveryReason -eq 'worker_error') 'Probe errors after operation must trigger recovery'
            Assert-True ($caseElapsed.Elapsed.TotalSeconds -lt 15) 'Probe error must restore promptly'
        }
        Write-Output "PASS: offline production case $behavior"
    }
}
finally {
    foreach ($process in $testProcesses) {
        try {
            if (-not $process.HasExited) {
                # These are only the supervisors started above. Closing their
                # job handles kills their own harmless test worker descendants.
                $process.Kill()
                $null = $process.WaitForExit(5000)
            }
        }
        finally { $process.Dispose() }
    }
    if ($null -ne $abandonedGuardObserver) { $abandonedGuardObserver.Dispose() }
    $expectedPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\open-airdrop-worker-tests-'
    $resolvedTestDirectory = [IO.Path]::GetFullPath($testDirectory)
    if ($resolvedTestDirectory.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $testDirectory)) {
        Remove-Item -LiteralPath $testDirectory -Recurse -Force
    }
}

Write-Output "PASS: $passed assertions"
