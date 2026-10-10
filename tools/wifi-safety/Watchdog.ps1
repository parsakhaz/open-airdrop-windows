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

function Initialize-WatchdogWorkerType {
    # Assign suspended children to a job before they can execute or spawn a child.
    # Closing this process's job handles also kills descendants if the watchdog dies.
    if ('OpenAirdrop.WatchdogWorker' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
namespace OpenAirdrop {
    public sealed class WatchdogWorker : IDisposable {
        IntPtr job, process;
        public int ProcessId { get; private set; }
        [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
            public long ProcessTime, JobTime;
            public uint Flags;
            public UIntPtr MinWorkingSet, MaxWorkingSet;
            public uint ActiveLimit;
            public UIntPtr Affinity;
            public uint Priority, Scheduling;
        }
        [StructLayout(LayoutKind.Sequential)] struct IoCounters {
            public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
        }
        [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {
            public BasicLimits Basic;
            public IoCounters Io;
            public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }
        [StructLayout(LayoutKind.Sequential)] struct Accounting {
            public long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
            public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct StartupInfo {
            public int Size;
            public string Reserved, Desktop, Title;
            public uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
            public ushort ShowWindow, ReservedSize;
            public IntPtr ReservedData, StandardInput, StandardOutput, StandardError;
        }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {
            public IntPtr Process, Thread;
            public uint ProcessId, ThreadId;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool SetInformationJobObject(IntPtr job, int kind, ref ExtendedLimits info, uint size);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool QueryInformationJobObject(IntPtr job, int kind, out Accounting info, uint size, IntPtr returned);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool CreateProcess(string app, StringBuilder command, IntPtr processAttributes,
            IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment,
            string directory, ref StartupInfo startup, out ProcessInfo info);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        static void Check(bool success) { if (!success) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        public static WatchdogWorker Start(string executable, string encodedCommand) {
            var worker = new WatchdogWorker();
            ProcessInfo info = new ProcessInfo();
            try {
                worker.job = CreateJobObject(IntPtr.Zero, null);
                Check(worker.job != IntPtr.Zero);
                var limits = new ExtendedLimits();
                limits.Basic.Flags = 0x2000; // KILL_ON_JOB_CLOSE; no breakaway.
                Check(SetInformationJobObject(worker.job, 9, ref limits, (uint)Marshal.SizeOf(limits)));
                var startup = new StartupInfo();
                startup.Size = Marshal.SizeOf(startup);
                var command = new StringBuilder("\"" + executable + "\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodedCommand);
                Check(CreateProcess(executable, command, IntPtr.Zero, IntPtr.Zero, false,
                    0x08000004, IntPtr.Zero, null, ref startup, out info)); // NO_WINDOW | SUSPENDED.
                worker.process = info.Process;
                worker.ProcessId = (int)info.ProcessId;
                Check(AssignProcessToJobObject(worker.job, worker.process));
                Check(ResumeThread(info.Thread) != 0xffffffff);
                return worker;
            } catch {
                if (info.Process != IntPtr.Zero) {
                    TerminateProcess(info.Process, 1);
                    WaitForSingleObject(info.Process, 5000);
                }
                worker.Dispose();
                throw;
            } finally {
                if (info.Thread != IntPtr.Zero) CloseHandle(info.Thread);
            }
        }
        public uint ActiveProcesses {
            get {
                Accounting info;
                Check(QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero));
                return info.ActiveProcesses;
            }
        }
        public bool HasExited {
            get {
                uint result = WaitForSingleObject(process, 0);
                if (result == 0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error());
                return result == 0 && ActiveProcesses == 0;
            }
        }
        public int ExitCode {
            get { uint code; Check(GetExitCodeProcess(process, out code)); return unchecked((int)code); }
        }
        public void Stop(int milliseconds) {
            if (job == IntPtr.Zero || ActiveProcesses == 0) return;
            Check(TerminateJobObject(job, 1));
            var elapsed = Stopwatch.StartNew();
            while (ActiveProcesses != 0) {
                if (elapsed.ElapsedMilliseconds >= milliseconds)
                    throw new TimeoutException("Operation/probe processes did not exit; restoration refused to avoid overlap.");
                Thread.Sleep(25);
            }
        }
        public void Dispose() {
            if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; }
            if (process != IntPtr.Zero) { CloseHandle(process); process = IntPtr.Zero; }
        }
    }
}
'@
}

function Start-WatchdogWorker {
    param([ValidateSet('operation', 'probe')] [string] $Kind)
    $quotedConfigPath = (Join-Path $RunDirectory 'watchdog.json').Replace("'", "''")
    $quotedErrorPath = (Join-Path $RunDirectory "$Kind-error.txt").Replace("'", "''")
    $command = @"
`$ErrorActionPreference = 'Stop'
try {
    `$config = Get-Content -LiteralPath '$quotedConfigPath' -Raw | ConvertFrom-Json
"@
    if ($Kind -eq 'operation') {
        $command += @'

    & $config.OperationScript -AdapterName $config.AdapterName
    if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }
    exit 0
'@
    }
    else {
        $command += @'

    Import-Module $config.ModulePath -Force
    if (Test-InternetConnectivity -Endpoints @($config.Endpoints)) { exit 0 }
    exit 1
'@
    }
    $command += @"

} catch {
    `$_ | Out-String | Set-Content -LiteralPath '$quotedErrorPath' -Encoding UTF8
    exit 2
}
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    return [OpenAirdrop.WatchdogWorker]::Start($powershellPath, $encoded)
}

function Stop-WatchdogWorkers {
    # Attempt both cancellations even if one fails. Never restore until both trees
    # are confirmed stopped, including children whose original parent has exited.
    $failures = @()
    foreach ($worker in @($script:operationWorker, $script:probeWorker)) {
        if ($null -ne $worker) {
            try { $worker.Stop(5000) } catch { $failures += $_.Exception.Message }
        }
    }
    if ($failures.Count -gt 0) { throw ($failures -join '; ') }
}

$startedAt = [DateTime]::UtcNow
$reportPath = Join-Path $RunDirectory 'report.json'
$logPath = Join-Path $RunDirectory 'watchdog.log'
$operationWorker = $null
$probeWorker = $null
$mutex = $null
$mutexHeld = $false
$report = [ordered]@{
    SchemaVersion = 1
    StartedAtUtc = $startedAt.ToString('o')
    FinishedAtUtc = $null
    Mode = $null
    RecoveryMode = $null
    OperationExitCode = $null
    OperationCancelled = $false
    WorkersStoppedBeforeRestore = $false
    RecoveryReason = $null
    DeadlineElapsedSeconds = $null
    RestoreStartedAtUtc = $null
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
    if ($config.Mode -notin @('drill', 'production')) { throw "Unknown watchdog mode '$($config.Mode)'." }
    if ($config.Mode -eq 'production') {
        if ([int] $config.TimeoutSeconds -ne 30) { throw 'Production watchdogs must use the fixed 30-second timeout.' }
        if ($config.RecoveryMode -notin @('AdapterStateOnly', 'DriverPackage')) { throw 'Production recovery mode must be explicit: AdapterStateOnly or DriverPackage.' }
        $report.RecoveryMode = [string] $config.RecoveryMode
        if (-not (Test-Path -LiteralPath $config.OperationScript -PathType Leaf)) { throw "Operation script is missing: $($config.OperationScript)" }
        if (-not (Test-Path -LiteralPath $config.ModulePath -PathType Leaf)) { throw "Safety module is missing: $($config.ModulePath)" }
        Initialize-WatchdogWorkerType
        $mutex = New-Object Threading.Mutex($false, 'Global\OpenAirdrop-WifiSafety-Guard')
        try { $mutexHeld = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] {
            $mutexHeld = $true
            throw 'The previous watchdog abandoned its guard. Recover and inspect locally before another operation.'
        }
        if (-not $mutexHeld) { throw 'Another guarded Wi-Fi operation is already running.' }
    }
    "$(Get-Date -Format o) watchdog started in $($config.Mode) mode" | Set-Content -LiteralPath $logPath -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $RunDirectory 'ready.signal') -Value $startedAt.ToString('o') -Encoding ASCII
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $healthy = $false
    if ($config.Mode -eq 'drill') {
        Set-Content -LiteralPath $config.StatePath -Value ([string] $config.BrokenContent) -Encoding ASCII
        $report.OperationExitCode = 0
        while ($elapsed.Elapsed.TotalSeconds -lt [int] $config.TimeoutSeconds) {
            $healthy = Test-DrillHealth -Config $config
            if ($healthy) { break }
            Start-Sleep -Milliseconds 100
        }
    }
    else {
        # Only the supervisor owns the deadline. Neither an operation nor a slow
        # Test-NetConnection can block this loop. Probe only AFTER operation exit
        # so healthy success cannot leave a still-running operation behind.
        try {
            $operationWorker = Start-WatchdogWorker -Kind operation
            while ($elapsed.Elapsed.TotalSeconds -lt 30) {
                if ($operationWorker.HasExited) {
                    $report.OperationExitCode = $operationWorker.ExitCode
                    if ($report.OperationExitCode -ne 0) { $report.RecoveryReason = 'operation_failed'; break }
                    if ($null -eq $probeWorker) { $probeWorker = Start-WatchdogWorker -Kind probe }
                    if ($probeWorker.HasExited) {
                        $probeExitCode = $probeWorker.ExitCode
                        $probeWorker.Dispose()
                        $probeWorker = $null
                        if ($probeExitCode -eq 0) { $healthy = $true; break }
                        if ($probeExitCode -ne 1) { throw "Connectivity probe failed with exit code $probeExitCode." }
                    }
                }
                Start-Sleep -Milliseconds 100
            }
        }
        catch {
            # Start() guarantees a failed launch is killed before it throws.
            # Conservatively restore after a launch attempt or supervision error.
            $report.RecoveryReason = 'worker_error'
            $_ | Out-String | Add-Content -LiteralPath $logPath -Encoding UTF8
        }
        if (-not $healthy) {
            if ($null -eq $report.RecoveryReason) { $report.RecoveryReason = 'deadline_expired' }
            $report.DeadlineElapsedSeconds = [Math]::Round($elapsed.Elapsed.TotalSeconds, 3)
            $report.OperationCancelled = ($null -ne $operationWorker -and -not $operationWorker.HasExited)
        }
        Stop-WatchdogWorkers
        if ($null -ne $operationWorker) {
            $report.OperationExitCode = $operationWorker.ExitCode
            $operationWorker.Dispose()
            $operationWorker = $null
        }
        if ($null -ne $probeWorker) { $probeWorker.Dispose(); $probeWorker = $null }
        $report.WorkersStoppedBeforeRestore = $true
    }

    if (-not $healthy) {
        $report.RestoreAttempted = $true
        $report.RestoreStartedAtUtc = [DateTime]::UtcNow.ToString('o')
        # Persist the trigger before potentially slow restoration. This is not a
        # final report; the guarded runner only reads report.json on completion.
        Write-WatchdogJson -Value ([pscustomobject] $report) -Path (Join-Path $RunDirectory 'recovery-started.json')
        if ($config.Mode -eq 'drill') {
            Set-Content -LiteralPath $config.StatePath -Value ([string] $config.HealthyContent) -Encoding ASCII
            $report.RestoreSucceeded = Test-DrillHealth -Config $config
        }
        else {
            Import-Module $config.ModulePath -Force
            Restore-WifiSafetyBackup -BackupPath $config.BackupPath -AdapterName $config.AdapterName -AdapterStateOnly:($report.RecoveryMode -eq 'AdapterStateOnly') -Confirm:$false
            $report.RestoreSucceeded = $true
        }
    }

    if ($config.Mode -eq 'drill') {
        $report.ConnectivityRestored = Test-DrillHealth -Config $config
    }
    elseif ($healthy) {
        $report.ConnectivityRestored = $true
    }
    else {
        # Post-restore verification also has a bounded probe worker; recovery
        # itself may take longer and cannot recover a hung kernel or driver swap.
        $verificationElapsed = [Diagnostics.Stopwatch]::StartNew()
        while ($verificationElapsed.Elapsed.TotalSeconds -lt 30) {
            if ($null -eq $probeWorker) { $probeWorker = Start-WatchdogWorker -Kind probe }
            if ($probeWorker.HasExited) {
                $probeExitCode = $probeWorker.ExitCode
                $probeWorker.Dispose()
                $probeWorker = $null
                if ($probeExitCode -eq 0) { $report.ConnectivityRestored = $true; break }
                if ($probeExitCode -ne 1) { throw "Post-restore connectivity probe failed with exit code $probeExitCode." }
            }
            Start-Sleep -Milliseconds 100
        }
        Stop-WatchdogWorkers
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
    try { Stop-WatchdogWorkers }
    catch {
        $report.Outcome = 'watchdog_error'
        $report.ConnectivityRestored = $false
        $report.Error = "$($report.Error) Worker cleanup failed: $($_.Exception.Message)"
    }
    foreach ($worker in @($operationWorker, $probeWorker)) { if ($null -ne $worker) { $worker.Dispose() } }
    $report.FinishedAtUtc = [DateTime]::UtcNow.ToString('o')
    Write-WatchdogJson -Value ([pscustomobject] $report) -Path $reportPath
    if ($mutexHeld) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
}

if ($report.Outcome -in @('watchdog_error', 'restore_failed_connectivity_check')) { exit 1 }
exit 0
