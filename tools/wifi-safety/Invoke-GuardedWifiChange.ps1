[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $AdapterName,
    [Parameter(Mandatory = $true)] [string] $BackupPath,
    [Parameter(Mandatory = $true)] [string] $OperationScript,
    [string[]] $ConnectivityEndpoints = @('1.1.1.1:443', '8.8.8.8:53'),
    [switch] $IUnderstandThisMayInterruptWifi
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IUnderstandThisMayInterruptWifi) {
    throw 'Refusing live Wi-Fi operation. Pass -IUnderstandThisMayInterruptWifi only after arranging local recovery access.'
}

$modulePath = Join-Path $PSScriptRoot 'OpenAirdrop.WifiSafety.psm1'
$watchdogPath = Join-Path $PSScriptRoot 'Watchdog.ps1'
Import-Module $modulePath -Force
Assert-IsAdministrator
$manifest = Test-WifiSafetyBackup -BackupPath $BackupPath
$record = Get-WifiAdapterRecord -AdapterName $AdapterName
Assert-Mt7925Record -Record $record
if ([string] $manifest.Adapter.PnpDeviceId -ne [string] $record.PnpDeviceId) {
    throw 'The backup belongs to a different PnP device. Refusing the operation.'
}
if (-not (Test-InternetConnectivity -Endpoints $ConnectivityEndpoints)) {
    throw 'Baseline connectivity is already unhealthy. Refusing the operation.'
}
if (-not (Test-Path -LiteralPath $OperationScript -PathType Leaf)) {
    throw "Operation script is missing: $OperationScript"
}

$runId = [guid]::NewGuid().ToString('n')
$runDirectory = Join-Path $env:ProgramData "OpenAirdrop\wifi-safety\runs\$runId"
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
$config = [pscustomobject]@{
    SchemaVersion = 1
    Mode = 'production'
    TimeoutSeconds = 30
    AdapterName = $AdapterName
    BackupPath = (Resolve-Path -LiteralPath $BackupPath).Path
    OperationScript = (Resolve-Path -LiteralPath $OperationScript).Path
    ModulePath = (Resolve-Path -LiteralPath $modulePath).Path
    Endpoints = $ConnectivityEndpoints
}
Write-JsonFile -Value $config -Path (Join-Path $runDirectory 'watchdog.json')

$taskName = "OpenAirdrop-WifiSafety-$runId"
$argument = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -RunDirectory "{1}"' -f $watchdogPath, $runDirectory
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argument
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$mutex = New-Object Threading.Mutex($false, 'Global\OpenAirdrop-WifiSafety-Guard')
if (-not $mutex.WaitOne(0)) {
    $mutex.Dispose()
    throw 'Another guarded Wi-Fi operation is already running.'
}

try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $reportPath = Join-Path $runDirectory 'report.json'
    $waitDeadline = (Get-Date).AddMinutes(3)
    while (-not (Test-Path -LiteralPath $reportPath -PathType Leaf) -and (Get-Date) -lt $waitDeadline) {
        Start-Sleep -Milliseconds 500
    }
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        throw "The independent watchdog did not produce a report. Leave the scheduled task in place and inspect: $runDirectory"
    }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $report | ConvertTo-Json -Depth 12
    if (-not $report.ConnectivityRestored) { exit 1 }
}
finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
