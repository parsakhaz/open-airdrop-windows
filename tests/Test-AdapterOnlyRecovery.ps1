[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\wifi-safety\OpenAirdrop.WifiSafety.psm1'
Import-Module $modulePath -Force
$module = Get-Module OpenAirdrop.WifiSafety
try {
    & $module {
        # Replace every external dependency in this isolated test process.
        $script:enableCount = 0
        $script:fakeRecord = [pscustomobject]@{
            PnpDeviceId = 'PCI\VEN_14C3&DEV_7925'
            FriendlyName = 'MediaTek MT7925'
            AdapterName = 'Wi-Fi'
            HardwareIds = @('PCI\VEN_14C3&DEV_7925')
            DriverVersion = '5.7.0.5115'
            InfName = 'oem59.inf'
        }
        $script:fakeBackup = [pscustomobject]@{ Adapter = $script:fakeRecord.PSObject.Copy() }
        function script:Assert-IsAdministrator { }
        function script:Test-WifiSafetyBackup { param($BackupPath) return $script:fakeBackup }
        function script:Get-WifiAdapterRecord { param($AdapterName) return $script:fakeRecord }
        function script:Enable-NetAdapter { [CmdletBinding(SupportsShouldProcess=$true)] param($Name) $script:enableCount++ }
        function script:pnputil.exe { throw 'Forbidden driver installation reached by adapter-only recovery.' }
        function script:Restart-NetAdapter { throw 'Forbidden explicit restart reached by adapter-only recovery.' }
        function script:Set-NetAdapterAdvancedProperty { throw 'Forbidden settings write reached by adapter-only recovery.' }

        Restore-WifiSafetyBackup -BackupPath 'fake-only' -AdapterName 'Wi-Fi' -AdapterStateOnly -Confirm:$false
        if ($script:enableCount -ne 1) { throw 'Matching adapter-only recovery must only enable once.' }
        foreach ($field in @('DriverVersion', 'InfName', 'PnpDeviceId')) {
            $original = $script:fakeRecord.$field
            $script:fakeRecord.$field = 'changed'
            $rejected = $false
            try { Restore-WifiSafetyBackup -BackupPath 'fake-only' -AdapterName 'Wi-Fi' -AdapterStateOnly -Confirm:$false }
            catch { $rejected = $true }
            $script:fakeRecord.$field = $original
            if (-not $rejected -or $script:enableCount -ne 1) { throw "Changed $field must be rejected before enable." }
        }
        Write-Output 'PASS: adapter-only recovery enables only the matching adapter; changed driver, INF, and identity are rejected (4 cases).'
    }
}
finally { Remove-Module OpenAirdrop.WifiSafety -Force }
