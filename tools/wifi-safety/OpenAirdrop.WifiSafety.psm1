Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-IsAdministrator {
    if (-not (Test-IsAdministrator)) {
        throw 'This command requires an elevated PowerShell session. No changes were made.'
    }
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)] [object] $Value,
        [Parameter(Mandatory = $true)] [string] $Path
    )

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $temporaryPath = "$Path.tmp"
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

function Get-WifiAdapterRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $AdapterName)

    $adapter = Get-NetAdapter -Name $AdapterName -IncludeHidden -ErrorAction Stop
    $pnpDeviceId = [string] $adapter.PnPDeviceID
    if ([string]::IsNullOrWhiteSpace($pnpDeviceId)) {
        throw "Adapter '$AdapterName' did not expose a PnP device ID."
    }

    $pnp = Get-PnpDevice -InstanceId $pnpDeviceId -ErrorAction Stop
    $driver = Get-CimInstance -ClassName Win32_PnPSignedDriver |
        Where-Object { $_.DeviceID -eq $pnpDeviceId } |
        Select-Object -First 1
    if ($null -eq $driver) {
        throw "Could not resolve the signed driver for '$AdapterName'."
    }

    $hardwareIds = @()
    $hardwareIdProperty = Get-PnpDeviceProperty -InstanceId $pnpDeviceId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue
    if ($null -ne $hardwareIdProperty -and $null -ne $hardwareIdProperty.Data) {
        $hardwareIds = @($hardwareIdProperty.Data)
    }

    [pscustomobject]@{
        AdapterName        = [string] $adapter.Name
        InterfaceGuid      = [string] $adapter.InterfaceGuid
        InterfaceIndex     = [int] $adapter.ifIndex
        Status             = [string] $adapter.Status
        MacAddress         = [string] $adapter.MacAddress
        LinkSpeed          = [string] $adapter.LinkSpeed
        PnpDeviceId        = $pnpDeviceId
        PnpClass           = [string] $pnp.Class
        FriendlyName       = [string] $pnp.FriendlyName
        Manufacturer       = [string] $pnp.Manufacturer
        HardwareIds        = $hardwareIds
        InfName            = [string] $driver.InfName
        DriverVersion      = [string] $driver.DriverVersion
        DriverDate         = if ($null -ne $driver.DriverDate) { ([datetime] $driver.DriverDate).ToString('o') } else { $null }
        DriverProviderName = [string] $driver.DriverProviderName
        DriverName         = [string] $driver.DriverName
    }
}

function Assert-Mt7925Record {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Record)

    if (-not ([string] $Record.PnpDeviceId).StartsWith('PCI\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing target '$($Record.FriendlyName)': the built-in MT7925 must be a PCI device."
    }

    $identityParts = @([string] $Record.FriendlyName, [string] $Record.AdapterName) + @($Record.HardwareIds)
    $identity = $identityParts -join ' '
    if ($identity -notmatch '(?i)(MediaTek|RZ717).*(MT7925|7925)|(MT7925|7925).*(MediaTek|RZ717)') {
        throw "Refusing target '$($Record.FriendlyName)': it is not identifiable as the built-in MediaTek MT7925/RZ717."
    }
}

function Get-FileHashRecord {
    param(
        [Parameter(Mandatory = $true)] [string] $Root,
        [Parameter(Mandatory = $true)] [System.IO.FileInfo] $File
    )

    $rootPath = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
    $relativePath = $File.FullName.Substring($rootPath.Length).TrimStart('\')
    $hash = Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256
    [pscustomobject]@{
        Path   = $relativePath
        Sha256 = $hash.Hash.ToLowerInvariant()
        Length = [int64] $File.Length
    }
}

function Test-WifiSafetyBackup {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $BackupPath)

    $manifestPath = Join-Path $BackupPath 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Backup manifest is missing: $manifestPath"
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.SchemaVersion -ne 1) {
        throw "Unsupported backup schema version '$($manifest.SchemaVersion)'."
    }
    if (-not $manifest.RestorePoint.Created) {
        throw 'The backup is incomplete because no System Restore point was created.'
    }
    if (@($manifest.Files).Count -eq 0) {
        throw 'The backup manifest contains no files.'
    }

    foreach ($entry in @($manifest.Files)) {
        $path = Join-Path $BackupPath ([string] $entry.Path)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Backup file is missing: $($entry.Path)"
        }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne [string] $entry.Sha256) {
            throw "Backup file failed SHA-256 verification: $($entry.Path)"
        }
    }

    return $manifest
}

function New-WifiSafetyBackup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)] [string] $AdapterName,
        [Parameter(Mandatory = $true)] [string] $Destination
    )

    Assert-IsAdministrator
    $record = Get-WifiAdapterRecord -AdapterName $AdapterName
    Assert-Mt7925Record -Record $record

    if (Test-Path -LiteralPath $Destination) {
        if (@(Get-ChildItem -LiteralPath $Destination -Force).Count -gt 0) {
            throw "Backup destination must be empty: $Destination"
        }
    }

    if (-not $PSCmdlet.ShouldProcess($record.FriendlyName, 'Create driver, firmware, settings, and System Restore backup')) {
        return
    }

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $driverPackagePath = Join-Path $Destination 'driver-package'
    $firmwarePath = Join-Path $Destination 'firmware-files'
    $driverBinaryPath = Join-Path $Destination 'loaded-driver'
    New-Item -ItemType Directory -Path $driverPackagePath -Force | Out-Null
    New-Item -ItemType Directory -Path $firmwarePath -Force | Out-Null
    New-Item -ItemType Directory -Path $driverBinaryPath -Force | Out-Null

    $restorePointDescription = "OpenAirDrop Wi-Fi safety backup $([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
    Checkpoint-Computer -Description $restorePointDescription -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
    $restorePoint = Get-ComputerRestorePoint -ErrorAction Stop |
        Sort-Object -Property SequenceNumber -Descending |
        Select-Object -First 1
    if ($null -eq $restorePoint) {
        throw 'Checkpoint-Computer returned without a discoverable restore point.'
    }

    $pnputilOutput = & pnputil.exe /export-driver $record.InfName $driverPackagePath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "pnputil driver export failed ($LASTEXITCODE): $($pnputilOutput -join [Environment]::NewLine)"
    }
    if (@(Get-ChildItem -LiteralPath $driverPackagePath -Filter '*.inf' -Recurse -File).Count -eq 0) {
        throw 'pnputil reported success, but the exported package contains no INF file.'
    }

    if ($record.DriverName -and (Test-Path -LiteralPath $record.DriverName -PathType Leaf)) {
        Copy-Item -LiteralPath $record.DriverName -Destination $driverBinaryPath -Force
    }

    $firmwareCandidates = Get-ChildItem -LiteralPath $driverPackagePath -Recurse -File |
        Where-Object { $_.Extension -match '(?i)^\.(bin|dat|fw|hex|rom)$' }
    foreach ($candidate in $firmwareCandidates) {
        $targetName = '{0}-{1}' -f ((Get-FileHash -LiteralPath $candidate.FullName -Algorithm SHA256).Hash.Substring(0, 12)), $candidate.Name
        Copy-Item -LiteralPath $candidate.FullName -Destination (Join-Path $firmwarePath $targetName) -Force
    }

    $advancedProperties = @(Get-NetAdapterAdvancedProperty -Name $AdapterName -AllProperties -ErrorAction SilentlyContinue |
        Select-Object DisplayName, DisplayValue, RegistryKeyword, RegistryValue)
    $powerManagement = Get-NetAdapterPowerManagement -Name $AdapterName -ErrorAction SilentlyContinue |
        Select-Object *
    $ipConfiguration = Get-NetIPConfiguration -InterfaceIndex $record.InterfaceIndex -Detailed -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, InterfaceIndex, NetProfile, IPv4Address, IPv6Address, IPv4DefaultGateway, IPv6DefaultGateway, DNSServer

    $settings = [pscustomobject]@{
        CapturedAtUtc     = [DateTime]::UtcNow.ToString('o')
        Adapter           = $record
        AdvancedProperties = $advancedProperties
        PowerManagement   = $powerManagement
        IpConfiguration   = $ipConfiguration
    }
    Write-JsonFile -Value $settings -Path (Join-Path $Destination 'adapter-settings.json')

    $files = @(Get-ChildItem -LiteralPath $Destination -Recurse -File |
        Where-Object { $_.Name -ne 'manifest.json' } |
        ForEach-Object { Get-FileHashRecord -Root $Destination -File $_ })

    $manifest = [pscustomobject]@{
        SchemaVersion = 1
        CreatedAtUtc  = [DateTime]::UtcNow.ToString('o')
        Adapter       = $record
        DriverExport  = [pscustomobject]@{
            InfName = $record.InfName
            Command = "pnputil /export-driver $($record.InfName) <backup>\driver-package"
            Output  = @($pnputilOutput | ForEach-Object { [string] $_ })
        }
        Firmware      = [pscustomobject]@{
            ExportedDriverPackageIsCanonicalCopy = $true
            CandidateFileCount = @($firmwareCandidates).Count
            Note = 'The complete pnputil export is authoritative. Recognizable firmware payloads are duplicated under firmware-files for inspection.'
        }
        RestorePoint  = [pscustomobject]@{
            Created        = $true
            Description    = $restorePoint.Description
            SequenceNumber = $restorePoint.SequenceNumber
            CreationTime   = [string] $restorePoint.CreationTime
        }
        Files = $files
    }
    Write-JsonFile -Value $manifest -Path (Join-Path $Destination 'manifest.json')
    Test-WifiSafetyBackup -BackupPath $Destination | Out-Null
    return $manifest
}

function Restore-WifiSafetyBackup {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)] [string] $BackupPath,
        [Parameter(Mandatory = $true)] [string] $AdapterName
    )

    Assert-IsAdministrator
    $manifest = Test-WifiSafetyBackup -BackupPath $BackupPath
    $currentRecord = Get-WifiAdapterRecord -AdapterName $AdapterName
    Assert-Mt7925Record -Record $currentRecord
    if ([string] $currentRecord.PnpDeviceId -ne [string] $manifest.Adapter.PnpDeviceId) {
        throw 'Refusing restore because the current adapter PnP identity differs from the backup.'
    }

    if (-not $PSCmdlet.ShouldProcess($currentRecord.FriendlyName, 'Restore backed-up driver package and adapter settings')) {
        return
    }

    $infFiles = @(Get-ChildItem -LiteralPath (Join-Path $BackupPath 'driver-package') -Filter '*.inf' -Recurse -File)
    if ($infFiles.Count -eq 0) {
        throw 'No exported INF file is available for restore.'
    }
    foreach ($infFile in $infFiles) {
        $output = & pnputil.exe /add-driver $infFile.FullName /install 2>&1
        $outputText = $output -join [Environment]::NewLine
        $acceptedNoOp = ($LASTEXITCODE -eq 259 -and $outputText -match '(?i)(added successfully|up-to-date on device)')
        if ($LASTEXITCODE -ne 0 -and -not $acceptedNoOp) {
            throw "pnputil restore failed for '$($infFile.Name)' ($LASTEXITCODE): $($output -join [Environment]::NewLine)"
        }
    }

    Enable-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction Stop
    $settingsPath = Join-Path $BackupPath 'adapter-settings.json'
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    foreach ($property in @($settings.AdvancedProperties)) {
        if ($property.RegistryKeyword -and $null -ne $property.RegistryValue) {
            $writableProperty = Get-NetAdapterAdvancedProperty -Name $AdapterName -RegistryKeyword $property.RegistryKeyword -ErrorAction SilentlyContinue
            if ($null -ne $writableProperty) {
                Set-NetAdapterAdvancedProperty -Name $AdapterName -RegistryKeyword $property.RegistryKeyword -RegistryValue @($property.RegistryValue) -NoRestart -ErrorAction Stop
            }
        }
    }
    Restart-NetAdapter -Name $AdapterName -Confirm:$false -ErrorAction Stop
}

function Test-InternetConnectivity {
    [CmdletBinding()]
    param([string[]] $Endpoints = @('1.1.1.1:443', '8.8.8.8:53'))

    foreach ($endpoint in $Endpoints) {
        $parts = $endpoint.Split(':')
        if ($parts.Count -ne 2) {
            throw "Invalid connectivity endpoint '$endpoint'; expected host:port."
        }
        $result = Test-NetConnection -ComputerName $parts[0] -Port ([int] $parts[1]) -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($result) {
            return $true
        }
    }
    return $false
}

Export-ModuleMember -Function @(
    'Assert-IsAdministrator',
    'Assert-Mt7925Record',
    'Get-WifiAdapterRecord',
    'New-WifiSafetyBackup',
    'Restore-WifiSafetyBackup',
    'Test-InternetConnectivity',
    'Test-IsAdministrator',
    'Test-WifiSafetyBackup',
    'Write-JsonFile'
)
