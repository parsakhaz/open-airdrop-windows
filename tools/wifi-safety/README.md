# Wi-Fi safety gate

This package is mandatory before any experiment changes the built-in MediaTek MT7925 driver, its package files, or its adapter state.

- `New-Backup.ps1` creates a System Restore point, exports the active driver package, preserves the loaded driver and recognizable firmware payloads, captures adapter settings, and hashes every backup file.
- `Restore-Backup.ps1` verifies every hash, refuses a different PnP device, reinstalls the package, restores settings, and restarts the adapter.
- `Invoke-GuardedWifiChange.ps1` runs an operation inside an independent `SYSTEM` scheduled task. It has a fixed 30-second connectivity deadline and restores on timeout or operation failure. Operation scripts must accept an `-AdapterName` parameter.
- `Invoke-ReversibleDrill.ps1` changes a temporary text file and proves that the watchdog restores it after the deadline.

## Safety rules

Never run a live change unless local recovery access exists, the backup verifies, the 30-second reversible drill passes, and a live adapter-disable drill passes. Every later driver or adapter operation must use the guarded runner.

The scripts require explicit acknowledgement switches and refuse non-PCI or non-MT7925 targets.

## Harmless drill

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\wifi-safety\Invoke-ReversibleDrill.ps1
```

The real backup and live drill require elevation. Discover the exact adapter name first with read-only `Get-NetAdapter`.

```powershell
.\tools\wifi-safety\New-Backup.ps1 -AdapterName 'Wi-Fi' -Destination 'C:\OpenAirdropRecovery\mt7925-before-experiments'
```

Run any live operation only through the guarded runner:

```powershell
.\tools\wifi-safety\Invoke-GuardedWifiChange.ps1 `
  -AdapterName 'Wi-Fi' `
  -BackupPath 'C:\OpenAirdropRecovery\mt7925-before-experiments' `
  -OperationScript 'C:\absolute\path\to\operation.ps1' `
  -IUnderstandThisMayInterruptWifi
```

Reports remain under `%ProgramData%\OpenAirdrop\wifi-safety\runs`. If connectivity cannot be proven after restore, stop all experiments and recover locally with the exported package or System Restore.

The runner holds a machine-wide mutex, so a second guarded operation is refused until the first one has finished and removed its scheduled task.
