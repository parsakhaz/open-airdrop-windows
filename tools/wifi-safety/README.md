# Wi-Fi safety gate

This package is mandatory before any experiment changes the built-in MediaTek MT7925 driver, its package files, or its adapter state.

- `New-Backup.ps1` creates a System Restore point, exports the active driver package, preserves the loaded driver and recognizable firmware payloads, captures adapter settings, and hashes every backup file.
- `Restore-Backup.ps1` verifies every hash, refuses a different PnP device, reinstalls the package, restores settings, and restarts the adapter.
- `Invoke-GuardedWifiChange.ps1` starts an independent `SYSTEM` watchdog task on demand, without a future trigger that could repeat the operation. Operation scripts must accept an `-AdapterName` parameter.
- `Invoke-ReversibleDrill.ps1` changes a temporary text file and proves that the watchdog restores it after the deadline.

The production supervisor runs the operation and connectivity probes in separate
Windows job objects. It starts workers suspended, assigns each to its job, then
resumes it. On deadline/failure it terminates and waits for the workers and their
descendants before restoration. It accepts healthy success only after the whole
operation tree exits. The guarded runner returns `0` for healthy success, `2` for
recovered rollback, and `1` for failed recovery; inspect its full report.

## Safety rules

Never run a live change unless local recovery access exists, the backup verifies, the 30-second reversible drill passes, and a live adapter-disable drill passes. Every later driver or adapter operation must use the guarded runner.

The current user instruction also requires fresh approval before any live driver
load, modification, replacement, or adapter experiment. The tests in this research
pass use temporary files and fake connectivity/recovery functions only; they do
not renew approval or validate a new watchdog build on the physical adapter.

The 30-second deadline is a trigger to stop the experiment and begin recovery,
not a guarantee that connectivity is restored within 30 seconds. Recovery commands
can take longer. No userspace watchdog protects against a kernel hang, bugcheck,
boot failure, or DMA corruption.

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

The independent production watchdog owns a machine-wide mutex, so closing the
runner cannot release the guard while an experiment is active. If the runner
does not receive a final report, it preserves the on-demand task for inspection;
the task has no automatic retrigger. Do not start another experiment until the
watchdog's final state and connectivity are understood.
