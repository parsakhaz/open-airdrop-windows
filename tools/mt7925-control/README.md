# MT7925 private-control probe

`MtkwlanProbe.cs` is a minimal, read-only proof that the stock MediaTek driver
5.7.0.5115 exposes its private vendor-OID tunnel through `\\.\MTKWLAN`.

The probe sends only `IOCTL_NDIS_QUERY_GLOBAL_STATS` (`0x00170002`) with vendor OID
`0xfffcf01c` and initializes the 28-byte `FuncSniffer` payload with opcode 2
(status query). It does not enable capture, change channel, or enter test mode.

Build it with the Windows Framework compiler already present on Windows:

```powershell
.\tools\mt7925-control\Build-Probe.ps1
```

Even read-only live experiments are run through the safety gate during reverse
engineering:

```powershell
$operation = (Resolve-Path .\tools\mt7925-control\operations\Query-SnifferStatus.ps1).Path
.\tools\wifi-safety\Invoke-GuardedWifiChange.ps1 `
  -AdapterName 'Wi-Fi' `
  -BackupPath 'C:\OpenAirdropRecovery\mt7925-before-experiments-v3' `
  -OperationScript $operation `
  -IUnderstandThisMayInterruptWifi
```

The probe result is written to
`%ProgramData%\OpenAirdrop\mt7925-control\sniffer-status-latest.json`.
