# open-airdrop-windows

An open-source Windows app for sending files to and receiving files from iPhones and Macs through AirDrop.

The project is licensed under GPL-3.0. The first implementation milestone is the mandatory [Wi-Fi safety gate](tools/wifi-safety/README.md): verified MT7925 backup/restore tooling and an independent 30-second connectivity watchdog. No radio experiment may bypass it.

## MT7925 research status

The built-in-card route remains under investigation. A Linux MT7925 implementation
reports associated AirDrop, and static analysis matches the Windows TX descriptor
fields to Linux. A working Windows raw-TX/associated-RX entry point is still
unproven. The next milestone is a same-channel prototype, with a hard approval
gate before any live driver change.

- [Linux/Windows evidence and datapath comparison](research/mt7925-linux-windows-datapath-map.md)
- [Recovered WiFiCx queues and TX descriptor dispatch](research/mt7925-wificx-queue-map.md)
- [Build plan, go/no-go gates, effort and risk](research/mt7925-miniport-build-plan.md)
- [Private-control dispatch findings](research/mt7925-private-control.md)

## Tests

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
```

The suite takes roughly 75 seconds: it exercises two real 30-second watchdog
deadlines using temporary-file operations and fake recovery, without touching
the adapter. See the [validation record](evidence/offline-validation-20261010.md).
