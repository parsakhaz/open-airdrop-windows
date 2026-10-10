# open-airdrop-windows

An open-source Windows app for sending files to and receiving files from iPhones and Macs through AirDrop.

The project is licensed under GPL-3.0. The first implementation milestone is the mandatory [Wi-Fi safety gate](tools/wifi-safety/README.md): verified MT7925 backup/restore tooling and an independent 30-second connectivity watchdog. No radio experiment may bypass it.

## Tests

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
```
