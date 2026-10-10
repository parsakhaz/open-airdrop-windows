# Live adapter recovery and raw-TX gate - 2026-10-10

## Outcome

The authorized adapter-only watchdog drill restored the real MT7925 and internet
connectivity. No raw action/AWDL frame was submitted, and no AirDrop transfer was
attempted. There is no application UI or runnable AirDrop transfer test yet.

The user subsequently accepted the measured 35.17-second WLAN outage, clarifying
a 10-second tolerance beyond the original 30-second limit. Recovery timing is
therefore not the current blocker. A callable caller-frame TX entry through the
existing signed driver is still missing.

## Exact safety result

See [machine-readable evidence](../evidence/live-adapter-only-drill-20261010.json).

- All seven backup file hashes passed; the PnP identity, INF, and driver version
  matched. The recorded System Restore point still existed.
- Tooling commit `0c432c8` added explicit `AdapterStateOnly` recovery. It enables
  only the matching adapter; it does not run `pnputil`, install a package, rewrite
  advanced settings, or explicitly restart the adapter. Disabling/enabling still
  entails normal OS-managed device transitions; this is not driver-swap coverage.
- Offline validation passed 51 watchdog assertions plus four isolated
  adapter-only recovery cases before the live run.
- The independently scheduled SYSTEM watchdog started at
  `08:01:15.3669407Z`. Its recovery trigger elapsed time was **30.034 seconds**.
- WLAN event 8003 recorded disconnection at `08:01:23.6531141Z`; event 8001
  recorded reconnection at `08:01:58.8270208Z`: **35.1739067 seconds** apart.
- The watchdog finished with verified internet connectivity at
  `08:01:59.5726892Z`, about 35.92 seconds after the disconnect event. Startup-to-
  completion was about 44.21 seconds; these are different intervals.
- Internet ICMP checks received 2/2 replies before, 3/3 immediately after, and
  3/3 during the final check. TCP connectivity was checked by the watchdog.
- The guarded runner returned 2, meaning successful rollback, not preservation
  of the requested disabled state. The drill wrapper correctly treated that as
  success. The temporary task and process were gone at the final check.
- `mtkwecx.sys` remained version 5.7.0.5115 with the same SHA-256 as before.

This proves one adapter-only recovery run, not a universal outage bound or the
ability to recover a kernel hang. The watchdog is created per guarded operation;
it is not left permanently armed after completion.

## Why there was no raw-frame attempt

The [static queue map](mt7925-wificx-queue-map.md) proves ordinary WiFiCx TX reaches
the chip-specific descriptor builder. Its virtual addresses are private kernel
implementation landmarks, not a callable user-mode ABI. No payload-bearing raw
TX command was identified in the recovered `MTKWLAN` dispatch or shipped IHV
control callback. Calling an arbitrary function pointer or mutating the vendor
queue would require additional kernel integration with unresolved ownership and
locking contracts; it is not covered by permission to use an existing signed API.

The station was associated on channel **153** before and after the drill. No AP
configuration, channel, driver package, signing policy, or boot setting changed.
The requested AWDL channels are 6/44/149; associated off-channel transmission is
not established. Merely asking the user to open the iPhone share sheet cannot
test the absent Windows radio path.

Exact requested-frame log: **zero submitted; zero captured; no payload or PCAP**.
Ordinary association and IP ping traffic occurred, but no raw RF capture was
collected, so no frame-by-frame accounting of that ambient traffic is claimed.

## Next gate

Continue recovering/building the native-frame input boundary offline. A
Packet11-style compatibility probe would be a new experimental filter driver,
not an already available signed-driver API; building it does not establish that
WiFiCx accepts its frames. Loading/installing such a probe, changing signing
policy, modifying the vendor client, or replacing/unloading the signed driver
requires a separate concrete approval and recovery assessment. Do not repeat the
adapter interruption merely because a UI or transfer test is requested.
