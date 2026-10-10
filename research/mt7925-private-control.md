# MT7925 private control path (driver 5.7.0.5115)

Date: 2026-10-10  
Target: MediaTek Wi-Fi 7 MT7925 160MHz PCIe Adapter, installed package `oem59.inf`

This note records static reverse engineering only. It does not claim that enabling
the private controls is association-safe, and none of the OIDs below have been sent
to the live adapter. Any live control experiment must run inside the repository's
tested 30-second connectivity auto-restore watchdog.

## Exact binaries

The preserved Driver Store files came from
`mtkwecx.inf_amd64_b75c624f1bf0bf41`.

| File | Bytes | SHA-256 |
|---|---:|---|
| `mtkwecx.sys` | 2,563,696 | `6232DBFD53C2E9824EB4D193980F7DB378B88DD155CB8D4E64AB56696E057161` |
| `mtkihvx.dll` | 605,664 | `D926D6869654EFC1C54EC0FB513CEE60CE94BE64244FB98DB4C7D219C9BA32A8` |
| `mtkwecx.inf` | 260,660 | `458A42C4A46131BD0E6B78FE6171C1423353734DE343048B41E6D23D38D6716A` |

All virtual addresses are for these exact binaries at their preferred image bases.
They are analysis landmarks, not a stable ABI.

## User-mode tunnel

`mtkihvx.dll` opens `\\.\MTKWLAN` using `CreateFileA` with
`GENERIC_READ | GENERIC_WRITE`, no sharing, and `OPEN_EXISTING`. Its four observed
requests use `DeviceIoControl` code `0x170002`, the NDIS control code
`IOCTL_NDIS_QUERY_GLOBAL_STATS`. The input begins with a four-byte OID; the output
buffer is the vendor payload.

| OID | Driver handler | Recovered name / note |
|---|---:|---|
| `0xfffcf13e` | `0x140023650` | `FuncIsGameMode`; one-byte output |
| `0xfffcf022` | `0x140024320` | small status/configuration result |
| `0xfffcf014` | `0x140019ad0` | `FuncCountry`; `0x304`-byte output |
| `0xfffcf017` | `0x14001abf0` | `FuncSar`; SAR-sized output |

The DLL also issues `0x220408`, `0x22040c`, `0x220410`, `0x220414`, `0x220448`, and
`0x22045c` through a separate helper-device path. That path is now resolved: it
enumerates the standard USB hub interface `{f18a0e88-c30c-11d0-8815-00a0c906bed8}`
and USB device interface `{a5dcbf10-6530-11d2-901f-00c04fb951ed}`, opens USB
interface paths, and queries descriptor/topology data. It does not address this
PCIe MT7925. The remaining DLL control `0x410050` is sent to a handle returned by
`BluetoothFindFirstRadio`, after requesting `SeLoadDriverPrivilege`; it belongs to
the Bluetooth radio path rather than `MTKWLAN`. Consequently, every observed DLL
IOCTL outside `0x170002` is unrelated to the PCIe Wi-Fi private control device.

## Kernel device, ACL, and dispatch

The control-device initializer near `0x14007df9c` creates `\Device\MTKWLAN` and
the `\DosDevices\MTKWLAN` symbolic link using KMDF, creates an I/O queue, and calls
`WdfControlFinishInitializing`.

Its embedded SDDL is:

```text
D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GRGW;;;WD)(A;;GR;;;RC)
```

Thus LocalSystem gets generic-all, administrators read/write/execute, Everyone
(`WD`) read/write, and restricted code read. This is static evidence that an
ordinary local process can open the tunnel; an actual open has not been attempted.

The KMDF `MTCxEvtIoDeviceControl` callback is at `0x14007f2b0`. It accepts only
`0x170002`, retrieves a minimum four-byte OID input plus the caller's output buffer,
invokes the internal OID dispatcher at `0x140028c94`, and completes the request.
Other controls are rejected by this queue.

## Vendor OID table

The dispatch table around `0x14024c000` uses 12-byte records containing an OID, a
32-bit image-relative handler value, and a flag.

| OID | Handler | Symbol/log name |
|---|---:|---|
| `0xfffcf01c` | `0x14001b160` | `FuncSniffer` |
| `0xfffcf104` | `0x14001b3d0` | `FuncSetIcs` |

### `FuncSniffer` payload

The in/out payload must be exactly `0x1c` bytes.

| Offset | Size | Meaning observed in handler |
|---:|---:|---|
| `0x00` | 4 | opcode: `0` configure/enable, `1` disable, `2` query |
| `0x05` | 1 | mode selector `0..2`, translated to firmware mode `1..3` |
| `0x08` | 4 | validated value; low byte passed to the lower command |
| `0x0c` | 1 | selector constrained to `0..3` |
| `0x10` | 4 | query result counter/status A |
| `0x14` | 4 | query result counter/status B |
| `0x18` | 4 | query result counter/status C |

Opcode 0 validates support through `0x140027524`, validates the offset-8 value via
`0x1400275d8`, and calls `0x1400d2a90(adapter, 1, mode, value8_low,
selector0c)`. Opcode 1 calls the same lower routine with zeroed settings when the
driver's enabled flag is set. Opcode 2 copies three internal values into the payload.

### `FuncSetIcs` payload

The payload must be exactly `0x50` bytes. The handler reads bytes `0..3`, a qword
at `+4`, a dword at `+0x0c`, and a word at `+0x10`. Its main path accepts byte 0
values 2 or 3. The first word at `+4` selects internal ICS flags (cases 0 through
3), while byte 1 is the enable value. It builds a local `0x54`-byte command and
calls `0x1400d1570`, the likely firmware-facing ICS command routine.

This proves a reachable private capture-control ABI. It does **not** yet prove where
captured frames are delivered, whether monitor RX coexists with an associated
station, or whether ICS data is exposed anywhere except the driver's PCAP/log path.

Further disassembly resolves two important constraints:

- `FuncSniffer` calls `IsAllPortIdle` (`0x140027524`) before enable. It rejects the
  request if any of the driver's five ports is active, so this packet-sniffer path
  cannot preserve a normal associated station.
- The ICS path is separate. Firmware command `0x93` accepts the 0x54-byte command,
  and `nicExtEventPhyIcsRawData` writes timestamped files named
  `\DriverData\MediaTek\ICS\IcsLog_<time>.bin`. Records contain magic
  `0x44d9c99a`, type `0x000d`, a word-count-derived size, and byte-swapped raw PHY
  words. This is proprietary RF/ICS diagnostic data, not a monitor-mode 802.11
  packet stream or PCAP.

Private OIDs `0xfffcf209` and `0xfffcf208` map to `FuncSetTestMode` and
`FuncGetTestMode`. They toggle/query a driver test flag; they do not accept a frame
buffer. Test mode is therefore not an association-preserving raw-TX API.

## Exhaustive vendor-OID audit

`pe_oid_inventory.py` recovers 96 valid 12-byte dispatch records and associates
each handler with RIP-relative log-name strings. The complete table was audited,
including all 19 handlers without a recovered `Func*` name.

The only TX/capture/test-labelled entries are:

| OID | Handler purpose |
|---|---|
| `0xfffcf00a` | TX statistics |
| `0xfffcf018` | TX-hang counter |
| `0xfffcf01c` | idle-only packet sniffer |
| `0xfffcf104` | PHY/ICS logging |
| `0xfffcf208` / `0xfffcf209` | get/set test-mode flag |

Potentially broad-looking entries were also ruled out:

- `0xfffcf01f` (`FuncTRx_Setting`) selects RX spatial streams, forced
  single-ended behavior, and spatial-index controls; its four-byte payload is not
  a transmit frame.
- `0xfffcf108` (`FuncSetReg`) is a large selector-driven register/debug handler.
  Its branches perform fixed register operations; there is no caller-sized frame
  submission.
- unnamed `0xfffcf109` is a 56-byte string-keyed configuration getter/setter for
  values such as `TxopLimit`, `AMSDURx`, and PHY policy settings.
- unnamed `0xfffcf003` and `0xfffcf004` use fixed-size 0x1d0-byte and four-byte
  buffers with fixed firmware command IDs `0x7c` and `0xc5`. Neither accepts a
  variable packet buffer.
- CSI, beamforming, fixed-rate, radio, P2P/GO-channel, MLO, statistics, efuse, SAR,
  and country handlers are configuration or telemetry only.

The WDI strings `WDI_TASK_IHV`, `WDI_IHV_REQUEST`, and `WDI_TLV_IHV_DATA` occur in
generic numeric-ID-to-name diagnostic functions shared by the driver framework.
No corresponding packet-oriented IHV handler is registered, and `mtkihvx.dll`
does not import or invoke a WLAN IHV-control API. Its Wi-Fi operations reduce to
the four observed `MTKWLAN` OID queries.

Together, the exhaustive dispatch audit closes the remaining stock-driver
userspace escape hatch: there is no private OID that accepts an arbitrary 802.11
TX buffer, and the only 802.11 RX sniffer enforces idle ports.

## Guarded live validation

The read-only probe in `tools/mt7925-control` opened `\\.\MTKWLAN` and issued the
opcode-2 sniffer status query under the tested 30-second watchdog. On
2026-10-10T05:34:11Z it returned 28 bytes and status `[0, 0, 0]`. The watchdog
reported `healthy_no_restore_needed`, `ConnectivityRestored=true`, and made no
restore attempt. The checked-in evidence contains no machine secrets.

## Open questions before live use

1. Trace `0x1400d2a90` and `0x1400d1570` into firmware command construction and
   determine whether either control changes channel or operating mode.
2. Trace `N6PciProcessRxIcsPacket`, `MT7925ParserIcsRawData`, `ProcessIcsLog`, and
   `PrintSnifferPcapLog` to identify the RX sink and file format.
3. A stock-driver raw 802.11 transmit primitive that preserves association was not
   found after auditing all 96 vendor OIDs and the WDI/IHV vocabulary. Further work
   must move below this dispatch surface (miniport modification/replacement or a
   firmware/PCIe path), not guess additional `MTKWLAN` controls.
4. Only after those static safety questions are answered, use a minimal read-only
   device-open/query probe. Any state-changing control remains watchdog-gated.

## Reproduction tools

The scripts beside this note use `pefile` and Capstone and never load a driver:

- `pe_string_xrefs.py` finds RIP-relative ASCII/UTF-16 string references.
- `pe_callsite_scan.py` locates imported call sites and nearby constants/strings.
- `pe_function_disasm.py` disassembles the PE runtime function containing a VA.
