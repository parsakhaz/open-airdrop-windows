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
`0x22045c` through a separate helper-device path. Current evidence does not connect
those controls to `MTKWLAN`.

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

## Open questions before live use

1. Trace `0x1400d2a90` and `0x1400d1570` into firmware command construction and
   determine whether either control changes channel or operating mode.
2. Trace `N6PciProcessRxIcsPacket`, `MT7925ParserIcsRawData`, `ProcessIcsLog`, and
   `PrintSnifferPcapLog` to identify the RX sink and file format.
3. Find a stock-driver raw 802.11 transmit primitive that preserves association.
   WDI action-frame operations are not arbitrary raw TX, and no such primitive has
   been proved yet.
4. Only after those static safety questions are answered, use a minimal read-only
   device-open/query probe. Any state-changing control remains watchdog-gated.

## Reproduction tools

The scripts beside this note use `pefile` and Capstone and never load a driver:

- `pe_string_xrefs.py` finds RIP-relative ASCII/UTF-16 string references.
- `pe_callsite_scan.py` locates imported call sites and nearby constants/strings.
- `pe_function_disasm.py` disassembles the PE runtime function containing a VA.
