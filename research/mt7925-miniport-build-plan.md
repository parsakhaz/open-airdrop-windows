# MT7925 native-frame data-path feasibility and build plan

Date: 2026-10-10

## Decision

**GO for static/offline development toward a same-channel, built-in-MT7925 Windows proof of concept. Windows feasibility remains conditional on TX entry and associated RX delivery. Do not install, replace, patch, or load a driver until the hard ask-first gate below.**

The earlier replacement-only verdict was too pessimistic. [`t4t5/omdrop-owl` at `1a952d2`](https://github.com/t4t5/omdrop-owl/tree/1a952d21f798bd045e505a5dc583f940b025177a) reports bidirectional AirDrop on a PCIe MT7925 while its station remains associated. It keeps the AP and AWDL on channel 6, 44, or 149, gives a passive monitor the station MAC, injects complete 802.11 frames, and relies on the associated station context for unicast ACKs. This is implementation evidence for the same chip under Linux; we have not reproduced it on this host or established parity with the Windows firmware build.

Legacy WDI provides a native-MPDU injection model worth comparing. The installed driver instead uses WiFiCx/NetAdapterCx queues; the WiFiCx header's `NdisWdiTxInjectFrameIndication` declaration is system-reserved and does not establish an available call path. Static comparison confirms that the installed MediaTek Windows driver maps internal frame type/subtype into the same MT7925 TX descriptor bits as Linux. The primary research target is therefore the stock client's internal native-frame TX/RX boundary; a replacement miniport remains the fallback. See the detailed [comparison](mt7925-linux-windows-datapath-map.md).

No driver, adapter, registry, signing-policy, or boot-policy change was made during this analysis.

## Evidence from the installed driver

Static inventory of the preserved `mtkwecx.sys` image exposes the following internal names:

- ring ownership: `MT7925InitTxRxRing`, `N6PciInitTxRing`, `N6PciInitRxRing`;
- transmit path: `N6XmitGetTxbufToDmaq`, `XmitSendPacket`, `XmitWriteTxDv1`, `AsicConnac3xXmitWriteTxD`, `MTCxHifPciXmitHardTransmit`, and `NdisCommonHifPciXmitHardTransmit`;
- receive path: `AsicConnac3xPciProcessRxPacket`, `AsicConnac3xPciProcessRxSnifferPacket`, and `N6PlatformIndicateRecvPktToNdis`;
- completion/indication boundary: `N6PlatformIndicateXmitPktToNdis` and `N6PlatformIndicateRecvPktToNdis`.

The [queue map](mt7925-wificx-queue-map.md) recovers the following path, including
the MT7925-specific callback-table assignment. Static class-extension
strings and `WdfVersionBindClass` show that this package is a WiFiCx/NetAdapterCx
client, not a legacy WDI miniport. It nevertheless retains `WdiSendDataProcess`,
extensive `NdisWdi*`/WDI task vocabulary, and a native 802.11 internal path:

```text
WiFiCx/NetAdapterCx packet and fragment queues
  -> EvtTxQueueAdvance -> worker -> processTxAdvance
  -> MTCxHifPci*XmitHardTransmit
  -> descriptor-input context populated from prepared 802.11 frame control
  -> dynamic TXD dispatch through adapter+0x1464f17
  -> MT7925-initialized callback -> Connac3 TXD/TXWI builder
  -> PCIe DMA ring + doorbell
  -> firmware/radio

RX producer / filtering (not fully mapped)
  -> vendor per-port RX lists
  -> EvtRxQueueAdvance -> NetAdapterCx rings
```

`WdiSendDataProcess` has a separate worker family; shared scheduler code does not
prove that WiFiCx calls that legacy processor.

The comparison is exact at the TX descriptor. In installed `mtkwecx.sys`
5.7.0.5115, `AsicConnac3xXmitWriteTxD` is the runtime function
`0x1401d8540-0x1401d9032`. At `0x1401d8af3-0x1401d8b0c` it clears TXWI dword 2
with `0xffffffcf`, then inserts an input byte at `+0x2b` into bits 5:4. At
`0x1401d8b0e-0x1401d8b1d` it clears the low nibble and inserts an input byte at
`+0x2d`. These are precisely Linux
`MT_TXD2_FRAME_TYPE = GENMASK(5, 4)` and
`MT_TXD2_SUB_TYPE = GENMASK(3, 0)`. The Windows builder can therefore express
internally selected management/action/data classification once its packet
context is populated. This does not establish external caller control.
Both WiFiCx hard-transmit helpers populate these descriptor-input offsets from
the prepared frame-control word: type `(FC >> 2) & 3`, subtype `(FC >> 4) & 15`.
That input is a separate stack object from the queue's TX bookkeeping object;
identical numeric offsets in those two structures must not be conflated. Remaining
tasks are to locate acceptable original frame input and recover
WCID/encryption/sequence handling. The chip selector's `0x7925` branch copies the
ops table at `0x14025d2c0` to adapter `+0x1464d7f`; builder member `+0x198` becomes
the exact dispatch field at `+0x1464f17`. The offline verifier checks that chain.

No caller-frame TX handler was identified in the 96 recovered vendor-OID records
or shipped IHV DLL call sites for this image. Its diagnostic sniffer requires
all ports idle. This result is scoped to that recovered ABI; alternate, dynamic,
or internal routes remain open research questions.

## Candidate assessment

| Candidate | What it can prove | Verdict |
|---|---|---|
| Stock private OID / `MTKWLAN` | Existing idle-only sniffer and diagnostics | No caller-frame TX found in recovered ABI |
| Generic Npcap/ndisprot send | Plain Ethernet-style NBL behavior | No-go for AWDL |
| Packet11-style Native-802.11 LWF | Whether the current NativeWiFi/WiFiCx compatibility boundary accepts a complete management NBL while associated | Conditional GO for the smallest guarded TX experiment; not a complete solution |
| Hypothesized client native-frame TX/RX entry | Could reuse stock association, scheduler, TXWI, rings, firmware, and completion | **Primary investigation target; callable boundary unproven** |
| Modified vendor client driver | Can expose the internal native-frame seam | Lab-only, build-specific, high risk; not a shippable design |
| Sidecar driver sharing BARs/rings | Concurrent hardware ownership | Hard no-go: DMA/reset/interrupt corruption risk |
| Replacement miniport | Full control if firmware and initialization can be implemented | Conditional fallback; multi-month, very high risk |

### What an LWF can and cannot establish

Legacy [Packet11](https://github.com/Felis-Sapiens/packet11/tree/d10579de880df4bdd6fde8cf2af331d556576ec4) is a concrete counterexample to the blanket LWF no-go. It binds to `wlan`, accepts a complete caller-built management frame, requires the station source MAC, attaches `DOT11_EXTSTA_SEND_CONTEXT`, and calls `NdisFSendNetBufferLists`. Its author reported transmission through several stock miniports, including cases that worked only while associated. See its [`createpacket`](https://github.com/Felis-Sapiens/packet11/blob/d10579de880df4bdd6fde8cf2af331d556576ec4/packetio.c#L28-L121) and [send path](https://github.com/Felis-Sapiens/packet11/blob/d10579de880df4bdd6fde8cf2af331d556576ec4/device.c#L424-L493).

That legacy Native-802.11 contract is deprecated, the current MT7925 package is a WiFiCx/NetAdapterCx client, and Packet11 exports no raw RX queue. It is therefore a high-value compatibility experiment, not a demonstrated complete solution. A generic LWF still cannot independently enable firmware sniffer filters or force the vendor TXWI path if the modern stack rejects its metadata.

The association claim comes from the [archived original article](https://web.archive.org/web/20120204035800/http://www.codeproject.com/Articles/28713/802-11-Packet-Injection-for-Windows), which reports unspecified Atheros USB, Intel PCI, and Rosewill adapters. It does not validate the reconstructed source, Windows 11, or MT7925. The transmitter did not require monitor mode; a separate monitor was recommended for RF verification.

Npcap does not test this packet shape: its write path sends a plain NBL with generic frame-type/802.1Q metadata and no `DOT11_EXTSTA_SEND_CONTEXT` or WDI frame metadata. [Raw Wi-Fi injection remains an open Npcap issue](https://github.com/nmap/npcap/issues/85).

### Why ndisprot is insufficient

The Microsoft ndisprot sample registers an NDIS protocol and sends NBLs, but explicitly binds `NdisMedium802_3`. It demonstrates raw **Ethernet** I/O, not raw native-802.11 hardware access. Moving the same idea to a Wi-Fi binding does not bypass the vendor's WDI encapsulation and firmware policy.

### Why a sidecar cannot share the device

Windows PnP assigns the PCIe function, BARs, MSI/MSI-X interrupts, DMA resources, and power transitions to one function driver. A second driver ringing doorbells or editing descriptors cannot synchronize producer/consumer indices, firmware command sequences, resets, D-states, or completion ownership with the MediaTek miniport. Failure modes include silent DMA corruption and bugchecks. The connectivity watchdog cannot recover a kernel hang, boot loop, or corrupted DMA state.

### Why patching is not a product path

An inline hook or modified binary would be build-specific, conflict with code integrity/HVCI and driver signing, and rely on unrecovered locks, object layouts, and firmware invariants. Even a patch that bypassed `IsAllPortIdle` would only enable the existing sniffer path; it would not create raw TX. Treat binary modification solely as a possible disposable-lab experiment, never as the implementation plan.

## Primary PoC architecture: reuse the installed WiFiCx client datapath

Microsoft's [WDI general datapath](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wdi-general-datapath-interfaces) documents the older native-frame contract: 802.11 NBLs cross the OS/vendor boundary, and its [TX encapsulation rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wdi-transmit-operations-and-offloads) leave frame type/subtype, DS bits, and address fields under host control. The WiFiCx form of [`NdisWdiTxInjectFrameIndication`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dot11wificxintf/nc-dot11wificxintf-ndis_wdi_tx_inject_frame_ind) exists but is explicitly system-reserved. It is a comparison landmark, not a supported third-party API or proof that the MediaTek client calls it.

The installed binary confirms the modern model directly: it binds WDF class extensions, embeds the source path `platform\wificx\wificxmain.c`, names `WifiCx` and `NetAdapterCx`, and implements `MTCxDriverNetAdapterStart`, `EvtNetAdapterSetReceiveFilter`, and `EvtNetAdapterReturnRxBuffer`. It also retains `WdiSendDataProcess` and the native descriptor path. The job is to recover this exact client driver's queue/callback boundary rather than assume the older WDI table layout verbatim.

`EvtNetAdapterSetReceiveFilter` programs ordinary packet/multicast filters;
`EvtNetAdapterReturnRxBuffer` identifies buffer lifetime handling. Neither name
establishes monitor mode, native-MPDU delivery, or a tap before RX policy.

The candidate architecture to validate is:

```text
OWL/AWDL userspace
  <-> versioned, bounded raw-frame queue
  <-> WiFiCx-aware kernel integration at the stock client-driver boundary
      TX: complete 802.11 bytes + validated internal metadata
          -> existing client scheduler -> existing MT7925 TXWI/ring
      RX: copy selected native MPDUs before discard/decapsulation
          <- existing MT7925 RX parser/ring

The stock MediaTek miniport retains sole ownership of firmware, PCIe DMA,
interrupts, association, station MAC, channel, ACKs, keys, PM, and reset.
```

The MVP stays on the associated AP channel (6, 44, or 149, subject to local regulatory availability), uses the station MAC, accepts only required AWDL category-127 vendor-specific action and IPv6 data shapes, never accepts caller TXWI/ring/rate/power fields, and copies RX into a bounded lossy queue. AWDL category 127 is not Public Action category 4; standard Public Action tasks alone do not establish AWDL support. Locating the installed driver's WiFiCx queue callbacks, metadata, and ownership rules is the next static task.

## Replacement-miniport architecture

A replacement is the fallback if access to the existing client datapath is blocked. It should use WiFiCx for the Windows Wi-Fi control plane and NetAdapterCx for ordinary data queues, with a private, tightly validated raw-frame sideband below 802.11 encapsulation.

### Required components

1. **PCIe function driver**: PnP/power callbacks, BAR mapping, DMA enablers, interrupt/DPC handling, reset and surprise-removal recovery.
2. **Firmware transport**: firmware loading/verification, MCU command/event queues, capability discovery, calibration/NVRAM, crash collection, and recovery.
3. **MT7925 ring layer**: allocate/map TX/RX descriptor rings, initialize indices, post RX buffers, build TXD/TXWI, ring doorbells, reap completions, and enforce teardown ordering.
4. **Wi-Fi MAC/control**: WiFiCx tasks and properties for scan, connect, authentication, key installation, roaming, regulatory domain, power save, SAR, and virtual ports.
5. **Normal Windows data path**: one NetAdapter per WDI/WiFiCx port, TX/RX queue creation, peer demultiplexing, checksum/offload metadata, cancellation, and backpressure.
6. **Raw RX tap**: copy selected frames immediately after RXD/RXV validation and before vendor-equivalent filtering/decapsulation. Export bounded records containing channel, band, RSSI/rate, timestamp, flags, and 802.11 bytes through a KMDF queue or shared ring.
7. **Raw TX sideband**: accept only versioned, length-checked requests; validate frame type, addresses, channel context, rate/power and regulatory constraints; build the correct MT7925 descriptor; assign a completion cookie; submit through the same serialized ring owner; report ACK/status/timeout.
8. **Channel/concurrency scheduler**: keep raw traffic on the associated channel unless verified firmware support permits MCC. AWDL social-channel operation while the infrastructure BSS is on another channel requires firmware-backed time slicing and is a separate milestone, not an assumption.

The raw path must be inside the sole ring owner. It must never let user mode provide physical addresses, ring indexes, TXWI bytes, rate/power outside allowed bounds, or firmware commands.

## Staged build plan

### R0 - finish the static WiFiCx/native-frame map (3-7 engineer-days, permitted now)

- Recover the exact WiFiCx/NetAdapterCx capability, TX/RX queue, and action-frame callback registrations in `mtkwecx.sys`; use older WDI handler layouts only as comparison evidence.
- Name the installed equivalents of target-descriptor init, data send, injected-frame scheduling, native MPDU retrieval, RX indication, and buffer return.
- Continue from the recovered WiFiCx hard-transmit helpers and MT7925 callback assignment: trace the prepared header back to acceptable original input. Do not assume a `WdiSendDataProcess` edge.
- Map WCID selection, injected/IHV TID handling, encryption exemption, sequence ownership, completion, and every failure cleanup.
- Match the Windows sniffer/monitor firmware payload with Linux `UNI_SNIFFER_ENABLE`/`UNI_SNIFFER_CONFIG`; locate the active-port RX filter and native-MPDU queue.
- Build golden offline vectors for one category-127 AWDL action MPDU and one unencrypted AWDL IPv6 data MPDU. No hardware I/O.
- Exit: every byte and ownership transition from the candidate buffer/metadata to TXWI, and from RXD to copied MPDU, is accounted for on this exact driver hash.

### R1 - offline integration skeleton (3-7 engineer-days, no driver load)

- Build—but do not install or load—a minimal WDK LWF/integration skeleton.
- Define a versioned IOCTL/shared-ring ABI with strict lengths, an AWDL frame allowlist, station-MAC enforcement, queue bounds, cancellation, and completion cookies.
- Port only OWL's packet-I/O boundary into an offline harness; retain its existing frame builder and scheduler.
- Unit/fuzz-test malformed frames, exhaustion, cancellation, and teardown.
- For an external LWF, allocate its own NBL pool, set the filter SourceHandle, and use the documented Native-802.11 send context. Never fabricate WDI-owned MiniportReserved metadata. Specify modern client metadata only after recovering its actual queue contract.
- Exit: the project builds and all packet/metadata transformations pass offline tests without touching an adapter.

### G1 - guarded live TX proof (1-3 engineer-weeks after fresh approval)

This phase installs/loads a driver and must not begin automatically.

1. Try the least-invasive Packet11-shaped LWF send on the associated channel: one inert vendor-action test frame, with no RX/mode change.
2. If the WLAN stack/client rejects it, locate that rejection, stop and report; do not silently move to a modified miniport.
3. Only if static work establishes a valid internal entry and ownership contract, use a separately approved lab plan to expose/test it. Verify that category-127 action and exempt IPv6 MPDUs reach the existing descriptor builder and complete normally.
4. Verify over the air with an independent sniffer; local completion alone is insufficient.

Exit: deterministic bounded same-channel raw TX while ordinary connectivity and association remain healthy.

### G2 - associated raw RX and OWL (3-8 additional engineer-weeks, conditional on TX proof)

- Enable only the Linux-equivalent monitor/filter settings needed to receive AWDL while the station remains active.
- Locate and copy frames at the client's pre-discard native-frame boundary; export channel, RSSI/rate, timestamp/TSF, flags, and 802.11 bytes where available.
- Run OWL discovery, then action/data RX/TX, then an end-to-end AirDrop transfer with the AP pinned to 6/44/149.
- Stress teardown, reconnect, sleep, roam, malformed input, queue pressure, and watchdog recovery.
- Exit: bidirectional same-channel AWDL plus healthy infrastructure traffic with no bugcheck, leak, stuck RX, or manual network repair.

### Fallback - replacement miniport (3-9 engineer-months to lab parity)

Only if the WiFiCx client seam is conclusively blocked, implement firmware boot, calibration, regulatory/SAR, PCIe rings, interrupts, reset, power, WiFiCx control, normal association, and the raw sideband. Production quality, HLK/signing, power/roam coverage, and broad OEM compatibility would take longer.

## Effort and risk

| Work | Estimate | Risk |
|---|---:|---|
| Finish static WiFiCx/TXWI/RX seam map | 3-7 engineer-days | Medium |
| Offline LWF/sideband skeleton and tests | 3-7 engineer-days | Medium |
| First guarded same-channel TX proof | 1-3 engineer-weeks | High |
| Associated RX plus usable OWL/AWDL | 3-8 engineer-weeks after TX proof | High |
| Full replacement miniport fallback | 3-9 engineer-months to lab parity | Very high |
| Production signing/HLK/power/roam hardening | Additional months | High |

These are planning ranges for an experienced specialist, not measured delivery commitments. They assume each preceding gate succeeds; a blocked internal interface can invalidate the weeks-scale route. Principal unknowns are access to the client native-frame boundary, target validation of unknown-peer/category-127 frames, global-vs-station WCID selection, encryption exemption, associated RX filters, and clean teardown. MCC is outside the same-channel MVP.

## Source and license boundary

Current MT7925-specific mt76 descriptor, MCU, and PCIe files are `BSD-3-Clause-Clear`, not blanket GPL-only; Linux commit [`a96fed2`](https://github.com/torvalds/linux/commit/a96fed2825d8dfb068bf640419c619b5f2df4218) records the relicensing. The license permits source/binary reuse with notices and non-endorsement conditions but expressly grants no patent rights. mac80211 and other surrounding Linux code remain GPL-2.0-only. Keep provenance per file, retain MediaTek/author notices, avoid copying GPL-only host-stack code, and obtain legal review before distributing a Windows port.

## Hard safety gate before any live driver action

Stop and obtain explicit user approval before staging/installing/loading a driver, enabling test signing, changing HVCI/Secure Boot, replacing the function driver, disabling the adapter, mapping BARs, or sending hardware/firmware commands. Building an unloaded artifact for review does not itself authorize deployment.

The existing 30-second connectivity watchdog is necessary for benign adapter changes but **not sufficient for a kernel function-driver experiment**. Live work additionally requires:

- a sacrificial target rather than the user's primary machine;
- an independent recovery network/interface;
- host-target kernel debugging;
- recovery media, BitLocker recovery key, and a tested full-disk restore;
- an offline way to remove the test driver and restore the inbox/vendor driver;
- a known-good signed driver package and exact PCI device recovery procedure.

Until those conditions and fresh approval exist, permitted work is static specification, offline parser/encoder tests, user-mode simulations, and unloaded build artifacts for review.

## References

- [Microsoft Windows driver samples](https://github.com/microsoft/Windows-driver-samples)
- [NDIS filter drivers](https://learn.microsoft.com/windows-hardware/drivers/network/ndis-filter-drivers)
- [NDIS protocol drivers](https://learn.microsoft.com/windows-hardware/drivers/network/ndis-protocol-drivers)
- [NetAdapterCx](https://learn.microsoft.com/windows-hardware/drivers/netcx/)
- [WiFiCx Wi-Fi drivers](https://learn.microsoft.com/windows-hardware/drivers/netcx/wifi-wdf-class-extension-wificx)
- [Driver signing during development and test](https://learn.microsoft.com/windows-hardware/drivers/install/driver-signing)
