# MT7925 miniport data-path feasibility and build plan

Date: 2026-10-09

## Decision

**Go for continued clean-room, read-only research; no-go for an in-place filter, protocol driver, binary patch, or shared-hardware sidecar. Conditional go for a replacement miniport only as a separately funded hardware-driver project on a sacrificial target.**

The shortest Windows mechanisms (an NDIS lightweight filter or an ndisprot-style protocol) operate on NDIS packets above the MediaTek driver's 802.11 encapsulation and firmware/TX-descriptor boundary. They can originate ordinary network packets, but cannot request an arbitrary 802.11 frame, preserve an arbitrary frame-control/address layout, select an MT7925 TXWI, or receive frames before the vendor driver filters/decapsulates them. The only technically sound built-in-card route is code that owns the MT7925 PCIe function, firmware protocol, DMA rings, and Wi-Fi control plane.

This is a **12-24+ engineer-month** program for a small team with Windows kernel, 802.11, and MediaTek chipset expertise. A useful raw-frame proof may be possible earlier, but maintaining normal association at the same time is the difficult part and cannot be promised until firmware multi-channel/concurrency behavior is understood.

No driver, adapter, registry, signing-policy, or boot-policy change was made during this analysis.

## Evidence from the installed driver

Static inventory of the preserved `mtkwecx.sys` image exposes the following internal names:

- ring ownership: `MT7925InitTxRxRing`, `N6PciInitTxRing`, `N6PciInitRxRing`;
- transmit path: `N6XmitGetTxbufToDmaq`, `XmitSendPacket`, `XmitWriteTxDv1`, `AsicConnac3xXmitWriteTxD`, `MTCxHifPciXmitHardTransmit`, and `NdisCommonHifPciXmitHardTransmit`;
- receive path: `AsicConnac3xPciProcessRxPacket`, `AsicConnac3xPciProcessRxSnifferPacket`, and `N6PlatformIndicateRecvPktToNdis`;
- completion/indication boundary: `N6PlatformIndicateXmitPktToNdis` and `N6PlatformIndicateRecvPktToNdis`.

These names establish a conventional layered path:

```text
Windows NDIS/WDI packet
  -> vendor classification/802.11 encapsulation
  -> MT7925 TXD/TXWI construction
  -> PCIe DMA ring + doorbell
  -> firmware/radio

radio/firmware
  -> PCIe RX ring
  -> RXD/RXV parsing + policy/filtering
  -> 802.11 decapsulation
  -> Windows NDIS/WDI indication
```

The earlier private-control audit found no vendor OID that enters the TXD/TXWI path with caller-provided 802.11 bytes. Its sniffer control requires all ports idle. Thus the missing capability is below NDIS packet injection and inside the vendor-owned data path.

## Candidate assessment

| Candidate | RX while associated | Arbitrary AWDL TX | Preserve normal association | Verdict |
|---|---:|---:|---:|---|
| User-mode packet capture/injection | Decapsulated traffic only | No | Yes | No-go |
| NDIS lightweight filter | NBLs exposed by stock miniport | No; stock miniport still owns 802.11/TXWI | Yes | No-go for raw AWDL; useful only above a future raw path |
| ndisprot-style protocol | Ethernet-style NBLs | No | Yes | No-go |
| Sidecar driver sharing BARs/rings | Theoretically | Theoretically | Unsafe | Hard no-go |
| Patched vendor binary | Potentially | Potentially | Uncertain | Non-shippable/high-risk no-go |
| Replacement miniport | Yes, if implemented below decapsulation | Yes | Possible only with full control/firmware support | Conditional go, major project |

### Why an LWF is insufficient

Microsoft's NDIS LWF sample can modify or originate NBLs through `FilterSendNetBufferLists` / `NdisFSendNetBufferLists` and indicate received NBLs through `FilterReceiveNetBufferLists` / `NdisFIndicateReceiveNetBufferLists`. That does not make it a MAC/PHY injection API. The lower miniport still interprets the NBL under its advertised data-plane contract and constructs the actual 802.11 frame and hardware descriptor. An LWF is valuable later for routing AWDL-derived Ethernet/IP traffic, policy, and telemetry, but it cannot manufacture public-action frames or arbitrary AWDL data frames on this stock miniport.

### Why ndisprot is insufficient

The Microsoft ndisprot sample registers an NDIS protocol and sends NBLs, but explicitly binds `NdisMedium802_3`. It demonstrates raw **Ethernet** I/O, not raw native-802.11 hardware access. Moving the same idea to a Wi-Fi binding does not bypass the vendor's WDI encapsulation and firmware policy.

### Why a sidecar cannot share the device

Windows PnP assigns the PCIe function, BARs, MSI/MSI-X interrupts, DMA resources, and power transitions to one function driver. A second driver ringing doorbells or editing descriptors cannot synchronize producer/consumer indices, firmware command sequences, resets, D-states, or completion ownership with the MediaTek miniport. Failure modes include silent DMA corruption and bugchecks. The connectivity watchdog cannot recover a kernel hang, boot loop, or corrupted DMA state.

### Why patching is not a product path

An inline hook or modified binary would be build-specific, conflict with code integrity/HVCI and driver signing, and rely on unrecovered locks, object layouts, and firmware invariants. Even a patch that bypassed `IsAllPortIdle` would only enable the existing sniffer path; it would not create raw TX. Treat binary modification solely as a possible disposable-lab experiment, never as the implementation plan.

## Replacement-miniport architecture

A replacement should use WiFiCx for the Windows Wi-Fi control plane and NetAdapterCx for ordinary data queues, with a private, tightly validated raw-frame sideband below 802.11 encapsulation.

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

### Phase 0 - clean-room specification (4-8 engineer-weeks)

- Freeze hashes and symbol/string evidence for each vendor build.
- Derive PCI IDs, BAR/register map, interrupt layout, ring count/size, descriptor formats, reset order, and firmware command/event envelopes using static analysis and public chipset-family documentation.
- Compare behavior and structures with upstream Linux `mt76`, recording ideas and facts without copying GPL-2.0-only implementation into this GPL-3.0-only repository. Obtain legal review before any code reuse.
- Produce executable parsers/encoders with golden byte-vector tests; no kernel loading.
- Exit: descriptor and init specifications account for every field needed for one TX and one RX completion.

### Phase 1 - isolated hardware bring-up (3-6 engineer-months)

- Use a sacrificial machine with an independent network interface, kernel debugger, recovery media, BitLocker key, and restorable disk image.
- Build a signed/test-signed KMDF PCIe diagnostic driver that owns the device only on that target.
- Bring up reset, firmware, interrupts, one RX ring, one TX ring, completion, timeout, and deterministic teardown.
- Exit: repeated cold boot/sleep/reset soak tests plus controlled frame RX/TX on a fixed channel without DMA/verifier faults.

### Phase 2 - Windows Wi-Fi function (6-12+ engineer-months)

- Implement WiFiCx control tasks and NetAdapterCx queues.
- Add scan/connect, WPA2/WPA3 keys, association maintenance, roaming, power management, regulatory/SAR behavior, and recovery.
- Exit: stable ordinary Wi-Fi comparable to the stock driver across reboot, sleep, roaming, and stress.

### Phase 3 - AWDL sideband (1-3 engineer-months after stable hardware path)

- Add pre-decapsulation AWDL RX filtering and bounded user-mode delivery.
- Add validated action/data-frame TX through the common TX scheduler.
- First constrain TX to the current associated channel; then measure whether firmware exposes safe MCC/time-slice primitives.
- Exit: bidirectional AWDL frames while infrastructure association remains healthy, with bounded loss/latency and clean recovery.

### Phase 4 - productization (additional 6-12 months)

- Driver Verifier, HLK, fuzzing of the sideband ABI, long power/roam/traffic soak, crash dump triage, signing and update/rollback design.
- Exit: signed releasable package with a documented compatibility matrix and recovery story.

## Effort and risk

| Work | Estimate | Risk |
|---|---:|---|
| Static architecture/specification | 4-8 engineer-weeks | Medium |
| PCIe/firmware/DMA proof | 3-6 engineer-months | Very high |
| Complete Windows Wi-Fi behavior | 6-12+ engineer-months | Very high |
| Raw RX/TX after stable bring-up | 1-3 engineer-months | High |
| Product hardening/signing | 6-12 additional months | High |

Principal unknowns are firmware authentication/loading, undocumented TXD/RXD variants, calibration/regulatory enforcement, association-compatible monitor delivery, and MCC support. A two-to-four-person specialist team should plan for **12-24+ months**, with a material chance that associated cross-channel AWDL is blocked by firmware.

## Hard safety gate before any live driver action

Stop and obtain explicit user approval before building for installation, enabling test signing, changing HVCI/Secure Boot, adding an INF, installing/loading a service, replacing the function driver, disabling the adapter, mapping BARs, or sending hardware/firmware commands.

The existing 30-second connectivity watchdog is necessary for benign adapter changes but **not sufficient for a kernel function-driver experiment**. Live work additionally requires:

- a sacrificial target rather than the user's primary machine;
- an independent recovery network/interface;
- host-target kernel debugging;
- recovery media, BitLocker recovery key, and a tested full-disk restore;
- an offline way to remove the test driver and restore the inbox/vendor driver;
- a known-good signed driver package and exact PCI device recovery procedure.

Until those conditions and fresh approval exist, the next permitted work is static specification, parser/encoder tests, and user-mode simulations only.

## References

- [Microsoft Windows driver samples](https://github.com/microsoft/Windows-driver-samples)
- [NDIS filter drivers](https://learn.microsoft.com/windows-hardware/drivers/network/ndis-filter-drivers)
- [NDIS protocol drivers](https://learn.microsoft.com/windows-hardware/drivers/network/ndis-protocol-drivers)
- [NetAdapterCx](https://learn.microsoft.com/windows-hardware/drivers/netcx/)
- [WiFiCx Wi-Fi drivers](https://learn.microsoft.com/windows-hardware/drivers/netcx/wifi-wdf-class-extension-wificx)
- [Driver signing during development and test](https://learn.microsoft.com/windows-hardware/drivers/install/driver-signing)

