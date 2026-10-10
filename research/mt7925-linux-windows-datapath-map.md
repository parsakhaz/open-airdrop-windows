# MT7925 Linux-to-Windows data-path map

Date: 2026-10-10  
Windows target: MediaTek Wi-Fi 7 MT7925 160 MHz PCIe Adapter, driver 5.7.0.5115  
Scope: static analysis and an offline build plan only

## Decision

**Go for static/offline development toward a same-channel MT7925 proof through
the Windows client's internal datapath. Its callable TX entry and associated RX
delivery remain unproven. Do not begin live driver work yet.**

The reason to continue is concrete rather than speculative. On Linux, the same
MT7925 family is already reported to run AirDrop in both directions while its
station remains associated. `omdrop-owl` does this by keeping AWDL on the AP's
channel, injecting complete 802.11 frames through a passive monitor interface,
and using the station MAC. Upstream `mt76` shows the corresponding MT7925 TXWI,
RXD, sniffer, ring, token, and completion paths.

The installed Windows driver contains the same decisive descriptor operation:
its Connac3 TXD builder writes the 802.11 frame type and subtype into bits 5:4 and
3:0 of `txwi[2]`, exactly matching `mt76`. Legacy Microsoft WDI has an internal
lower-edge frame injection primitive and an MPDU receive boundary. The installed
driver instead uses WiFiCx/NetAdapterCx queues, so the legacy model is comparison
evidence, not its recovered ABI. We must establish how a safe input reaches the
stock Windows client's native-frame builder, and whether associated RX can return
AWDL's category-127 vendor-specific action and data frames. Linux establishes a
working chip/firmware combination; Windows firmware parity is not established.

This note does **not** claim that an external LWF has been proven on this modern
MediaTek WiFiCx stack. Packet11 shows that legacy Native 802.11 filters could build
management NBLs in the required shape; Npcap does not build that shape. Neither
result demonstrates that Windows 11's Microsoft WLAN component and this MT7925
driver will accept an LWF-originated management MPDU.

No driver, adapter, registry, signing policy, boot policy, or hardware state was
changed for this analysis.

## Evidence strength

| Finding | Evidence | Confidence |
|---|---|---:|
| MT7925 can inject and receive AWDL while an infrastructure STA remains associated | Public `omdrop-owl` implementation and MT7925 test report | High, but not reproduced on this Windows host |
| Linux uses a native-802.11 TXWI and supports injected frames | Pinned upstream Linux `mt76` source | High |
| Windows WDI has an internal LE-to-regular-datapath injection route | Microsoft DDI documentation and WDI sample | High |
| Installed MediaTek code builds Connac3 `txwi[2]` type/subtype fields with the same masks as `mt76` | Hash-pinned static disassembly | High |
| Installed WiFiCx ordinary TX reaches that builder on the MT7925 initialization branch | Queue calls, prepared-header projection, chip selector, and ops-table copy | High, static |
| The installed client's send path reaches that builder for arbitrary injected management frames | Indirect tables and partial path recovery only | Unknown; first static gate |
| A generic LWF can inject on this Windows 11/MT7925 stack | Historical Packet11 precedent only | Unknown |
| Associated RX exposes off-BSS AWDL management/data MPDUs on Windows | No proof yet | Unknown; first RX gate |
| Cross-channel association plus AWDL works | Neither Linux proof nor Windows evidence | No-go for the first milestone |

## Exact Linux counterexample

The [`omdrop-owl` repository at
`1a952d21`](https://github.com/t4t5/omdrop-owl/tree/1a952d21f798bd045e505a5dc583f940b025177a)
identifies `mt7925e` on a Framework 13 as its first target and reports AirDrop
working in both directions while Wi-Fi stays connected
([README lines 4-10](https://github.com/t4t5/omdrop-owl/blob/1a952d21f798bd045e505a5dc583f940b025177a/README.md#L4-L10)).
This is the important operating recipe, not merely a claim of monitor-mode
support:

1. The infrastructure station remains associated.
2. The AP is on AWDL channel 6, 44, or 149; AWDL stays on that same channel.
3. A monitor VIF on the same PHY uses the station MAC.
4. OWL advertises only intersecting slots on that channel.
5. The card transmits injected frames from the station MAC, and the associated
   station ACKs the phone's unicast frames.
6. OWL presents `awdl0` to the unchanged omdrop sender and receiver.

The project documents that sequence in
[README lines 16-29](https://github.com/t4t5/omdrop-owl/blob/1a952d21f798bd045e505a5dc583f940b025177a/README.md#L16-L29)
and records `mt7925e` as a tested shared-mode profile that injects while
associated in
[`owl-profiles` lines 19-21](https://github.com/t4t5/omdrop-owl/blob/1a952d21f798bd045e505a5dc583f940b025177a/userspace/owl-profiles#L19-L21).
The helper verifies the associated/default-route interface and its frequency,
creates `mon0` on the same PHY, applies the station MAC, disables MT76 runtime
power management for the window, and starts OWL
([association/channel checks](https://github.com/t4t5/omdrop-owl/blob/1a952d21f798bd045e505a5dc583f940b025177a/userspace/omdrop-discoverable#L268-L293),
[monitor setup and launch](https://github.com/t4t5/omdrop-owl/blob/1a952d21f798bd045e505a5dc583f940b025177a/userspace/omdrop-discoverable#L295-L323)).

The evidence has boundaries. The project reports about 490 kB/s send and
1.3 MB/s receive, with injected frames paced at roughly 2.5 ms. It also reports
that deleting the monitor VIF can wedge station RX until a reconnect, so its stop
path deliberately reconnects. Most importantly, its tested mode requires the AP
to be on 6, 44, or 149
([known issues](https://github.com/t4t5/omdrop-owl/blob/1a952d21f798bd045e505a5dc583f940b025177a/README.md#L114-L130)).
That makes it an exact counterexample to "associated raw AWDL is impossible," but
not evidence for Windows or multi-channel concurrency.

## Linux TX map

```text
omdrop sender / AWDL control
  -> OWL constructs radiotap + complete 802.11 action or data frame
  -> pcap_inject(mon0)
  -> mac80211 monitor-injection path strips TX radiotap and marks injection
  -> mt792x/mac80211 TX chooses vif/STA WCID or global WCID
  -> mt7925e_tx_prepare_skb allocates token/PID
  -> mt7925_mac_write_txwi writes native-802.11 TXD/TXWI
  -> HWTXP maps frame buffers and token
  -> WFDMA TX ring / firmware / RF
  -> TX-free or TX-status notification releases token and completes skb
```

OWL's frame construction is explicit. It builds a TX radiotap header, a complete
802.11 management-action or data header, the AWDL payload, and optionally an FCS
([radiotap and 802.11 header construction](https://github.com/jedbillyb/owl/blob/832d70f815c3d4a06a02117bf0fc5e868daa1ff0/src/tx.c#L297-L343),
[complete action/data frames](https://github.com/jedbillyb/owl/blob/832d70f815c3d4a06a02117bf0fc5e868daa1ff0/src/tx.c#L357-L401)).
Its WLAN send routine passes that prepared buffer to `pcap_inject`
([`daemon/io.c` lines 381-390](https://github.com/jedbillyb/owl/blob/832d70f815c3d4a06a02117bf0fc5e868daa1ff0/daemon/io.c#L381-L390)).
There is no MediaTek-private userspace command in this path.

At Linux commit
[`879d754e`](https://github.com/torvalds/linux/tree/879d754e48f6fda26ad06c9d183cd9f7f4f0affd),
the MT7925 driver then provides the hardware-specific proof:

- `mt7925_mac_write_txwi_80211` selects `MT_HDR_FORMAT_802_11`, derives the
  descriptor frame type and subtype from the caller's 802.11 frame control, and
  applies fixed-rate policy
  ([`mac.c` lines 661-706](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/mac.c#L661-L706)).
- For `IEEE80211_TX_CTL_INJECTED`, it preserves the supplied sequence number and
  disables hardware A-MSDU
  ([`mac.c` lines 712-725](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/mac.c#L712-L725)).
- The common TX entry starts with the global WCID and substitutes a VIF/STA WCID
  when one is available
  ([`mt792x_core.c` lines 80-140](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt792x_core.c#L80-L140)).
- The PCIe preparation path falls back to that global WCID, allocates a token and
  packet ID, writes the TXWI, and appends/maps the HWTXP
  ([`pci_mac.c` lines 1-55](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/pci_mac.c#L1-L55)).
- The queue layout has data, MCU, firmware-download, RX-MCU, and RX-data rings;
  initialization allocates queues and enables WFDMA/NAPI
  ([queue layout](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/pci.c#L219-L235),
  [queue and callback initialization](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/pci.c#L282-L352)).
- TX-free notifications clean the DMA queues, parse WCID and MSDU IDs, release
  tokens, record retry/failure state, and complete the skb
  ([`mac.c` lines 1103-1185](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/mac.c#L1103-L1185)).

This is also a useful descriptor oracle for the Windows binary. In the pinned
Connac3 header, `MT_TXD2_FRAME_TYPE` is `GENMASK(5, 4)` and
`MT_TXD2_SUB_TYPE` is `GENMASK(3, 0)`
([`mt76_connac3_mac.h` lines 236-241](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt76_connac3_mac.h#L236-L241)).

## Linux RX and monitor map

```text
RF / firmware
  -> WFDMA RX-data ring
  -> mt7925_queue_rx_skb classifies normal RX vs MCU/TXS/TX-free
  -> mt7925_mac_fill_rx parses RXD/RXV, channel, RSSI, FCS, crypto state
  -> native 802.11 bytes are retained when header translation is off
  -> mt76_rx / mac80211 monitor delivery adds radiotap metadata
  -> pcap capture on mon0
  -> OWL parses AWDL and presents Ethernet/IPv6 on awdl0
  -> unchanged omdrop receiver
```

The RXD parser distinguishes header-translated 802.3 frames from native 802.11,
recovers frame-control/sequence/QoS metadata, records channel/RSSI/FCS state, and
adds HE/EHT radiotap information for native frames
([`mt7925/mac.c` lines 360-615](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/mac.c#L360-L615)).
The RX queue handler separates firmware events, TX status/free notifications,
and normal RX before passing successful normal frames to `mt76_rx`
([`mac.c` lines 1187-1266](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/mac.c#L1187-L1266)).

Monitor configuration is a real firmware path, not merely an upper-layer packet
filter. `CONF_CHANGE_MONITOR` changes RX filters and configures active interfaces
([`main.c` lines 810-856](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/main.c#L810-L856));
the driver sends `UNI_SNIFFER_ENABLE` and `UNI_SNIFFER_CONFIG` TLVs containing
band, width, primary/center channels, SCO, and error-drop policy
([`mcu.c` lines 2174-2272](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/mcu.c#L2174-L2272)).
The MT7925 advertises `WANT_MONITOR_VIF`, matching omdrop's passive monitor VIF
([`mt792x_core.c` lines 723-735](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt792x_core.c#L723-L735)).

## Legacy WDI/TAL comparison, not the installed WiFiCx ABI

The installed image binds WDF class extensions, embeds
`platform\wificx\wificxmain.c`, names `WifiCx` and `NetAdapterCx`, and implements
`EvtAdapterCreateTxQueue`, `EvtTxQueueAdvance`, `EvtAdapterCreateRxQueue`, and
`EvtRxQueueAdvance`. Microsoft's [WiFiCx client model](https://learn.microsoft.com/en-us/windows-hardware/drivers/netcx/writing-a-wificx-client-driver)
uses these queue registrations. Recovering this client's queue and buffer
ownership is required before assuming any legacy WDI handler layout below.

Microsoft describes WDI as a Microsoft WLAN component between the rest of the OS
and the IHV miniport. It maps existing Native WLAN/NDIS interfaces to WDI, while
the data path uses NBLs and new handlers
([WDI IHV component model](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wdi-ihv-component-model)).
Within WDI/TAL, 802.11 frames are NBL chains; `MiniportReserved[0]` points to
`WDI_FRAME_METADATA`, allocated by WDI on TX and by the TAL on RX
([general datapath interfaces](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wdi-general-datapath-interfaces)).

The documented older WDI model to compare against is (the connection to the
MediaTek builder in this image is still an unproven mapping):

```text
internal MediaTek lower edge (LE), associated port context
  -> NdisWdiTxInjectFrameIndication(PortId, PeerId, ExTid, NBL, ...)
  -> Microsoft WDI TxMgr classification/scheduling and WDI_FRAME_METADATA
  -> MiniportWdiTxTalSend / TxDataSend and TxDequeueIndication
  -> MediaTek WdiSendDataProcess (MT7925-gated)
  -> chip ops table
  -> AsicConnac3xXmitWriteTxD
  -> MT7925 TXD/TXWI + HIF/PCIe TX ring
  -> firmware / RF / completion

RF / firmware
  -> MT7925 RX ring and RXD/RXV parser
  -> MediaTek peer/TID NBL queues
  -> MiniportWdiRxGetMpdus
  -> WDI RxMgr / Microsoft WLAN component
  -> Native WLAN consumer or a bounded raw-RX side channel
```

### The WDI injection and RX seams

The legacy WDI callback
[`NdisWdiTxInjectFrameIndication`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dot11wdi/nc-dot11wdi-ndis_wdi_tx_inject_frame_ind)
explicitly allows the **lower edge** to inject frames through the regular data
path, with authentication/association frames and Wi-Fi Direct action frames as
examples. Its inputs include the WDI data-path handle, port, peer, extended TID,
NBL chain, unicast and legacy-rate flags, EtherType, and encryption exemption.
It appears in the WDI-provided `NDIS_WDI_DATA_API`
([structure definition](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dot11wdi/ns-dot11wdi-_ndis_wdi_data_api)).

This is not a public user-mode or ordinary LWF API. The handle and port/peer state
are owned inside the IHV miniport/WDI relationship. A useful implementation must
therefore either find an existing MediaTek caller or add a tightly bounded call
at that internal layer; an external component cannot invent a valid data-path
handle or peer lifecycle. Furthermore, the [WiFiCx declaration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dot11wificxintf/nc-dot11wificxintf-ndis_wdi_tx_inject_frame_ind)
is explicitly reserved for system use. Its existence does not prove this client
registers or calls it. No production design may assume it is a supported extension.

On RX,
[`MiniportWdiRxGetMpdus`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dot11wdi/nc-dot11wdi-miniport_wdi_rx_get_mpdus)
returns NBL chains from the IHV miniport, one MPDU per NBL, and requires each NB's
data offset to start at the 802.11 MAC header. That is a useful older model for
locating the equivalent native-frame stage in WiFiCx, not a recovered callback in
this client. The Microsoft RX model says
the target-specific RxEngine interprets RX descriptors and manages DMA buffers,
while RxMgr performs remaining discard/reorder/reassembly work
([WDI RX path](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wdi-rx-path)).

The pinned Microsoft WDI sample makes both boundaries concrete. It registers
`TxDataSend`, `TxTalSend`, and `RxGetMpdus` handlers
([sample lines 1840-1881](https://github.com/microsoft/Windows-driver-samples/blob/2dc3fd3a0cc84a2933f2194e7ec0871584979071/network/wlan/WDI/PLATFORM/NDIS6/SDIO/N6Sdio_WdiMain.c#L1840-L1881)).
Its normal data-send path reads `DOT11_EXTSTA_SEND_CONTEXT` from
`MediaSpecificInformation`, labels the buffer as 802.11, inspects the actual
frame bytes, and sends them to the NIC
([sample lines 1951-2131](https://github.com/microsoft/Windows-driver-samples/blob/2dc3fd3a0cc84a2933f2194e7ec0871584979071/network/wlan/WDI/PLATFORM/NDIS6/SDIO/N6Sdio_WdiMain.c#L1951-L2131)).
Its `TxTalSend` comment calls that handler the interface for frames injected by
the LE through the data path
([sample lines 2291-2324](https://github.com/microsoft/Windows-driver-samples/blob/2dc3fd3a0cc84a2933f2194e7ec0871584979071/network/wlan/WDI/PLATFORM/NDIS6/SDIO/N6Sdio_WdiMain.c#L2291-L2324)),
and its `RxGetMpdus` returns queued peer NBLs
([sample lines 2544-2635](https://github.com/microsoft/Windows-driver-samples/blob/2dc3fd3a0cc84a2933f2194e7ec0871584979071/network/wlan/WDI/PLATFORM/NDIS6/SDIO/N6Sdio_WdiMain.c#L2544-L2635)).
This sample proves the legacy contract, not the installed MediaTek architecture
or policy.

### Installed MediaTek TXD evidence

The evidence below applies only to the preserved `mtkwecx.sys` 5.7.0.5115 image:

```text
SHA-256 6232DBFD53C2E9824EB4D193980F7DB378B88DD155CB8D4E64AB56696E057161
image base 0x140000000
```

The installed INF declares `IF_TYPE_IEEE80211`, `NdisMediumNative802_11`, and
`NdisPhysicalMediumNative802_11`, with `LowerRange="ethernet,wlan"`. Static
initialization identifies NDIS 6.89. The earlier
[private-control audit](mt7925-private-control.md) identified no caller-frame TX
handler in the recovered OID table/IHV call sites. Internal datapath integration
is one remaining candidate; alternate/dynamically registered paths are not excluded.

`pe_string_xrefs.py` resolves `AsicConnac3xXmitWriteTxD` to runtime function
`0x1401d8540-0x1401d9032`. The recovered instructions around the `txwi[2]`
write are:

| Address | Recovered operation | Meaning |
|---:|---|---|
| `0x1401d8af3` | load dword `[rbx+8]` | load `txwi[2]` |
| `0x1401d8af8` | AND with `0xffffffcf` | clear bits 5:4 |
| `0x1401d8afe`-`0x1401d8b0c` | load byte `[rdi+0x2b]`, shift by four, masked insert with `0x30` | insert frame type into bits 5:4 |
| `0x1401d8b0e` | AND with `0xfffffff0` | clear bits 3:0 |
| `0x1401d8b14`-`0x1401d8b1d` | load byte `[rdi+0x2d]`, masked insert with `0x0f` | insert frame subtype into bits 3:0 |

Those masks exactly match Linux's Connac3 `MT_TXD2_FRAME_TYPE` and
`MT_TXD2_SUB_TYPE`. The builder structurally encodes internal type/subtype into
Connac3 TXD2. Their provenance, allowed values, and arbitrary management-frame
reachability remain unknown; this is not a callable external injection door.

The builder has two recovered code references: LEA instructions at
`0x1401e38b1` and `0x1401f12b3`, followed by MOV instructions that initialize
ops-table slots `0x14025cff8` and `0x14025d458`. The latter are data addresses,
not call sites. Separately,
`WdiSendDataProcess` occupies `0x1400504c4-0x140050cde` and explicitly includes
chip ID `0x7925` in its gates, but it is separate from the recovered WiFiCx queue
path. Still unknown are:

- where acceptable caller-supplied 802.11 bytes and length enter the live client;
- which policy permits an associated station to submit category-127 frames;
- how port, peer/WCID, own-MAC, sequence, encryption exemption, rate, and channel
  policy are selected for a management action frame.

The subsequent [WiFiCx queue map](mt7925-wificx-queue-map.md) resolves the current
queue-to-hard-transmit-to-dynamic-TXD-dispatch path. It also traces the separate
descriptor-input fields from the prepared frame-control word. The `0x7925` chip
branch copies the initialized ops table from `0x14025d2c0` into adapter
`+0x1464d7f`; member `+0x198` installs `AsicConnac3xXmitWriteTxD` at the dispatch
field `+0x1464f17`. Thus that static call chain is closed. Original raw-input
acceptance and associated RX policy remain unresolved; external injection is
still a research hypothesis, not a working entry.

`verify_mt7925_txd.py` checks the exact image SHA-256, runtime-function bounds,
instruction bytes, and both initializer-to-slot mappings. Its action/data vectors
cover only the six type/subtype bits; they are not complete transmit descriptors.
It opens a regular file only and refuses other driver hashes.

## Packet11 is not Npcap

An earlier categorical statement that an LWF can never originate a Native 802.11
management NBL was too strong. Historical Packet11 is a concrete counterexample,
but it does not prove this modern stack.

At commit
[`d10579de`](https://github.com/Felis-Sapiens/packet11/tree/d10579de880df4bdd6fde8cf2af331d556576ec4),
the reverse-engineered Packet11 code:

- binds as a `wlan` LWF
  ([INF lines 51-73](https://github.com/Felis-Sapiens/packet11/blob/d10579de880df4bdd6fde8cf2af331d556576ec4/packet11.inf#L51-L73));
- accepts only complete 802.11 management frames whose source address equals the
  adapter MAC;
- allocates an NBL containing the caller's exact management bytes;
- attaches a `DOT11_EXTSTA_SEND_CONTEXT` at
  `NET_BUFFER_LIST_INFO(..., MediaSpecificInformation)`
  ([`packetio.c` lines 32-126](https://github.com/Felis-Sapiens/packet11/blob/d10579de880df4bdd6fde8cf2af331d556576ec4/packetio.c#L32-L126));
- waits until it can derive an NBL pool from observed Native 802.11 traffic
  ([`packetio.c` lines 781-792](https://github.com/Felis-Sapiens/packet11/blob/d10579de880df4bdd6fde8cf2af331d556576ec4/packetio.c#L781-L792)); and
- sends the constructed NBL with `NdisFSendNetBufferLists` only on
  `NdisMediumNative802_11`
  ([`device.c` lines 424-494](https://github.com/Felis-Sapiens/packet11/blob/d10579de880df4bdd6fde8cf2af331d556576ec4/device.c#L424-L494)).

The generic NDIS operation is documented: a filter may originate NBLs, set OOB
information with `NET_BUFFER_LIST_INFO`, and send them with
`NdisFSendNetBufferLists`; its `SourceHandle` must equal the filter handle
([Microsoft filter-send contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sending-data-from-a-filter-driver)).
The Native 802.11 context is likewise documented. It carries encryption exemption,
PHY selection, and related attributes in `MediaSpecificInformation`; its header
must use `sizeof(DOT11_EXTSTA_SEND_CONTEXT)`, and `uSendFlags` must be zero
([`DOT11_EXTSTA_SEND_CONTEXT`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/windot11/ns-windot11-dot11_extsta_send_context)).

Packet11 must be treated as architectural evidence, not reusable production code.
It is reverse-engineered and tiny, has no convincing modern validation, hardcodes
a 24-byte context, sets undocumented `uSendFlags=1`, and passes an observed NBL
pool handle as its NBL `SourceHandle` even though the current NDIS contract
requires the filter handle. Its repository also provides no clear reuse license.

Npcap's write path is materially different. At pinned commit
[`41439dd8`](https://github.com/nmap/npcap/tree/41439dd846e91efa055bceff6ebaf1e4c6381c8e):

- `NPF_BufferToMdl` performs Ethernet/VLAN/MDL transformations only; with
  `EtherHeader` false it passes the supplied bytes through
  ([`Write.c` lines 154-285](https://github.com/nmap/npcap/blob/41439dd846e91efa055bceff6ebaf1e4c6381c8e/packetWin7/npf/npf/Write.c#L154-L285)).
- `NPF_Write` allocates a generic NBL, sets IP/frame-type and 802.1Q information,
  taps it locally, and then calls `NdisFSendNetBufferLists`. It does **not** attach
  a send-side `DOT11_EXTSTA_SEND_CONTEXT`
  ([`Write.c` lines 415-605](https://github.com/nmap/npcap/blob/41439dd846e91efa055bceff6ebaf1e4c6381c8e/packetWin7/npf/npf/Write.c#L415-L605)).
- Native 802.11 attach support is conditioned on Network Monitor capability and
  leaves `EtherHeader` false
  ([`Openclos.c` lines 2097-2168](https://github.com/nmap/npcap/blob/41439dd846e91efa055bceff6ebaf1e4c6381c8e/packetWin7/npf/npf/Openclos.c#L2097-L2168)).

Therefore, passing a captured `[radiotap][802.11]` buffer to Npcap is not the
Packet11 experiment: Npcap neither removes TX radiotap nor supplies the Native
802.11 send context. Its local tap also means seeing the packet in a same-host
capture proves only local loop/tap processing, not RF transmission. Npcap issue
[#85](https://github.com/nmap/npcap/issues/85) records exactly that unresolved
injection gap.

The proper conclusion is narrow: a standards-correct LWF proof remains a bounded
experimental gate, but external-LWF acceptance must not be a dependency of the
Windows architecture until it is observed on this exact WiFiCx/MT7925 build.

The [archived original Packet11 article](https://web.archive.org/web/20120204035800/http://www.codeproject.com/Articles/28713/802-11-Packet-Injection-for-Windows)
reports tested Atheros USB, Intel PCI, and Rosewill adapters, without exact model
IDs. Some chipsets required association; others sent while unassociated after
channel selection. A second monitor-mode adapter was for observing transmitted
frames, not a requirement to put the transmitting adapter in monitor mode.

## Other Windows precedents and their limits

TamoSoft documents [arbitrary 802.11 injection](https://www.tamos.com/products/commwifi/wireless-ap-simulation)
and lists the [NETGEAR A9000 as recommended](https://www.tamos.com/download/main/ca)
for Windows 11. Its [technical notes](https://www.tamos.com/products/commwifi/technotes)
identify injection exclusions for several other Wi-Fi 7 USB products, not A9000.
The [mt76 USB port's implementation notes](https://github.com/Network-Weather/mt76-usb-macos/blob/main/docs/MT7925.md)
map A9000 ID `0846:9072` to MT7925. Together these support an MT7925-family Windows
injection precedent. It is USB, not this PCIe card, and TamoSoft's
[manual](https://www.tamos.com/htmlhelp/commwifi/using_the_program.htm) says capture
uses a special driver with normal connectivity unavailable. This is not evidence
for associated injection with stock `mtkwecx.sys`.

Public WDI/WiFiCx action tasks and Wi-Fi Direct vendor IEs demonstrate controlled
management traffic, but do not establish arbitrary AWDL category-127 transmission.
OWL explicitly sets [category 127](https://github.com/jedbillyb/owl/blob/832d70f815c3d4a06a02117bf0fc5e868daa1ff0/src/frame.h#L32-L44),
a vendor-specific action category distinct from Public Action category 4.

## Linux-to-Windows correspondence

| Required function | Linux proof | Windows evidence | Remaining gate |
|---|---|---|---|
| Full 802.11 action/data bytes | OWL builds radiotap + full 802.11; mac80211 delivers native bytes to `mt76` | Legacy WDI and Packet11 establish older native-NBL contracts | Locate raw buffer/length in the installed WiFiCx client |
| Frame type/subtype in TXD | `mt7925_mac_write_txwi_80211` derives both from frame control | WiFiCx hard-TX derives descriptor input from prepared frame control; MT7925 selects Connac3 builder with identical masks | Trace acceptable original input and header rewriting/policy |
| Port/peer identity | mac80211 VIF/STA WCID with global-WCID fallback | Legacy WDI injection requires PortId/PeerId/ExTid; WiFiCx has port/peer queue demultiplexing | Select a valid associated context for category-127 vendor action |
| Own MAC | omdrop uses station MAC; hardware transmits it | MediaTek TXD has own-MAC/WTBL policy; Packet11 also constrained SA to adapter MAC | Prove current station MAC is accepted without rewrite |
| Same-channel scheduling | AP is already on 6/44/149; no channel switch | Existing associated Windows channel is known to miniport | First proof must use current AP channel 6/44/149 |
| Raw RX while associated | passive monitor VIF + sniffer MCU TLVs + native RXD path | Legacy `MiniportWdiRxGetMpdus` is an MPDU boundary; installed client has WiFiCx RX callbacks | Locate native bytes and prove off-BSS AWDL admission while STA is active |
| Completion | mt76 token/PID plus TX-free/TXS paths | WDI transfer/send completion plus vendor HIF completion names | Correlate a proof-frame cookie through completion and over-air capture |

## Go/no-go gates

### Go now: read-only and offline work

1. **R0-TX call graph, recovered:** the [queue map](mt7925-wificx-queue-map.md)
   closes queue-to-dispatch and the MT7925 initializer-to-Connac3 callback edge.
   Keep these assertions in the hash-locked checker while tracing original
   raw-input acceptance. `WdiSendDataProcess` is a separate path.
2. **R0-TX inputs:** identify the object at `rdi`, name offsets `+0x2b/+0x2d`, and
   trace buffer pointer/length, port, WCID, own-MAC, rate, exemption, ACK, and
   sequence inputs.
3. **R0-RX call graph:** recover the installed WiFiCx RX queue/return callbacks
   and the earliest point after RXD/RXV validation where native management/data
   bytes still exist. Use `MiniportWdiRxGetMpdus` as legacy comparison only.
4. **R0-policy:** find the associated-port RX filters and any firmware sniffer or
   promiscuous command corresponding to Linux's `UNI_SNIFFER_*` controls. The
   private idle-only `FuncSniffer` is not assumed to be this WDI data-path state.
5. **Offline descriptor oracle:** add hash-locked extraction tests that assert the
   recovered masks, ops-table targets, and call-graph invariants. Build golden
   native-802.11 TXD vectors from documented facts and the BSD-licensed MT7925
   hardware files; do not copy GPL-only mac80211 implementation code.
6. **Offline proof driver:** prepare, but do not install or load, a minimal LWF
   that constructs a full 802.11 management NBL without radiotap, with its own
   pools, correct `SourceHandle`, zeroed/`sizeof` Native send context,
   `DOT11_EXEMPT_ALWAYS`, and completion telemetry. Do not fabricate
   `MiniportReserved[0]`; WDI owns its TX metadata. This is a bounded acceptance
   test, not the chosen product path.
7. **Internal-client design:** specify a versioned, length-checked sideband that can
   only submit permitted management/action and AWDL data frames on the current
   associated channel. User mode must never supply WDI handles, TXWI bytes,
   physical addresses, ring indices, arbitrary firmware commands, or out-of-policy
   rate/power/channel values.

### Hard gate before any live action

Stop and obtain fresh explicit approval before installing/loading the offline LWF,
attaching a kernel debugger, enabling test signing, changing HVCI/Secure Boot,
patching or replacing the MediaTek driver, changing adapter mode, sending a WDI
frame, or issuing firmware/hardware commands.

The existing backup and tested 30-second connectivity watchdog is required, but
it is not sufficient protection for a kernel-driver load, binary hook, DMA error,
bugcheck, or boot loop. A live phase additionally needs a sacrificial target,
independent recovery network, host-target kernel debugging, recovery media and
BitLocker key, an offline driver-removal path, and a second radio for over-air
capture. This document performs none of those actions.

### First live proof, only after approval

The lowest-risk experiment order is:

1. Associate to an AP already on channel 6, 44, or 149.
2. Use the current station MAC, current associated port, no channel change, no
   alternate AWDL MAC, and one inert vendor-specific category-127 action frame.
3. Try the standards-correct external LWF NBL shape first. Record its NDIS
   completion and independently sniff RF. Failure here rejects only the external
   route, not the internal client path.
4. If static work has established a safe internal seam, test one internally
   injected NBL with the same frame under kernel debugging and independent RF
   capture.
5. On first RF success, prove broadcast vendor action, unicast ACK/completion,
   associated RX of the response, then AWDL data. Keep every step on the
   infrastructure channel.

The outcome matrix localizes failure:

| Observation | Conclusion |
|---|---|
| External NBL completes with invalid media/data | External metadata or binding is rejected; trace the rejecting layer before drawing a conclusion about the client |
| Internal submission reaches the client but not its TXD builder | Investigate port/peer/metadata classification and scheduling |
| Builder produces a TXD and completion fails before RF | descriptor, WCID/OMAC, firmware, or rate/policy gate |
| Frame appears over air but no response reaches RX | associated RX filter/peer classification gate |
| Action and data work on the AP channel | same-channel Windows path is viable; begin AWDL integration |
| Only a channel change makes it work | no-go for the association-preserving MVP |

## Explicit unknowns and product boundaries

- The stock Windows driver's external Native 802.11 LWF acceptance is unknown.
- The installed client's valid port/peer context for a broadcast category-127
  action frame is unknown; legacy WDI PortId/PeerId/ExTid fields are only clues.
- The final descriptor-input fields at `+0x2b/+0x2d` come from prepared frame
  control; what externally supplied frame shapes can reach that stage remains
  unknown.
- Firmware handling of a management TXD from the associated station port is
  unknown on Windows even though Linux proves the hardware/firmware family can do
  it through `mt76`.
- Associated Windows RX may filter vendor action, other-BSS, multicast, or AWDL
  data before reaching any client queue we can observe.
- FCS ownership, sequence ownership, ACK policy, encryption exemption, fixed-rate
  selection, and completion semantics need a one-frame proof.
- Linux succeeds by using the station MAC. Alternate AWDL MAC/virtual-port support
  is outside the first milestone.
- Off-channel AWDL/MCC/channel hopping is outside the first milestone and remains
  a no-go until explicit firmware scheduling support is recovered.
- Any binary hook is build-specific and conflicts with signing/HVCI assumptions;
  it may be a disposable lab instrument, not a product architecture.

## Effort and risk

| Milestone | Estimate | Risk |
|---|---:|---:|
| Complete the static WiFiCx-to-TXD and RX call maps | 3-7 engineer-days | Medium |
| Build offline extractors, field vectors, and an unloaded LWF acceptance probe | 3-7 engineer-days | Medium |
| Prepare a recoverable, signed/test-signed sacrificial lab after approval | 3-5 engineer-days | High |
| Obtain one same-channel over-air action TX and associated RX proof | 1-3 engineer-weeks after the static map | High |
| Associated RX plus usable OWL/AWDL, after successful TX proof | 3-8 engineer-weeks | High |
| Version/signing/power/roam/soak/product hardening | 3-6+ additional engineer-months | Very high |
| Replacement miniport if the internal path is blocked | 3-9 engineer-months to limited lab parity; production longer | Very high |

These are specialist planning ranges, conditional on each previous gate working,
not delivery promises. A blocked internal interface can invalidate the weeks-scale
path. The [build plan](mt7925-miniport-build-plan.md) is the canonical sequencing
and risk estimate. Replacement remains a fallback.

## Source-use constraints

At Linux commit `879d754e`, the relevant MT7925 hardware-path files carry
`SPDX-License-Identifier: BSD-3-Clause-Clear`, including
[`mac.c`](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/mac.c#L1),
[`mcu.c`](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/mcu.c#L1),
[`pci.c`](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/pci.c#L1),
[`pci_mac.c`](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt7925/pci_mac.c#L1),
and
[`mt792x_core.c`](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/drivers/net/wireless/mediatek/mt76/mt792x_core.c#L1).
The upstream
[relicense commit](https://github.com/torvalds/linux/commit/a96fed2825d8dfb068bf640419c619b5f2df4218)
and the
[BSD-3-Clause-Clear text](https://github.com/torvalds/linux/blob/879d754e48f6fda26ad06c9d183cd9f7f4f0affd/LICENSES/preferred/BSD-3-Clause-Clear#L15-L31)
permit source/binary redistribution subject to notices and non-endorsement, but
the license expressly grants no patent rights. Linux `net/mac80211` remains
GPL-2.0-only. The BSD hardware descriptors, MCU layouts, and DMA logic are
candidates for a Windows port subject to their notice terms and a dedicated
license review; GPL mac80211 implementation code is outside that reuse set.

OWL/omdrop and Npcap have separate licensing constraints, and Packet11 has no
clear reuse license. Treat them as behavioral and architectural evidence unless
a dedicated license review approves code reuse.
