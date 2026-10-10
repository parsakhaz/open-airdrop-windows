# MT7925 WiFiCx queue map (read-only static analysis)

## Scope and result

This is a static map of the installed MediaTek image only. No adapter, service,
registry, firmware, or driver state was changed.

```text
file    C:\Windows\System32\DriverStore\FileRepository\
        mtkwecx.inf_amd64_b75c624f1bf0bf41\mtkwecx.sys
version 5.7.0.5115
SHA-256 6232DBFD53C2E9824EB4D193980F7DB378B88DD155CB8D4E64AB56696E057161
base    0x140000000
```

The important conclusion is narrower than “the paths never meet.” The decoded
WiFiCx callbacks implement a NetAdapterCx ring path which constructs MediaTek TX
objects and submits them through `MTCxHifPci*XmitHardTransmit`. Both hard-TX
helpers reach a dynamic TXD-dispatch wrapper, but the selected MT7925 function
pointer has not yet been statically tied to `AsicConnac3xXmitWriteTxD`. There is
**no direct or statically resolved call edge** from the queue callbacks to
`WdiSendDataProcess`, and no direct call to the Connac3 builder.
`WdiSendDataProcess` is reached by a different family of workers. Both paths use
the generic scheduler at `0x14008d62c`, but on different embedded work objects;
that shared primitive is not evidence that their packet pipelines converge.

The WiFiCx path reaches a common TXD-dispatch wrapper. A crucial structure
boundary is now proven: the pooled queue TX object and the short descriptor-input
context passed as the wrapper's third argument are **different objects**. Bytes
`+0x2b` and `+0x2d` in the descriptor-input context are the 802.11 type/subtype
consumed by the Connac3 builder. Both hard-TX helpers derive those fields directly
from the prepared frame-control word immediately before dispatch. Queue TX-object
fields at the same numeric offsets have different, still-provisional meanings.

## Function address map

All bounds come from the PE exception/runtime-function table; names come from
RIP-relative log-string references unless noted otherwise.

| Role | Runtime range / address | Evidence |
|---|---:|---|
| `EvtAdapterCreateTxQueue` | `0x140086920-0x140086f5e` | `EvtAdapterCreateTxQueue` string xrefs within the range |
| `EvtTxQueueAdvance` | `0x140086f60-0x1400871b2` | named string xrefs at `0x140086fe6`, `0x140087099`, `0x1400870f7` |
| `EvtTxQueueCancel` | `0x1400871c0-0x14008744b` | named string xrefs |
| `EvtTxQueueStart` | `0x140087bd0-0x1400883a7` | named string xrefs |
| `EvtTxQueueStop` | `0x1400883b0-0x1400885cd` | named string xref |
| `MTCxTxQueueInitialize` | `0x14008a170-0x14008a8b6` | named string xrefs |
| `processTxAdvance` | `0x14008ac28-0x14008bd47` | named string xrefs |
| TX work scheduler | `0x14008d62c` | 30 decoded direct callers; generic work-object primitive |
| AP/special hard TX | `0x1400885d0-0x140089047` | embedded name `MTCxHifPciApXmitHardTransmit` |
| normal hard TX | `0x140089048-0x14008a16f` | embedded name `MTCxHifPciXmitHardTransmit` |
| `EvtAdapterCreateRxQueue` | `0x14008bd50-0x14008c211` | named string xref at `0x14008bd87` |
| `EvtRxQueueAdvance` | `0x14008c220-0x14008c4d1` | named string xrefs at `0x14008c2b3`, `0x14008c41f`, `0x14008c4a1` |
| `EvtRxQueueCancel` | `0x14008c4e0-0x14008c5e2` | named string xrefs |
| `EvtRxQueueStart` | `0x14008ca20-0x14008caee` | named string xrefs |
| `EvtRxQueueStop` | `0x14008caf0-0x14008cbbe` | named string xrefs |
| `MTRxQueueInitialize` | `0x14008cbc0-0x14008ce44` | embedded name at `0x14008cbec` |
| `WdiSendDataProcess` | `0x1400504c4-0x140050cde` | previously recovered named function |
| `AsicConnac3xXmitWriteTxD` | `0x1401d8540-0x1401d9032` | previously recovered named function |

## TX queue creation and callback registration

`EvtAdapterCreateTxQueue` builds the callback configuration from concrete code
addresses before the guarded NetAdapterCx calls:

```text
0x140086a23 LEA -> 0x140086f60  EvtTxQueueAdvance
0x140086a2e LEA -> 0x140087af0  notification callback
0x140086a39 LEA -> 0x1400871c0  EvtTxQueueCancel
0x140086a44 LEA -> 0x140087bd0  EvtTxQueueStart
0x140086a4f LEA -> 0x1400883b0  EvtTxQueueStop
```

Two adjacent object-lifecycle callbacks are also installed at `0x140087450` and
`0x140087680`; their exact cleanup/destroy ordering was not needed for the data
path result. After registering packet extensions including
`ms_fragment_virtualaddress`, `ms_fragment_logicaladdress`,
`ms_packet_wifiexemptionaction`, and conditionally `ms_packet_gso`, the create
handler makes the direct call:

```text
0x140086e8a -> MTCxTxQueueInitialize (0x14008a170)
```

`MTCxTxQueueInitialize` obtains the typed queue context and ring collection. The
recovered context fields used later are:

| Queue-context offset | Recovered use |
|---:|---|
| `+0x00` | queue handle |
| `+0x08` | adapter/device context |
| `+0x10` | per-port context selected through adapter table `+0x14c0` |
| `+0x20` | queue index/class used to select per-queue work storage |
| `+0x28` | byte obtained at queue start and copied to TX object `+0x2a` |
| `+0x29` | translated queue-start byte, copied to TX object byte `+0x2b`; exact meaning remains provisional |
| `+0x30` | NetAdapterCx ring collection |
| `+0x50` | driver-private per-packet records, stride `0x1c` |

At `EvtTxQueueStart`, `0x140087d6e` calls a guarded framework accessor. Its byte
result is stored at queue context `+0x28` by `0x140087d7e`; a byte-table lookup is
then stored at `+0x29` by `0x140087d8c`. The exact public enum/function name for
that guarded accessor remains unresolved, so this map does not assign a stronger
semantic name to `+0x28`.

## TX advance to hard-transmit

`EvtTxQueueAdvance` does not call `processTxAdvance` inline. It:

1. obtains the typed queue context;
2. reads adapter at `+0x08`, queue byte at `+0x20`, and the ring collection at
   `+0x30`;
3. allocates a small work node with the direct call
   `0x1400870bb -> 0x14009a480`;
4. appends the node under the per-queue spin lock; and
5. schedules the per-queue work object with
   `0x140087192 -> 0x14008d62c`.

Five queue workers make direct calls to `processTxAdvance`:

```text
worker 0x140012000-0x140012247: 0x140012196 -> 0x14008ac28
worker 0x140012250-0x140012497: 0x1400123e6 -> 0x14008ac28
worker 0x1400124a0-0x1400126e7: 0x140012636 -> 0x14008ac28
worker 0x1400126f0-0x140012937: 0x140012886 -> 0x14008ac28
worker 0x140012940-0x140012b87: 0x140012ad6 -> 0x14008ac28
```

`processTxAdvance` consumes the NetAdapterCx packet and fragment rings, allocates
a driver TX object via `0x140035adc`, and calls the leaf copier at
`0x14008b28c -> 0x14008ab8c`. That copier proves this field flow:

```text
0x14008ab96  queue_ctx[0x28] -> tx_object[0x2a]
0x14008ab9c  queue_ctx[0x29] -> tx_object[0x2b]
```

After fragment bookkeeping, the submit branch is:

```text
0x14008b703 -> 0x1400885d0  MTCxHifPciApXmitHardTransmit
0x14008b70a -> 0x140089048  MTCxHifPciXmitHardTransmit
```

The AP/special helper reads TX-object bytes `+0x2d`, `+0x2b`, and `+0x2a` at
`0x1400886e6`, `0x1400886f1`, and `0x1400886f8`, respectively, while building
local policy metadata. The normal helper reads TX-object `+0x2b` at
`0x1400891d8` and `+0x2a` at `0x14008920c`. These accesses do **not** establish
type/subtype semantics for the TX-object offsets.

Both helpers then make a direct call to the same TXD-dispatch wrapper:

```text
0x140088f4f -> 0x1401a2b2c  from MTCxHifPciApXmitHardTransmit
0x140089f69 -> 0x1401a2b2c  from MTCxHifPciXmitHardTransmit
```

The wrapper is the 24-byte leaf at `0x1401a2b2c-0x1401a2b44`:

```text
0x1401a2b2c  load function pointer [adapter+0x1464f17]
0x1401a2b33  test it for null
0x1401a2b38  non-null: tail-jump through CFG dispatch
0x1401a2b3f  null: tail-jump to XmitWriteTxDv1 at 0x1401a2b44
```

This closes the queue-to-TXD-*dispatch* edge. It does not yet close the final
dynamic edge to `AsicConnac3xXmitWriteTxD`: the assignment of
`adapter+0x1464f17` for the MT7925 branch remains to be proved.

## TX object versus descriptor-input context

The TX-object pool initializer `__TxDmaqInit` is
`0x14003884c-0x140038c5f`. It explicitly clears:

```text
0x140038aa7  tx_object[0x2b] = 0
0x140038ab7  tx_object[0x2d] = 0
```

These are TX-object initializers only. They do not initialize the builder's
descriptor-input context. The queue copier overwrites TX-object `+0x2b` but does
not write TX-object `+0x2d`. A separate AP frame path, `XmitApSendPacket`
(`0x1401a1f30-0x1401a24be`), writes TX-object `+0x2d` at `0x1401a2156`, but its
semantic meaning is provisional until all consumers are reconciled.

Both WiFiCx hard-TX helpers independently create a short descriptor-input context
at stack address `[rbp-0x69]` and pass its address in `R8`, the wrapper's third
argument. The special/AP path does this at `0x140088ed8`; the normal path does it
at `0x140089f17`. Immediately beforehand, each helper parses the prepared 802.11
frame-control word at `[rsi]`:

```text
special/AP path
0x140088ed5  load frame control
0x140088ed8  R8 = &context
0x140088edc  shift right 2
0x140088ee3  mask with 3
0x140088ee7  store word [context+0x2b]       # frame type
0x140088eeb  reload frame control
0x140088eee  shift right 4
0x140088ef2  mask with 0x0f
0x140088ef6  store word [context+0x2d]       # frame subtype

normal path
0x140089ef5  load frame control
0x140089f00  shift right 2
0x140089f04  mask with 3
0x140089f08  store word [context+0x2b]       # frame type
0x140089f0c  reload frame control
0x140089f0f  shift right 4
0x140089f13  mask with 0x0f
0x140089f17  R8 = &context
0x140089f1b  store word [context+0x2d]       # frame subtype
```

`AsicConnac3xXmitWriteTxD` also uses the third argument: it copies `R8` into `RDI`
at `0x1401d8570`. Its input layout matches this stack context, supporting the
candidate dynamic edge; selection of that callback is still unproven. Its offsets
must not be interpreted as offsets in the pooled queue TX object.

At the Connac3 builder:

```text
0x1401d8af3          load txwi[2]
0x1401d8af8          clear TXD2 bits 5:4
0x1401d8afe-8b0c     insert byte [descriptor_context+0x2b] into bits 5:4
0x1401d8b0e          clear TXD2 bits 3:0
0x1401d8b14-8b1d     insert byte [descriptor_context+0x2d] into bits 3:0
```

The builder address is installed through two ops-table initializers. The actual
code references are `LEA` instructions at `0x1401e38b1` and `0x1401f12b3`; the
following `MOV`s at `0x1401e38b8` and `0x1401f12ba` store it into BSS slots
`0x14025cff8` and `0x14025d458`, respectively. The BSS addresses are slots, not
initializer instruction addresses.

## RX queue flow

`EvtAdapterCreateRxQueue` constructs the callback configuration with resolved
targets for advance (`0x14008c220`), cancel (`0x14008c4e0`), start
(`0x14008ca20`), and stop (`0x14008caf0`). After registering fragment extensions,
it calls:

```text
0x14008c16c -> MTRxQueueInitialize (0x14008cbc0)
```

`MTRxQueueInitialize` records the queue handle at RX context `+0x00`, adapter at
`+0x08`, selected port context at `+0x18`, and ring collection at `+0x20`. It also
stores the queue handle into port context `+0x240` and clears port byte `+0x254`.

`EvtRxQueueAdvance` then performs a driver-private-to-NetAdapterCx copy loop. It
selects one of three adapter lists (`+0x12a0`, `+0x12b8`, or `+0x12d0`) from port
state, removes an RX node with `ExInterlockedRemoveHeadList` at `0x14008c33d`,
writes the node/buffer reference into the fragment ring, writes the packet-ring
entry, and advances both ring indices. This identifies a WiFiCx receive boundary,
but does not by itself establish native-802.11 versus translated payload format.
No direct/static edge from it to legacy `MiniportWdiRxGetMpdus` was found.

## Relationship to the legacy WDI send worker

Static xrefs to `WdiSendDataProcess` are direct calls from the worker family at
`0x140050ce0`, `0x140050dc0`, `0x140050ea0`, `0x140050f80`, `0x140051060`, and
`0x140051140`. None of the WiFiCx queue functions above is among those callers.

`WdiSendDataProcess` itself calls `0x14008d62c` at `0x140050c08`, passing the work
object at adapter offset `+0x5ca9e0`. `EvtTxQueueAdvance` calls the same scheduler
with an object derived from adapter offset `+0x340678 + queue*0x20f0`. This proves
reuse of the driver's work scheduler, not reuse of packet metadata or entry into
the WDI processor.

## Confidence and remaining gates

| Finding | Confidence |
|---|---|
| Callback/function bounds and listed direct calls | High |
| Asynchronous `EvtTxQueueAdvance -> workers -> processTxAdvance` chain | High |
| Descriptor-context `+0x2b` type and `+0x2d` subtype use in Connac3 TXD2 | High |
| Both hard-TX paths derive descriptor type/subtype directly from frame control | High |
| WiFiCx queue copies queue `+0x29` into a distinct TX-object byte `+0x2b` | High; field meaning provisional |
| WiFiCx and legacy WDI paths are separate before scheduling | High |
| Both hard-TX helpers reach common dynamic TXD dispatch at `0x1401a2b2c` | High |
| Dynamic dispatch selects `AsicConnac3xXmitWriteTxD` on MT7925 | Plausible, not statically closed |

The next read-only gates are deliberately bounded:

1. Find every writer of `adapter+0x1464f17`, recover the MT7925 selection branch,
   and tie its value to one of the two BSS slots containing
   `AsicConnac3xXmitWriteTxD`.
2. Name the guarded framework accessor at `0x140087d6e` and decode the translation
   table used for queue context `+0x29`; do not assume it is a frame-type enum.
3. Trace the raw-buffer pointer and length from the AP/special path into the TX
   object and prepared frame at `[rsi]`, without assuming the ordinary NetAdapterCx
   packet ring accepts an 802.11 MPDU. Reconcile all consumers before naming TX
   object bytes `+0x2a/+0x2b/+0x2d`.
4. Map the hardware RX producer into the three lists consumed by
   `EvtRxQueueAdvance`, and determine where non-associated/vendor-action frames
   are admitted or discarded.

These gaps keep the current verdict unchanged: the stock image contains the
required descriptor machinery, but this queue map does not prove an external
WiFiCx/LWF raw-802.11 injection seam. No live driver experiment is justified by
this analysis alone.
