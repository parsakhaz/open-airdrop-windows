# Offline MT7925 research

Start with the [build plan](mt7925-miniport-build-plan.md), then the
[Linux/Windows comparison](mt7925-linux-windows-datapath-map.md) and
[private-control audit](mt7925-private-control.md). These distinguish observed
instructions, source-reported behavior, architectural hypotheses, and live gates.

The PE tools read regular files. They do not load a driver, open a device, issue
IOCTLs, or change adapter state. They require Python 3.10+, `pefile`, and
`capstone`; use an isolated environment. Vendor binaries and downloaded sources
are not redistributed in this repository.

## Reproduce the descriptor evidence

With dependencies already installed, supply a copy of `mtkwecx.sys` 5.7.0.5115:

```powershell
python research\verify_mt7925_txd.py 'C:\path\to\mtkwecx.sys'
python research\pe_string_xrefs.py 'C:\path\to\mtkwecx.sys' AsicConnac3xXmitWriteTxD --context 4
python research\pe_address_xrefs.py 'C:\path\to\mtkwecx.sys' 0x1401d8540 --context 4
python research\pe_function_disasm.py 'C:\path\to\mtkwecx.sys' 0x1401d8540 --around 0x1401d8af3 --context 25
```

The verifier refuses any image whose SHA-256 differs from
`6232dbfd53c2e9824eb4d193980f7db378b88dd155cb8d4e64ab56696e057161`.
It checks function bounds, the recovered instruction sequence, and LEA/MOV pairs
that install the builder in two ops-table slots. Expected TXD2 low-six-bit values
are `0x0d` for an action-frame header and `0x20` for a basic data-frame header.
These are field-projection examples, not complete transmit descriptors.

The general xref helpers scan executable sections and retain context around hits
rather than every decoded instruction. They use linear disassembly, not a complete
control-flow recovery engine; indirect references and dynamically generated paths
can escape detection. Absence of a hit is not proof of unreachable behavior.

All addresses refer to the preferred image base of the recorded binary. They are
not live kernel addresses or a stable ABI. The current user instruction requires
fresh approval before any driver load or live adapter/firmware operation.
