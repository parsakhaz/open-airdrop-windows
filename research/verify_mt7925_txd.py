#!/usr/bin/env python3
"""Verify static TXD landmarks in one hash-pinned MT7925 driver; never load it."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP


EXPECTED_SHA256 = "6232dbfd53c2e9824eb4d193980f7db378b88dd155cb8d4e64ab56696e057161"
BUILDER = 0x1401D8540
BUILDER_END = 0x1401D9032
FIELD_START = 0x1401D8AF3
FIELD_BYTES = bytes.fromhex(
    "8b4b088bc183e0cf8943080fb6572bc1e20433d183e23033d18bc2"
    "83e0f08943080fb64f2d33ca83e10f33ca"
)
INITIALIZERS = ((0x1401E38B1, 0x14025CFF8), (0x1401F12B3, 0x14025D458))
QUEUE_CALLS = (
    (0x140086E8A, 0x14008A170),  # create -> initialize
    (0x140012196, 0x14008AC28),  # worker 0 -> processTxAdvance
    (0x14008B28C, 0x14008AB8C),  # queue metadata copier
    (0x14008B703, 0x1400885D0),  # AP/special submit
    (0x14008B70A, 0x140089048),  # normal submit
    (0x140088F4F, 0x1401A2B2C),  # AP/special -> dynamic TXD wrapper
    (0x140089F69, 0x1401A2B2C),  # normal -> same wrapper
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify(path: Path) -> dict:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(digest == EXPECTED_SHA256, f"unsupported image SHA-256: {digest}")
    pe = pefile.PE(data=data, fast_load=False)
    base = pe.OPTIONAL_HEADER.ImageBase
    require(pe.FILE_HEADER.Machine == 0x8664, "expected an AMD64 PE image")
    require(base == 0x140000000, "unexpected preferred image base")
    ranges = {
        (base + entry.struct.BeginAddress, base + entry.struct.EndAddress)
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION
    }
    require((BUILDER, BUILDER_END) in ranges, "TXD runtime-function bounds differ")
    recovered = pe.get_data(FIELD_START - base, len(FIELD_BYTES))
    require(recovered == FIELD_BYTES, "type/subtype instruction sequence differs")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    initializers = []
    for address, expected_slot in INITIALIZERS:
        instructions = list(md.disasm(pe.get_data(address - base, 14), address))
        require(len(instructions) == 2, "expected a LEA/MOV initializer pair")
        lea, mov = instructions
        require(lea.mnemonic == "lea" and mov.mnemonic == "mov", "unexpected initializer")
        source, destination = lea.operands[1], mov.operands[0]
        require(
            source.type == X86_OP_MEM and source.mem.base == X86_REG_RIP
            and destination.type == X86_OP_MEM and destination.mem.base == X86_REG_RIP,
            "expected RIP-relative initializer operands",
        )
        target = lea.address + lea.size + source.mem.disp
        slot = mov.address + mov.size + destination.mem.disp
        require(target == BUILDER and slot == expected_slot, "ops-table mapping differs")
        initializers.append({"instruction_va": hex(address), "slot_va": hex(slot)})

    direct_edges = []
    for address, target in QUEUE_CALLS:
        instruction = next(md.disasm(pe.get_data(address - base, 5), address), None)
        require(
            instruction is not None and instruction.mnemonic == "call"
            and instruction.operands[0].type == X86_OP_IMM
            and instruction.operands[0].imm == target,
            f"queue direct edge differs at {address:#x}",
        )
        direct_edges.append({"call_va": hex(address), "target_va": hex(target)})

    # Special/AP helper passes a stack descriptor-input structure at RBP-0x69.
    # Its +0x2b/+0x2d fields come from FC, NOT similarly numbered TX-object fields.
    context_code = list(md.disasm(pe.get_data(0x88ED5, 0x25), 0x140088ED5))
    expected_context = [
        ("movzx", "eax, word ptr [rsi]"), ("lea", "r8, [rbp - 0x69]"),
        ("shr", "ax, 2"), ("mov", "rcx, r15"), ("and", "ax, 3"),
        ("mov", "word ptr [rbp - 0x3e], ax"),
        ("movzx", "eax, word ptr [rsi]"), ("shr", "ax, 4"),
        ("and", "ax, 0xf"), ("mov", "word ptr [rbp - 0x3c], ax"),
    ]
    require(
        [(i.mnemonic, i.op_str) for i in context_code] == expected_context,
        "prepared-FC to descriptor-input mapping differs",
    )

    # This verifies only the recovered TXD2 field projection, not a complete
    # usable TXWI: WCID, buffer, ownership, sequence and crypto remain unknown.
    mask = 0x3F
    vectors = []
    for name, frame_control in (("action", 0x00D0), ("data", 0x0008)):
        frame_type = (frame_control >> 2) & 3
        subtype = (frame_control >> 4) & 15
        bits = (frame_type << 4) | subtype
        for original in (0, 0xFFFFFFFF, 0xA5A55A5A):
            result = (original & ~mask) | bits
            require(result & ~mask == original & ~mask, "unrelated TXD2 bits changed")
        vectors.append({"frame": name, "frame_control": hex(frame_control), "txd2_low6": hex(bits)})

    return {
        "result": "PASS",
        "sha256": digest,
        "builder_va": hex(BUILDER),
        "builder_end_va": hex(BUILDER_END),
        "txd2_type_mask": "0x30",
        "txd2_subtype_mask": "0x0f",
        "input_type_offset": "0x2b",
        "input_subtype_offset": "0x2d",
        "ops_initializers": initializers,
        "queue_direct_edges": direct_edges,
        "descriptor_input_from_prepared_fc": {
            "instruction_va": "0x140088ed5",
            "argument": "R8 = RBP - 0x69",
            "type_offset": "0x2b",
            "subtype_offset": "0x2d",
            "unresolved": "dynamic MT7925 callback selection and original raw-input contract",
        },
        "field_projection_vectors": vectors,
        "scope": "static file validation only; no driver load, device open, or RF proof",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path, help="offline mtkwecx.sys 5.7.0.5115 image")
    args = parser.parse_args()
    try:
        result = verify(args.pe)
    except (OSError, ValueError, pefile.PEFormatError) as error:
        parser.exit(1, f"FAIL: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
