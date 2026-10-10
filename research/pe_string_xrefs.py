#!/usr/bin/env python3
"""Find x64 RIP-relative references to an ASCII or UTF-16 PE string."""

from __future__ import annotations

import argparse
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("needle")
    parser.add_argument("--context", type=int, default=20)
    args = parser.parse_args()

    data = args.pe.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    base = pe.OPTIONAL_HEADER.ImageBase
    offsets = set()
    for encoded in (args.needle.encode("ascii") + b"\0", args.needle.encode("utf-16le") + b"\0\0"):
        start = 0
        while True:
            found = data.find(encoded, start)
            if found < 0:
                break
            offsets.add(found)
            start = found + 1
    if not offsets:
        raise SystemExit("String not found")

    target_vas = {}
    for offset in offsets:
        rva = pe.get_rva_from_offset(offset)
        target_vas[base + rva] = offset
    print("targets:", ", ".join(f"VA={va:#x}/file={offset:#x}" for va, offset in target_vas.items()))

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    instructions = []
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            instructions.extend(md.disasm(section.get_data(), base + section.VirtualAddress))
    by_address = {instruction.address: index for index, instruction in enumerate(instructions)}
    runtime_ranges = [
        (base + entry.struct.BeginAddress, base + entry.struct.EndAddress)
        for entry in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])
    ]

    for instruction in instructions:
        references = []
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                referenced = instruction.address + instruction.size + operand.mem.disp
                if referenced in target_vas:
                    references.append(referenced)
        if not references:
            continue
        containing = next(((begin, end) for begin, end in runtime_ranges if begin <= instruction.address < end), None)
        print(f"\n=== xref at {instruction.address:#x}; function={containing} ===")
        center = by_address[instruction.address]
        for current in instructions[max(0, center - args.context) : center + args.context + 1]:
            marker = ">>" if current.address == instruction.address else "  "
            print(f"{marker} {current.address:#018x} {current.mnemonic:8} {current.op_str}")


if __name__ == "__main__":
    main()
