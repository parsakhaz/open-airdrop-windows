#!/usr/bin/env python3
"""Find static references to a virtual address in an x64 PE image."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import deque
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("address", type=lambda value: int(value, 0))
    parser.add_argument("--context", type=int, default=8)
    args = parser.parse_args()
    if args.context < 0:
        parser.error("--context must be nonnegative")

    pe = pefile.PE(str(args.pe), fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    runtime_ranges = sorted(
        (image_base + entry.struct.BeginAddress, image_base + entry.struct.EndAddress)
        for entry in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])
    )
    runtime_starts = [begin for begin, _ in runtime_ranges]

    def containing_function(address: int) -> tuple[int, int] | None:
        index = bisect_right(runtime_starts, address) - 1
        if index >= 0 and address < runtime_ranges[index][1]:
            return runtime_ranges[index]
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    detail_md = Cs(CS_ARCH_X86, CS_MODE_64)
    detail_md.detail = True
    records: list[dict[str, object]] = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        before: deque = deque(maxlen=args.context)
        active: list[dict[str, object]] = []
        section_data = section.get_data()
        section_va = image_base + section.VirtualAddress
        for address, size, mnemonic, op_str in md.disasm_lite(section_data, section_va):
            current = (address, mnemonic, op_str)
            for record in active[:]:
                record["instructions"].append(current)  # type: ignore[union-attr]
                record["remaining"] = int(record["remaining"]) - 1
                if record["remaining"] == 0:
                    active.remove(record)

            hit = False
            if "rip" in op_str or f"{args.address:#x}" in op_str:
                offset = address - section_va
                detailed = next(detail_md.disasm(section_data[offset : offset + size], address), None)
                if detailed:
                    for operand in detailed.operands:
                        if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                            referenced = detailed.address + detailed.size + operand.mem.disp
                        elif operand.type == X86_OP_IMM:
                            referenced = operand.imm
                        else:
                            continue
                        if referenced == args.address:
                            hit = True
                            break
            if hit:
                record = {
                    "address": address,
                    "function": containing_function(address),
                    "instructions": [*before, current],
                    "remaining": args.context,
                }
                records.append(record)
                if args.context:
                    active.append(record)
            before.append(current)

    print(f"{args.pe}: {len(records)} references to {args.address:#x}")
    for record in records:
        containing = record["function"]
        label = f"{containing[0]:#x}-{containing[1]:#x}" if containing else "unknown"
        print(f"\n=== reference at {int(record['address']):#x}; function {label} ===")
        for address, mnemonic, op_str in record["instructions"]:
            marker = ">>" if address == record["address"] else "  "
            print(f"{marker} {address:#018x} {mnemonic:8} {op_str}")


if __name__ == "__main__":
    main()
