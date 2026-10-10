#!/usr/bin/env python3
"""Find x64 RIP-relative references to an ASCII or UTF-16 PE string."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import deque
import re
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("needle")
    parser.add_argument("--context", type=int, default=20)
    parser.add_argument(
        "--substring",
        action="store_true",
        help="Match within printable strings and resolve references to their starts",
    )
    args = parser.parse_args()
    if args.context < 0:
        parser.error("--context must be nonnegative")

    data = args.pe.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    base = pe.OPTIONAL_HEADER.ImageBase
    offsets = set()
    if args.substring:
        needle = args.needle.casefold()
        for match in re.finditer(rb"[ -~]{4,}\x00", data):
            if needle in match.group()[:-1].decode("ascii").casefold():
                offsets.add(match.start())
        wide_pattern = re.compile(rb"(?:[ -~]\x00){4,}\x00\x00")
        for match in wide_pattern.finditer(data):
            if needle in match.group()[:-2].decode("utf-16le").casefold():
                offsets.add(match.start())
    else:
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
    for offset in sorted(offsets):
        rva = pe.get_rva_from_offset(offset)
        target_vas[base + rva] = offset
    print("targets:", ", ".join(f"VA={va:#x}/file={offset:#x}" for va, offset in target_vas.items()))

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.skipdata = True
    detail_md = Cs(CS_ARCH_X86, CS_MODE_64)
    detail_md.detail = True
    runtime_ranges = sorted(
        (base + entry.struct.BeginAddress, base + entry.struct.EndAddress)
        for entry in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])
    )
    runtime_starts = [begin for begin, _ in runtime_ranges]

    def containing_function(address: int) -> tuple[int, int] | None:
        index = bisect_right(runtime_starts, address) - 1
        if index >= 0 and address < runtime_ranges[index][1]:
            return runtime_ranges[index]
        return None

    # Keep only the requested context around hits.  Materializing every decoded
    # instruction in a multi-megabyte driver can consume several gigabytes with
    # Capstone's Python objects and get the analysis process killed.
    records: list[dict[str, object]] = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        before: deque = deque(maxlen=args.context)
        active: list[dict[str, object]] = []
        section_data = section.get_data()
        section_va = base + section.VirtualAddress
        for address, size, mnemonic, op_str in md.disasm_lite(section_data, section_va):
            current = (address, mnemonic, op_str)
            for record in active[:]:
                record["instructions"].append(current)  # type: ignore[union-attr]
                record["remaining"] = int(record["remaining"]) - 1
                if record["remaining"] == 0:
                    active.remove(record)

            references = []
            if "rip" in op_str:
                offset = address - section_va
                detailed = next(detail_md.disasm(section_data[offset : offset + size], address), None)
                if detailed:
                    for operand in detailed.operands:
                        if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                            referenced = detailed.address + detailed.size + operand.mem.disp
                            if referenced in target_vas:
                                references.append(referenced)
            if references:
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

    for record in records:
        print(
            f"\n=== xref at {int(record['address']):#x}; "
            f"function={record['function']} ==="
        )
        for address, mnemonic, op_str in record["instructions"]:
            marker = ">>" if address == record["address"] else "  "
            print(f"{marker} {address:#018x} {mnemonic:8} {op_str}")


if __name__ == "__main__":
    main()
