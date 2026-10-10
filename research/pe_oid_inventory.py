#!/usr/bin/env python3
"""Inventory MediaTek vendor-OID records and recover handler log-name strings."""

from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP


def printable_at(data: bytes, offset: int) -> str | None:
    if offset < 0 or offset >= len(data):
        return None
    match = re.match(rb"[ -~]{4,}\x00", data[offset : offset + 300])
    return match.group()[:-1].decode("ascii") if match else None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("--match", help="Case-insensitive regex applied to recovered names")
    args = parser.parse_args()

    data = args.pe.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    base = pe.OPTIONAL_HEADER.ImageBase
    functions = {
        base + entry.struct.BeginAddress: base + entry.struct.EndAddress
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION
    }
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    pattern = re.compile(args.match, re.IGNORECASE) if args.match else None

    seen: set[tuple[int, int]] = set()
    for offset in range(0, len(data) - 12, 4):
        oid, pointer, flags = struct.unpack_from("<III", data, offset)
        if oid < 0xFF000000 or not (0x40000000 <= pointer < 0x41000000) or flags not in (0, 1):
            continue
        handler = 0x100000000 + pointer
        end = functions.get(handler)
        if end is None or (oid, handler) in seen:
            continue
        seen.add((oid, handler))
        names = []
        for instruction in md.disasm(pe.get_data(handler - base, end - handler), handler):
            for operand in instruction.operands:
                if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
                    continue
                target = instruction.address + instruction.size + operand.mem.disp
                try:
                    target_offset = pe.get_offset_from_rva(target - base)
                except pefile.PEFormatError:
                    continue
                text = printable_at(data, target_offset)
                if text and (text.startswith("Func") or "Oid" in text or "OID" in text):
                    names.append(text)
        label = ", ".join(dict.fromkeys(names)) or "(unnamed)"
        if pattern and not pattern.search(label):
            continue
        print(f"{oid:#010x} handler={handler:#x} size={end-handler:#x} flags={flags} {label}")


if __name__ == "__main__":
    main()
