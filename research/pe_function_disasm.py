#!/usr/bin/env python3
"""Disassemble the PE runtime function containing a virtual address."""

from __future__ import annotations

import argparse
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP


def printable_string(data: bytes, offset: int) -> str | None:
    for encoding, unit in (("ascii", 1), ("utf-16le", 2)):
        limit = min(len(data), offset + 300)
        end = offset
        terminator = b"\0" * unit
        while end + unit <= limit and data[end : end + unit] != terminator:
            end += unit
        if end - offset < 4 * unit:
            continue
        try:
            text = data[offset:end].decode(encoding)
        except UnicodeDecodeError:
            continue
        if all(character.isprintable() for character in text):
            return text[:180]
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("address", type=lambda value: int(value, 0))
    args = parser.parse_args()
    data = args.pe.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    base = pe.OPTIONAL_HEADER.ImageBase
    containing = next(
        (
            (base + entry.struct.BeginAddress, base + entry.struct.EndAddress)
            for entry in pe.DIRECTORY_ENTRY_EXCEPTION
            if base + entry.struct.BeginAddress <= args.address < base + entry.struct.EndAddress
        ),
        None,
    )
    if not containing:
        raise SystemExit("Address is not covered by a PE runtime function")
    start, end = containing
    code = pe.get_data(start - base, end - start)
    imports = {}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode(errors="replace")
        for entry in descriptor.imports:
            name = entry.name.decode(errors="replace") if entry.name else f"ordinal_{entry.ordinal}"
            imports[entry.address] = f"{dll}!{name}"

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    print(f"function {start:#x}-{end:#x} ({end-start} bytes)")
    for instruction in md.disasm(code, start):
        annotations = []
        for operand in instruction.operands:
            if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
                continue
            va = instruction.address + instruction.size + operand.mem.disp
            if va in imports:
                annotations.append(imports[va])
            try:
                offset = pe.get_offset_from_rva(va - base)
            except pefile.PEFormatError:
                continue
            text = printable_string(data, offset)
            if text:
                annotations.append(repr(text))
        suffix = f" ; {' | '.join(annotations)}" if annotations else ""
        print(f"{instruction.address:#018x} {instruction.mnemonic:8} {instruction.op_str}{suffix}")


if __name__ == "__main__":
    main()
