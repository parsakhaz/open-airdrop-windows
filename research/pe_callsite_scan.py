#!/usr/bin/env python3
"""Locate x64 PE import call sites and string references without loading a driver."""

from __future__ import annotations

import argparse
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP


def read_string(data: bytes, offset: int) -> str | None:
    if offset < 0 or offset >= len(data):
        return None
    ascii_end = data.find(b"\0", offset, min(len(data), offset + 260))
    if ascii_end > offset:
        candidate = data[offset:ascii_end]
        if len(candidate) >= 4 and all(0x20 <= byte < 0x7F for byte in candidate):
            return candidate.decode("ascii")
    end = offset
    while end + 1 < min(len(data), offset + 520) and data[end : end + 2] != b"\0\0":
        end += 2
    if end > offset:
        try:
            candidate = data[offset:end].decode("utf-16le")
            if len(candidate) >= 4 and all(character.isprintable() for character in candidate):
                return candidate
        except UnicodeDecodeError:
            pass
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("symbols", nargs="+", help="Imported function names to locate")
    parser.add_argument("--context", type=int, default=18)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    pe = pefile.PE(str(args.pe), fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    data = args.pe.read_bytes()
    targets: dict[int, str] = {}
    wanted = {name.lower() for name in args.symbols}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = descriptor.dll.decode(errors="replace")
        for entry in descriptor.imports:
            name = entry.name.decode(errors="replace") if entry.name else f"ordinal_{entry.ordinal}"
            if name.lower() in wanted:
                targets[entry.address] = f"{dll}!{name}"

    if not targets:
        raise SystemExit("No requested imports found")

    runtime_ranges = []
    for runtime in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []):
        begin = image_base + runtime.struct.BeginAddress
        end = image_base + runtime.struct.EndAddress
        runtime_ranges.append((begin, end))

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    all_instructions = []
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        code = section.get_data()
        address = image_base + section.VirtualAddress
        all_instructions.extend(md.disasm(code, address))

    index_by_address = {instruction.address: index for index, instruction in enumerate(all_instructions)}
    hits = []
    for instruction in all_instructions:
        if instruction.mnemonic not in {"call", "jmp"}:
            continue
        for operand in instruction.operands:
            if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
                continue
            referenced = instruction.address + instruction.size + operand.mem.disp
            if referenced in targets:
                hits.append((instruction, targets[referenced]))

    print(f"{args.pe}: {len(hits)} call/jump sites")
    for instruction, target in hits:
        containing = next(((begin, end) for begin, end in runtime_ranges if begin <= instruction.address < end), None)
        function_label = f"0x{containing[0]:x}-0x{containing[1]:x}" if containing else "unknown"
        if args.summary:
            center = index_by_address[instruction.address]
            clues = []
            for current in all_instructions[max(0, center - 36) : center]:
                if current.mnemonic == "mov" and current.op_str.startswith(("edx, 0x", "r9d, 0x", "dword ptr [rsp + 0x28], 0x")):
                    clues.append(f"0x{current.address:x}:{current.op_str}")
                for operand in current.operands:
                    if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                        va = current.address + current.size + operand.mem.disp
                        try:
                            file_offset = pe.get_offset_from_rva(va - image_base)
                        except pefile.PEFormatError:
                            continue
                        value = read_string(data, file_offset)
                        if value and value not in clues:
                            clues.append(value[:120])
            print(f"0x{instruction.address:x} {target} function={function_label} clues={clues}")
            continue
        print(f"\n=== {target} at 0x{instruction.address:x}; function {function_label} ===")
        center = index_by_address[instruction.address]
        start = max(0, center - args.context)
        end = min(len(all_instructions), center + args.context + 1)
        for current in all_instructions[start:end]:
            annotations = []
            for operand in current.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    va = current.address + current.size + operand.mem.disp
                    try:
                        file_offset = pe.get_offset_from_rva(va - image_base)
                    except pefile.PEFormatError:
                        continue
                    value = read_string(data, file_offset)
                    if value:
                        annotations.append(repr(value[:160]))
            marker = ">>" if current.address == instruction.address else "  "
            suffix = f" ; {' | '.join(annotations)}" if annotations else ""
            print(f"{marker} 0x{current.address:016x}  {current.mnemonic:8} {current.op_str}{suffix}")


if __name__ == "__main__":
    main()
