#!/usr/bin/env python3
"""Locate MediaTek 12-byte vendor-OID records by handler virtual address."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

import pefile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("handlers", nargs="+", type=lambda value: int(value, 0))
    args = parser.parse_args()

    data = args.pe.read_bytes()
    pe = pefile.PE(data=data, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    for handler in args.handlers:
        encoded = struct.pack("<I", handler & 0xFFFFFFFF)
        cursor = 0
        found_any = False
        while True:
            offset = data.find(encoded, cursor)
            if offset < 0:
                break
            cursor = offset + 1
            if offset >= 4 and offset + 8 <= len(data):
                oid, pointer, flags = struct.unpack_from("<III", data, offset - 4)
                if pointer == (handler & 0xFFFFFFFF) and oid >= 0xFF000000:
                    record_rva = pe.get_rva_from_offset(offset - 4)
                    print(
                        f"handler={handler:#x} oid={oid:#010x} flags={flags:#x} "
                        f"record_va={base + record_rva:#x} file={offset - 4:#x}"
                    )
                    found_any = True
        if not found_any:
            print(f"handler={handler:#x}: no plausible vendor-OID record")


if __name__ == "__main__":
    main()
