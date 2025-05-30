# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Molly Draven
# This file is part of the PE Emulator/Disassembler project, licensed under GPLv3.
# See LICENSE file for details.

from typing import Any, Tuple, List
import pefile  # type: ignore
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64  # type: ignore
from capstone import CsInsn  # type: ignore


def load_pe(file_path: str) -> Tuple[Any, bytes]:
    with open(file_path, "rb") as f:
        data = f.read()
    pe = pefile.PE(data=data)
    return pe, data


def get_entry_info(pe: Any) -> tuple[int, int, int]:
    if not hasattr(pe, "OPTIONAL_HEADER") or pe.OPTIONAL_HEADER is None:
        raise AttributeError("PE file does not have a valid OPTIONAL_HEADER")
    if not hasattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint") or not hasattr(pe.OPTIONAL_HEADER, "ImageBase"):
        raise AttributeError("OPTIONAL_HEADER missing AddressOfEntryPoint or ImageBase")
    entry_point_rva: int = int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0))
    image_base: int = int(getattr(pe.OPTIONAL_HEADER, "ImageBase", 0))
    entry_point_va: int = image_base + entry_point_rva
    return entry_point_rva, image_base, entry_point_va

def disassemble_entry(code: bytes, entry_point_va: int, arch: str) -> List[CsInsn]:
    if arch == "x86":
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        md: Cs = Cs(CS_ARCH_X86, CS_MODE_64)
    return list(md.disasm(code, entry_point_va)) # type: ignore

