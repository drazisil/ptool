# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Molly Draven
# This file is part of the PE Emulator/Disassembler project, licensed under GPLv3.
# See LICENSE file for details.

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

def load_pe(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    pe = pefile.PE(data=data)
    return pe, data

def get_entry_info(pe):
    entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry_point_va = image_base + entry_point_rva
    return entry_point_rva, image_base, entry_point_va

def disassemble_entry(code, entry_point_va, arch):
    if arch == 'x86':
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    return list(md.disasm(code, entry_point_va))
