# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Molly Draven
# This file is part of the PE Emulator/Disassembler project, licensed under GPLv3.
# See LICENSE file for details.

from peutils import load_pe, get_entry_info, disassemble_entry
from emulator import setup_unicorn, add_call_stack_hook
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_RSP

def analyze_pe_file(file_path, disasm_bytes=32):
    pe, data = load_pe(file_path)
    entry_point_rva, image_base, entry_point_va = get_entry_info(pe)
    arch = 'x86' if pe.FILE_HEADER.Machine == 0x14c else 'x64'
    # Find code section
    for section in pe.sections:
        section_start = section.VirtualAddress + image_base
        section_end = section_start + section.Misc_VirtualSize
        if section_start <= entry_point_va < section_end:
            code_section = section
            break
    else:
        raise RuntimeError("Entry point not in any section!")
    entry_offset = (entry_point_va - code_section.VirtualAddress - image_base) + code_section.PointerToRawData
    code = data[entry_offset:entry_offset+disasm_bytes]
    disasm = disassemble_entry(code, entry_point_va, arch)
    return {
        'pe': pe,
        'data': data,
        'entry_point_va': entry_point_va,
        'image_base': image_base,
        'arch': arch,
        'code': code,
        'disasm': disasm
    }

def emulate_entry(pe, image_base, code, arch, entry_point_va, sections):
    uc = setup_unicorn(pe, image_base, code, sections, arch)
    call_stack = []
    add_call_stack_hook(uc, pe, arch, call_stack)
    emu_error = None
    ip_reg = None
    try:
        uc.emu_start(entry_point_va, entry_point_va + 8)
    except Exception as e:
        emu_error = e
        if arch == 'x86':
            ip_reg = uc.reg_read(0x20)
        else:
            ip_reg = uc.reg_read(0x2a)
    reg_name_map = {
        UC_X86_REG_EAX: "EAX",
        UC_X86_REG_EBX: "EBX",
        UC_X86_REG_ECX: "ECX",
        UC_X86_REG_EDX: "EDX"
    }
    reg_names = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX]
    regs = {reg_name_map.get(reg, str(reg)): uc.reg_read(reg) for reg in reg_names}
    if arch == 'x86':
        sp_val = uc.reg_read(UC_X86_REG_ESP)
        sp_name = 'ESP'
    else:
        sp_val = uc.reg_read(UC_X86_REG_RSP)
        sp_name = 'RSP'
    return {
        'emu_error': emu_error,
        'ip_reg': ip_reg,
        'call_stack': call_stack,
        'regs': regs,
        'sp_val': sp_val,
        'sp_name': sp_name
    }
