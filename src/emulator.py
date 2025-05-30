# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Molly Draven
# This file is part of the PE Emulator/Disassembler project, licensed under GPLv3.
# See LICENSE file for details.

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_RSP
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

def setup_unicorn(pe, image_base, code, sections, arch):
    if arch == 'x86':
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
    else:
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # Map all code sections
    for section in sections:
        section_addr = image_base + section.VirtualAddress
        section_size = max(section.SizeOfRawData, section.Misc_VirtualSize)
        aligned_size = ((section_size + 0xFFF) // 0x1000) * 0x1000
        try:
            uc.mem_map(section_addr, aligned_size)
            uc.mem_write(section_addr, section.get_data()[:aligned_size])
        except Exception:
            pass
    # Map stack
    STACK_ADDR = 0x0ff00000
    STACK_SIZE = 2 * 1024 * 1024
    uc.mem_map(STACK_ADDR, STACK_SIZE)
    if arch == 'x86':
        stack_ptr = STACK_ADDR + STACK_SIZE // 2
        uc.reg_write(UC_X86_REG_ESP, stack_ptr)
        fake_ret = (0xdeadbeef).to_bytes(4, byteorder='little')
        uc.mem_write(stack_ptr - 4, fake_ret)
        uc.reg_write(UC_X86_REG_ESP, stack_ptr - 4)
    else:
        stack_ptr = STACK_ADDR + STACK_SIZE // 2
        uc.reg_write(UC_X86_REG_RSP, stack_ptr)
        fake_ret = (0xdeadbeefdeadbeef).to_bytes(8, byteorder='little')
        uc.mem_write(stack_ptr - 8, fake_ret)
        uc.reg_write(UC_X86_REG_RSP, stack_ptr - 8)
    # Map TEB
    TEB_ADDR = 0x0
    TEB_SIZE = 0x1000
    uc.mem_map(TEB_ADDR, TEB_SIZE)
    uc.mem_write(TEB_ADDR, b'\x00' * TEB_SIZE)
    return uc

def add_call_stack_hook(uc, pe, arch, call_stack):
    def hook_code(uc, address, size, user_data):
        try:
            inst_bytes = uc.mem_read(address, size)
            cs_mode = CS_MODE_32 if arch == 'x86' else CS_MODE_64
            md = Cs(CS_ARCH_X86, cs_mode)
            for insn in md.disasm(inst_bytes, address):
                if insn.mnemonic == 'call':
                    call_stack.append(address)
                elif insn.mnemonic == 'ret' and call_stack:
                    call_stack.pop()
        except Exception:
            pass
    uc.hook_add(1, hook_code)
