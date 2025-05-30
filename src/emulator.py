# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Molly Draven
# This file is part of the PE Emulator/Disassembler project, licensed under GPLv3.
# See LICENSE file for details.

from typing import Any
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64  # type: ignore
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_RSP  # type: ignore
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64  # type: ignore


def setup_unicorn(pe: Any, image_base: int, code: bytes, sections: Any, arch: str) -> Any:
    if arch == "x86":
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
    else:
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # Map all code sections
    for section in sections:
        section_addr = image_base + getattr(section, "VirtualAddress", 0)  # type: ignore
        section_size = max(getattr(section, "SizeOfRawData", 0), getattr(section, "Misc_VirtualSize", 0))  # type: ignore
        aligned_size = ((section_size + 0xFFF) // 0x1000) * 0x1000
        try:
            uc.mem_map(section_addr, aligned_size)
            uc.mem_write(section_addr, section.get_data()[:aligned_size])

            # output debug info
            print(f"Mapped section {getattr(section, 'Name', b'').decode().strip()} at 0x{section_addr:X} with size {aligned_size} bytes")
        except Exception:
            pass
    # Map stack
    STACK_ADDR = 0x0FF00000
    STACK_SIZE = 2 * 1024 * 1024
    uc.mem_map(STACK_ADDR, STACK_SIZE)
    if arch == "x86":
        stack_ptr: int = STACK_ADDR + STACK_SIZE // 2
        uc.reg_write(UC_X86_REG_ESP, int(stack_ptr))  # type: ignore
        fake_ret = (0xDEADBEEF).to_bytes(4, byteorder="little")
        uc.mem_write(stack_ptr - 4, fake_ret)
        uc.reg_write(UC_X86_REG_ESP, int(stack_ptr - 4))  # type: ignore
    else:
        stack_ptr: int = STACK_ADDR + STACK_SIZE // 2
        uc.reg_write(UC_X86_REG_RSP, int(stack_ptr))  # type: ignore
        fake_ret = (0xDEADBEEFDEADBEEF).to_bytes(8, byteorder="little")
        uc.mem_write(stack_ptr - 8, fake_ret)
        uc.reg_write(UC_X86_REG_RSP, int(stack_ptr - 8))  # type: ignore
    # Map TEB
    TEB_ADDR = 0x0
    TEB_SIZE = 0x1000
    uc.mem_map(TEB_ADDR, TEB_SIZE)
    uc.mem_write(TEB_ADDR, b"\x00" * TEB_SIZE)
    return uc


def add_call_stack_hook(uc: Any, pe: Any, arch: str, call_stack: list[Any]) -> None:
    def hook_code(uc: Any, address: int, size: int, user_data: Any) -> None:
        try:
            inst_bytes = uc.mem_read(int(address), int(size))
            cs_mode = CS_MODE_32 if arch == "x86" else CS_MODE_64
            md = Cs(CS_ARCH_X86, cs_mode)
            for insn in md.disasm(inst_bytes, int(address)): # type: ignore
                if insn.mnemonic == "call":
                    call_stack.append(int(address))
                elif insn.mnemonic == "ret" and call_stack:
                    call_stack.pop()
        except Exception:
            pass

    uc.hook_add(1, hook_code)
