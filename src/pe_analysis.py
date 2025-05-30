# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Molly Draven
# This file is part of the PE Emulator/Disassembler project, licensed under GPLv3.
# See LICENSE file for details.

from typing import Any, Dict, List, Optional
from peutils import load_pe, get_entry_info, disassemble_entry  # type: ignore
from emulator import setup_unicorn, add_call_stack_hook  # type: ignore
from unicorn import UcError  # type: ignore
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_ESP,
    UC_X86_REG_RSP,
    UC_X86_REG_EIP,
    UC_X86_REG_RIP,
)  # type: ignore


def analyze_pe_file(file_path: str, disasm_bytes: int = 32) -> Dict[str, Any]:
    pe, data = load_pe(file_path)
    # get_entry_info returns Tuple[Any, int, int], but we only use image_base and entry_point_va
    _unused: Any
    _unused, image_base, entry_point_va = get_entry_info(pe)  # type: ignore
    arch = "x86" if getattr(pe.FILE_HEADER, "Machine", 0) == 0x14C else "x64"  # type: ignore
    # Find code section
    code_section: Any = None
    for section in getattr(pe, "sections", []):  # type: ignore
        section_start = getattr(section, "VirtualAddress", 0) + image_base  # type: ignore
        section_end = section_start + getattr(section, "Misc_VirtualSize", 0)  # type: ignore
        if section_start <= entry_point_va < section_end:
            code_section = section
            break
    if code_section is None:
        raise RuntimeError("Entry point not in any section!")
    entry_offset = int(
        entry_point_va - getattr(code_section, "VirtualAddress", 0) - image_base  # type: ignore
    ) + int(getattr(code_section, "PointerToRawData", 0))  # type: ignore
    code = data[entry_offset : entry_offset + disasm_bytes]
    disasm = disassemble_entry(code, entry_point_va, arch)  # type: ignore
    return {
        "pe": pe,
        "data": data,
        "entry_point_va": entry_point_va,
        "image_base": image_base,
        "arch": arch,
        "code": code,
        "disasm": disasm,
    }


def handle_emulation_error(
    uc: Any, arch: str, call_stack: List[Any], error: Optional[str]
) -> Dict[str, Any]:
    """Capture and return full emulator state on error."""
    # Instruction pointer
    if arch == "x86":
        ip_reg = uc.reg_read(UC_X86_REG_EIP)
        sp_val = uc.reg_read(UC_X86_REG_ESP)
        sp_name = "ESP"
    else:
        ip_reg = uc.reg_read(UC_X86_REG_RIP)
        sp_val = uc.reg_read(UC_X86_REG_RSP)
        sp_name = "RSP"
    # General purpose registers
    reg_name_map = {
        UC_X86_REG_EAX: "EAX",
        UC_X86_REG_EBX: "EBX",
        UC_X86_REG_ECX: "ECX",
        UC_X86_REG_EDX: "EDX",
    }
    reg_names = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX]
    regs = {reg_name_map.get(reg, str(reg)): uc.reg_read(reg) for reg in reg_names}
    # Try to read top of stack
    try:
        stack_bytes = uc.mem_read(sp_val, 32)
        stack_hex = stack_bytes.hex()
    except Exception as stack_exc:
        stack_hex = f"Could not read stack memory: {stack_exc}"
    return {
        "emu_error": error,
        "ip_reg": ip_reg,
        "call_stack": call_stack,
        "regs": regs,
        "sp_val": sp_val,
        "sp_name": sp_name,
        "stack_hex": stack_hex,
    }


def emulate_entry(
    pe: Any, image_base: int, code: bytes, arch: str, entry_point_va: int, sections: Any
) -> Dict[str, Any]:
    uc = setup_unicorn(pe, image_base, code, sections, arch)
    call_stack: List[Any] = []
    add_call_stack_hook(uc, pe, arch, call_stack)
    print(f"Starting emulation at entry point: 0x{entry_point_va:x} ({arch})")
    try:
        uc.emu_start(entry_point_va, entry_point_va + 8)
        # On success, capture state as well
        return handle_emulation_error(uc, arch, call_stack, None)
    except UcError as ue:
        return handle_emulation_error(uc, arch, call_stack, f"Unicorn emulation error: {ue}")
    except Exception as e:
        return handle_emulation_error(uc, arch, call_stack, str(e))
