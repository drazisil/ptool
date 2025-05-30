# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Molly Draven
# This file is part of the PE Emulator/Disassembler project, licensed under GPLv3.
# See LICENSE file for details.

from typing import Any
from gui import main as gui_main  # type: ignore


def print_registers(uc: Any, reg_names: list[Any], reg_name_map: dict[Any, str]) -> None:
    for reg in reg_names:
        print(f"{reg_name_map.get(reg, str(reg))}: {uc.reg_read(reg)}")


def print_stack(uc: Any, sp_reg: Any, sp_name: str) -> None:
    sp_val = uc.reg_read(sp_reg)
    print(f"{sp_name}: 0x{sp_val:x}")
    try:
        stack_bytes = uc.mem_read(sp_val, 16)
        print(f"Top 16 bytes of stack at {sp_name}:", stack_bytes.hex())
    except Exception as e:
        print(f"Could not read stack memory: {e}")


if __name__ == "__main__":
    gui_main()
