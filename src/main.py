import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_RSP
from emulator import setup_unicorn, add_call_stack_hook
from peutils import load_pe, get_entry_info, disassemble_entry
from gui import main as gui_main


def print_registers(uc, reg_names, reg_name_map):
    for reg in reg_names:
        print(f"{reg_name_map.get(reg, str(reg))}: {uc.reg_read(reg)}")

def print_stack(uc, sp_reg, sp_name):
    sp_val = uc.reg_read(sp_reg)
    print(f"{sp_name}: 0x{sp_val:x}")
    try:
        stack_bytes = uc.mem_read(sp_val, 16)
        print(f"Top 16 bytes of stack at {sp_name}:", stack_bytes.hex())
    except Exception as e:
        print(f"Could not read stack memory: {e}")

def main():
    file = "/home/drazisil/Downloads/MCity_d.exe"
    pe, data = load_pe(file)
    entry_point_rva, image_base, entry_point_va = get_entry_info(pe)
    print(f"Entry Point: {hex(entry_point_va)}")
    print(f"Base Address: {hex(image_base)}")
    arch = 'x86' if pe.FILE_HEADER.Machine == 0x14c else 'x64'
    # Find the section containing the entry point
    for section in pe.sections:
        section_start = section.VirtualAddress + image_base
        section_end = section_start + section.Misc_VirtualSize
        if section_start <= entry_point_va < section_end:
            code_section = section
            break
    else:
        print("Entry point not in any section!")
        return
    entry_offset = (entry_point_va - code_section.VirtualAddress - image_base) + code_section.PointerToRawData
    code = data[entry_offset:entry_offset+32]
    print("Disassembled code at entry point:")
    for i in disassemble_entry(code, entry_point_va, arch):
        print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
    print("\nEmulating first instruction at entry point with Unicorn:")
    reg_name_map = {
        UC_X86_REG_EAX: "EAX",
        UC_X86_REG_EBX: "EBX",
        UC_X86_REG_ECX: "ECX",
        UC_X86_REG_EDX: "EDX"
    }
    reg_names = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX]
    uc = setup_unicorn(pe, image_base, code, pe.sections, arch)
    call_stack = []
    add_call_stack_hook(uc, pe, arch, call_stack)
    try:
        uc.emu_start(0x1000000, 0x1000000 + 8)
    except Exception as e:
        print(f"Unicorn emulation error: {e}")
        if hasattr(e, 'exception') and hasattr(e.exception, 'address'):
            print(f"Invalid memory access at address: 0x{e.exception.address:x}")
        elif hasattr(e, 'address'):
            print(f"Invalid memory access at address: 0x{e.address:x}")
        if arch == 'x86':
            ip_reg = uc.reg_read(0x20)
            print(f"EIP at error: 0x{ip_reg:x}")
        else:
            ip_reg = uc.reg_read(0x2a)
            print(f"RIP at error: 0x{ip_reg:x}")
        if call_stack:
            print("Simulated call stack trace:")
            for addr in reversed(call_stack):
                print(f"  0x{addr:x}")
        else:
            print("Simulated call stack trace: <empty>")
    print("Register state after emulation:")
    print_registers(uc, reg_names, reg_name_map)
    if arch == 'x86':
        print_stack(uc, UC_X86_REG_ESP, "ESP")
    else:
        print_stack(uc, UC_X86_REG_RSP, "RSP")

if __name__ == "__main__":
    gui_main()
