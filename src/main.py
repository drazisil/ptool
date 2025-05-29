import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_RSP

# Main function to demonstrate the PEFile class    
def main():
    file = "/home/drazisil/Downloads/MCity_d.exe"

    with open(file, "rb") as f:
        # Read the file in binary mode
        data = f.read()
    # Create a PEFile object
    # and parse the PE header information

        pe = pefile.PE(data=data)
    
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_point_va = image_base + entry_point_rva
        print(f"Entry Point: {hex(entry_point_va)}")
        print(f"Base Address: {hex(image_base)}")

        # Identify if the entry point is a valid address
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint >= pe.OPTIONAL_HEADER.ImageBase:
            print("The entry point is a valid address.")
        else:
            print("The entry point is not a valid address.")
            exit(1)

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

        # Calculate offset in file for entry point
        entry_offset = (entry_point_va - code_section.VirtualAddress - image_base) + code_section.PointerToRawData
        # Read 32 bytes from entry point for disassembly
        code = data[entry_offset:entry_offset+32]

        # Determine architecture (32 or 64 bit)
        if pe.FILE_HEADER.Machine == 0x14c:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif pe.FILE_HEADER.Machine == 0x8664:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            print("Unknown architecture!")
            return

        print("Disassembled code at entry point:")
        for i in md.disasm(code, entry_point_va):
            print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

        # Emulate the first instruction at the entry point using Unicorn
        print("\nEmulating first instruction at entry point with Unicorn:")
        reg_name_map = {
            UC_X86_REG_EAX: "EAX",
            UC_X86_REG_EBX: "EBX",
            UC_X86_REG_ECX: "ECX",
            UC_X86_REG_EDX: "EDX"
        }
        if pe.FILE_HEADER.Machine == 0x14c:
            uc = Uc(UC_ARCH_X86, UC_MODE_32)
            reg_names = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX]
        elif pe.FILE_HEADER.Machine == 0x8664:
            uc = Uc(UC_ARCH_X86, UC_MODE_64)
            reg_names = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX]  # 64-bit regs can be added
        else:
            print("Unknown architecture for emulation!")
            return
        ADDRESS = 0x1000000
        uc.mem_map(ADDRESS, 2 * 1024 * 1024)
        uc.mem_write(ADDRESS, code)
        # Map all code sections from the PE file
        for section in pe.sections:
            section_addr = image_base + section.VirtualAddress
            section_size = max(section.SizeOfRawData, section.Misc_VirtualSize)
            # Align section size to 0x1000 (page size)
            aligned_size = ((section_size + 0xFFF) // 0x1000) * 0x1000
            try:
                uc.mem_map(section_addr, aligned_size)
                uc.mem_write(section_addr, section.get_data()[:aligned_size])
            except Exception as e:
                # Section may already be mapped, skip if so
                pass
        # Map a stack and set stack pointer
        STACK_ADDR = 0x0ff00000
        STACK_SIZE = 2 * 1024 * 1024
        uc.mem_map(STACK_ADDR, STACK_SIZE)
        if pe.FILE_HEADER.Machine == 0x14c:
            stack_ptr = STACK_ADDR + STACK_SIZE // 2
            uc.reg_write(UC_X86_REG_ESP, stack_ptr)
            # Push a fake return address onto the stack (e.g., 0xdeadbeef)
            fake_ret = (0xdeadbeef).to_bytes(4, byteorder='little')
            uc.mem_write(stack_ptr - 4, fake_ret)
            uc.reg_write(UC_X86_REG_ESP, stack_ptr - 4)
        elif pe.FILE_HEADER.Machine == 0x8664:
            stack_ptr = STACK_ADDR + STACK_SIZE // 2
            uc.reg_write(UC_X86_REG_RSP, stack_ptr)
            # Push a fake return address onto the stack (e.g., 0xdeadbeefdeadbeef)
            fake_ret = (0xdeadbeefdeadbeef).to_bytes(8, byteorder='little')
            uc.mem_write(stack_ptr - 8, fake_ret)
            uc.reg_write(UC_X86_REG_RSP, stack_ptr - 8)
        # Map the Thread Environment Block (TEB) at 0x0 for fs:[0] access
        TEB_ADDR = 0x0
        TEB_SIZE = 0x1000  # 4KB is enough for basic TEB access
        uc.mem_map(TEB_ADDR, TEB_SIZE)
        uc.mem_write(TEB_ADDR, b'\x00' * TEB_SIZE)
        # Set up a call stack trace using a code hook
        call_stack = []
        def hook_code(uc, address, size, user_data):
            try:
                # Read the current instruction
                inst_bytes = uc.mem_read(address, size)
                # Use Capstone to disassemble the instruction
                if pe.FILE_HEADER.Machine == 0x14c:
                    cs_mode = CS_MODE_32
                else:
                    cs_mode = CS_MODE_64
                md = Cs(CS_ARCH_X86, cs_mode)
                for insn in md.disasm(inst_bytes, address):
                    if insn.mnemonic == 'call':
                        call_stack.append(address)
                    elif insn.mnemonic == 'ret' and call_stack:
                        call_stack.pop()
            except Exception:
                pass
        uc.hook_add(1, hook_code)  # 1 = UC_HOOK_CODE
        try:
            uc.emu_start(ADDRESS, ADDRESS + 8)  # Emulate first 8 bytes (may be 1-2 instructions)
        except Exception as e:
            print(f"Unicorn emulation error: {e}")
            # Try to get the address that caused the error
            if hasattr(e, 'exception') and hasattr(e.exception, 'address'):
                print(f"Invalid memory access at address: 0x{e.exception.address:x}")
            elif hasattr(e, 'address'):
                print(f"Invalid memory access at address: 0x{e.address:x}")
            # Print the instruction pointer at the time of the error
            if pe.FILE_HEADER.Machine == 0x14c:
                ip_reg = uc.reg_read(0x20)  # UC_X86_REG_EIP
                print(f"EIP at error: 0x{ip_reg:x}")
            elif pe.FILE_HEADER.Machine == 0x8664:
                ip_reg = uc.reg_read(0x2a)  # UC_X86_REG_RIP
                print(f"RIP at error: 0x{ip_reg:x}")
            # Print the simulated call stack trace
            if call_stack:
                print("Simulated call stack trace:")
                for addr in reversed(call_stack):
                    print(f"  0x{addr:x}")
            else:
                print("Simulated call stack trace: <empty>")
        print("Register state after emulation:")
        for reg in reg_names:
            print(f"{reg_name_map.get(reg, str(reg))}: {uc.reg_read(reg)}")
        # Print stack pointer and top 16 bytes of stack
        if pe.FILE_HEADER.Machine == 0x14c:
            sp_reg = UC_X86_REG_ESP
            sp_name = "ESP"
        elif pe.FILE_HEADER.Machine == 0x8664:
            sp_reg = UC_X86_REG_RSP
            sp_name = "RSP"
        else:
            sp_reg = None
            sp_name = "SP"
        if sp_reg is not None:
            sp_val = uc.reg_read(sp_reg)
            print(f"{sp_name}: 0x{sp_val:x}")
            try:
                stack_bytes = uc.mem_read(sp_val, 16)
                print(f"Top 16 bytes of stack at {sp_name}:", stack_bytes.hex())
            except Exception as e:
                print(f"Could not read stack memory: {e}")


if __name__ == "__main__":
    main()
