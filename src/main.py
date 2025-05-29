import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

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


if __name__ == "__main__":
    main()
