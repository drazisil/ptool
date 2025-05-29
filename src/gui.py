import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit
)
from peutils import load_pe, get_entry_info, disassemble_entry
from emulator import setup_unicorn, add_call_stack_hook
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_RSP

class PEToolGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PE Emulator/Disassembler")
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.open_btn = QPushButton("Open PE File")
        self.open_btn.clicked.connect(self.open_file)
        self.layout.addWidget(self.open_btn)

        self.info_label = QLabel("No file loaded.")
        self.layout.addWidget(self.info_label)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.layout.addWidget(self.output)

    def open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PE File", "", "Executable Files (*.exe);;All Files (*)")
        if not file_path:
            return
        self.info_label.setText(f"Loaded: {file_path}")
        try:
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
                self.output.setText("Entry point not in any section!")
                return
            entry_offset = (entry_point_va - code_section.VirtualAddress - image_base) + code_section.PointerToRawData
            code = data[entry_offset:entry_offset+32]
            disasm = disassemble_entry(code, entry_point_va, arch)
            out = [f"Entry Point: 0x{entry_point_va:x}\nBase Address: 0x{image_base:x}\n"]
            out.append("Disassembly at entry point:")
            for i in disasm:
                out.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
            # Emulation
            uc = setup_unicorn(pe, image_base, code, pe.sections, arch)
            call_stack = []
            add_call_stack_hook(uc, pe, arch, call_stack)
            try:
                uc.emu_start(entry_point_va, entry_point_va + 8)
            except Exception as e:
                out.append(f"\nUnicorn emulation error: {e}")
                if hasattr(e, 'address'):
                    out.append(f"Invalid memory access at address: 0x{e.address:x}")
                if arch == 'x86':
                    ip_reg = uc.reg_read(0x20)
                    out.append(f"EIP at error: 0x{ip_reg:x}")
                else:
                    ip_reg = uc.reg_read(0x2a)
                    out.append(f"RIP at error: 0x{ip_reg:x}")
                if call_stack:
                    out.append("Simulated call stack trace:")
                    for addr in reversed(call_stack):
                        out.append(f"  0x{addr:x}")
                else:
                    out.append("Simulated call stack trace: <empty>")
            out.append("\nRegister state after emulation:")
            reg_name_map = {
                UC_X86_REG_EAX: "EAX",
                UC_X86_REG_EBX: "EBX",
                UC_X86_REG_ECX: "ECX",
                UC_X86_REG_EDX: "EDX"
            }
            reg_names = [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX]
            for reg in reg_names:
                out.append(f"{reg_name_map.get(reg, str(reg))}: {uc.reg_read(reg)}")
            if arch == 'x86':
                sp_val = uc.reg_read(UC_X86_REG_ESP)
                out.append(f"ESP: 0x{sp_val:x}")
            else:
                sp_val = uc.reg_read(UC_X86_REG_RSP)
                out.append(f"RSP: 0x{sp_val:x}")
            self.output.setText("\n".join(out))
        except Exception as e:
            self.output.setText(f"Error: {e}")

def main():
    app = QApplication(sys.argv)
    window = PEToolGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
