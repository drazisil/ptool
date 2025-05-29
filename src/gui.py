import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit, QHBoxLayout, QSpinBox
)
from pe_analysis import analyze_pe_file, emulate_entry

class PEToolGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PE Emulator/Disassembler")
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.open_btn = QPushButton("Open PE File")
        self.open_btn.clicked.connect(self.open_file)
        self.layout.addWidget(self.open_btn)

        # Add disasm bytes selector
        disasm_layout = QHBoxLayout()
        disasm_label = QLabel("Disassembly bytes:")
        self.disasm_spin = QSpinBox()
        self.disasm_spin.setMinimum(1)
        self.disasm_spin.setMaximum(4096)
        self.disasm_spin.setValue(32)
        disasm_layout.addWidget(disasm_label)
        disasm_layout.addWidget(self.disasm_spin)
        self.layout.addLayout(disasm_layout)

        self.info_label = QLabel("No file loaded.")
        self.layout.addWidget(self.info_label)

        self.start_btn = QPushButton("Start Emulation")
        self.start_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_emulation)
        self.layout.addWidget(self.start_btn)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.layout.addWidget(self.output)

        self.analysis = None

    def open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PE File", "", "Executable Files (*.exe);;All Files (*)")
        if not file_path:
            return
        self.info_label.setText(f"Loaded: {file_path}")
        disasm_bytes = self.disasm_spin.value()
        try:
            self.analysis = analyze_pe_file(file_path, disasm_bytes=disasm_bytes)
            out = [f"Entry Point: 0x{self.analysis['entry_point_va']:x}\nBase Address: 0x{self.analysis['image_base']:x}\n"]
            out.append("Disassembly at entry point:")
            for i in self.analysis['disasm']:
                out.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
            self.output.setText("\n".join(out))
            self.start_btn.setEnabled(True)
        except Exception as e:
            self.output.setText(f"Error: {e}")
            self.start_btn.setEnabled(False)

    def start_emulation(self):
        if not self.analysis:
            self.output.setText("No PE file loaded.")
            return
        try:
            emu = emulate_entry(
                self.analysis['pe'], self.analysis['image_base'], self.analysis['code'], self.analysis['arch'],
                self.analysis['entry_point_va'], self.analysis['pe'].sections
            )
            out = self.output.toPlainText().splitlines()
            if emu['emu_error']:
                out.append(f"\nUnicorn emulation error: {emu['emu_error']}")
                if hasattr(emu['emu_error'], 'address'):
                    out.append(f"Invalid memory access at address: 0x{emu['emu_error'].address:x}")
                if emu['ip_reg'] is not None:
                    out.append(f"{emu['sp_name']} at error: 0x{emu['ip_reg']:x}")
                if emu['call_stack']:
                    out.append("Simulated call stack trace:")
                    for addr in reversed(emu['call_stack']):
                        out.append(f"  0x{addr:x}")
                else:
                    out.append("Simulated call stack trace: <empty>")
            out.append("\nRegister state after emulation:")
            for reg, val in emu['regs'].items():
                out.append(f"{reg}: {val}")
            out.append(f"{emu['sp_name']}: 0x{emu['sp_val']:x}")
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
