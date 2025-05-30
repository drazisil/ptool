# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Molly Draven
# This file is part of the PE Emulator/Disassembler project, licensed under GPLv3.
# See LICENSE file for details.

from typing import Any
import sys
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QPushButton,
    QLabel,
    QFileDialog,
    QTextEdit,
    QHBoxLayout,
    QSpinBox,
    QGroupBox,
    QGridLayout,
    QMessageBox,
)
from pe_analysis import analyze_pe_file, emulate_entry  # type: ignore


class PEToolGUI(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PE Emulator/Disassembler")
        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)

        self.about_btn = QPushButton("About")
        self.about_btn.clicked.connect(self.show_about)
        self.main_layout.addWidget(self.about_btn)

        self.open_btn = QPushButton("Open PE File")
        self.open_btn.clicked.connect(self.open_file)
        self.main_layout.addWidget(self.open_btn)

        # Add disasm bytes selector
        disasm_layout = QHBoxLayout()
        disasm_label = QLabel("Disassembly bytes:")
        self.disasm_spin = QSpinBox()
        self.disasm_spin.setMinimum(1)
        self.disasm_spin.setMaximum(4096)
        self.disasm_spin.setValue(32)
        disasm_layout.addWidget(disasm_label)
        disasm_layout.addWidget(self.disasm_spin)
        self.main_layout.addLayout(disasm_layout)

        self.info_label = QLabel("No file loaded.")
        self.main_layout.addWidget(self.info_label)

        # Register group
        self.reg_group = QGroupBox("Registers")
        self.reg_grid = QGridLayout()
        self.reg_labels: dict[str, QLabel] = {}
        reg_names = ["EAX", "EBX", "ECX", "EDX", "ESP", "RSP"]
        for i, reg in enumerate(reg_names):
            label = QLabel(f"{reg}: N/A")
            self.reg_labels[reg] = label
            self.reg_grid.addWidget(label, i // 2, i % 2)
        self.reg_group.setLayout(self.reg_grid)
        self.main_layout.addWidget(self.reg_group)

        self.start_btn = QPushButton("Start Emulation")
        self.start_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_emulation)
        self.main_layout.addWidget(self.start_btn)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.main_layout.addWidget(self.output)

        self.analysis: dict[str, Any] | None = None

    def open_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open PE File", "", "Executable Files (*.exe);;All Files (*)"
        )
        if not file_path:
            return
        self.info_label.setText(f"Loaded: {file_path}")
        disasm_bytes = self.disasm_spin.value()
        try:
            self.analysis = analyze_pe_file(file_path, disasm_bytes=disasm_bytes)
            out = [
                f"Entry Point: 0x{self.analysis['entry_point_va']:x}\nBase Address: 0x{self.analysis['image_base']:x}\n"
            ]
            out.append("Disassembly at entry point:")
            for i in self.analysis["disasm"]:
                out.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
            self.output.setText("\n".join(out))
            self.start_btn.setEnabled(True)
        except Exception as e:
            self.output.setText(f"Error: {e}")
            self.start_btn.setEnabled(False)

    def start_emulation(self) -> None:
        if not self.analysis:
            self.output.setText("No PE file loaded.")
            return
        try:
            emu = emulate_entry(
                self.analysis["pe"],
                self.analysis["image_base"],
                self.analysis["code"],
                self.analysis["arch"],
                self.analysis["entry_point_va"],
                self.analysis["pe"].sections,
            )
            out = self.output.toPlainText().splitlines()
            if emu["emu_error"]:
                out.append(f"\nUnicorn emulation error: {emu['emu_error']}")
                if hasattr(emu["emu_error"], "address"):
                    out.append(
                        f"Invalid memory access at address: 0x{emu['emu_error'].address:x}"
                    )
                if emu["ip_reg"] is not None:
                    out.append(f"IP at error: 0x{emu['ip_reg']:x}")
                if emu["call_stack"]:
                    out.append("Simulated call stack trace:")
                    for addr in reversed(emu["call_stack"]):
                        out.append(f"  0x{addr:x}")
                else:
                    out.append("Simulated call stack trace: <empty>")
            out.append("\nRegister state after emulation:")
            for reg, val in emu["regs"].items():
                out.append(f"{reg}: {val}")
                if reg in self.reg_labels:
                    self.reg_labels[reg].setText(f"{reg}: {val}")
            # Show ESP/RSP
            (
                self.reg_labels["ESP"].setText(f"ESP: 0x{emu['sp_val']:x}")
                if "ESP" in self.reg_labels
                else None
            )
            (
                self.reg_labels["RSP"].setText(f"RSP: 0x{emu['sp_val']:x}")
                if "RSP" in self.reg_labels
                else None
            )
            out.append(f"{emu['sp_name']}: 0x{emu['sp_val']:x}")
            # Show the IP register
            if emu["ip_reg"] is not None:
                out.append(f"IP: 0x{emu['ip_reg']:x}")
            self.output.setText("\n".join(out))
        except Exception as e:
            self.output.setText(f"Error: {e}")

    def show_about(self) -> None:
        about_text = (
            "<b>PE Emulator/Disassembler</b><br>"
            "Copyright (C) 2025 Molly Draven<br>"
            "<br>"
            "This program is free software: you can redistribute it and/or modify "
            "it under the terms of the GNU General Public License as published by "
            "the Free Software Foundation, either version 3 of the License, or "
            "(at your option) any later version.<br><br>"
            "This program is distributed in the hope that it will be useful, "
            "but WITHOUT ANY WARRANTY; without even the implied warranty of "
            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the "
            "GNU General Public License for more details.<br><br>"
            "You should have received a copy of the GNU General Public License "
            "along with this program.  If not, see <a href='https://www.gnu.org/licenses/'>https://www.gnu.org/licenses/</a>.<br><br>"
            "Contact: molly.crendraven@gmail.com"
        )
        QMessageBox.about(self, "About PE Emulator/Disassembler", about_text)


def main() -> None:
    app = QApplication(sys.argv)
    window = PEToolGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
