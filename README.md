# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 Molly Draven
# This file is part of the PE Emulator/Disassembler project, licensed under GPLv3.
# See LICENSE file for details.

# PE Emulator/Disassembler

This project is a graphical tool for loading, disassembling, and emulating Windows PE (Portable Executable) files. It uses Python, PyQt5 for the GUI, and leverages pefile, capstone, and unicorn for PE parsing, disassembly, and emulation.

## Features
- Load and inspect PE files (.exe)
- Disassemble entry point code (user-selectable byte count)
- Emulate entry point execution and display register/stack state
- Simulated call stack trace on emulation error
- Graphical register display

## Requirements
- Python 3.13 (see Pipfile for version)
- Linux (tested)

## Installation

### 1. Clone the repository
```zsh
git clone <your-repo-url>
cd ptool
```

### 2. Install dependencies using pipenv (recommended)
```zsh
pipenv install
```

Or, to install using requirements.txt:
```zsh
pip install -r requirements.txt
```

## Usage

### Launch the GUI
```zsh
pipenv run python src/main.py
```
Or, if using a virtualenv:
```zsh
python src/main.py
```

### How to use
1. Click **Open PE File** and select a Windows .exe file.
2. Adjust the **Disassembly bytes** spinner to control how many bytes to disassemble at the entry point.
3. The entry point and disassembly will be shown.
4. Click **Start Emulation** to emulate the entry point and view register/stack state and call stack trace.

## Project Structure
- `src/peutils.py` – PE file utilities
- `src/emulator.py` – Unicorn emulation helpers
- `src/pe_analysis.py` – High-level PE analysis and emulation logic
- `src/gui.py` – PyQt5 GUI
- `src/main.py` – Launches the GUI

## Development
- Edit the `Pipfile` to manage dependencies. Run `pipenv lock` and `pipenv requirements > requirements.txt` to update lock and requirements files.
- To run tests (if/when added):
  ```zsh
  pipenv run pytest
  ```

## License
MIT (or specify your license here)