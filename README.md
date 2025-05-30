<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2025 Molly Draven
This file is part of the PE Emulator/Disassembler project, licensed under GPLv3.
See LICENSE file for details.
-->

# PE Emulator/Disassembler

A graphical tool for loading, disassembling, and emulating Windows PE (Portable Executable) files. Built with Python, PyQt5, pefile, capstone, and unicorn.

## Features
- Load and inspect PE files (.exe)
- Disassemble entry point code (user-selectable byte count)
- Emulate entry point execution and display register/stack state
- Simulated call stack trace on emulation error
- Graphical register display
- GPLv3 licensed, with About box and full compliance

## Requirements
- Python 3.13+
- Linux (tested)

## Setup

### 1. Clone the repository
```zsh
git clone https://github.com/drazisil/ptool.git
cd ptool
```

### 2. Install dependencies (choose one)
#### Using Poetry (recommended)
```zsh
poetry install
```

## Usage

### Launch the GUI
#### With Poetry
```zsh
poetry run python src/main.py
```

### How to use the application
1. Click **Open PE File** and select a Windows .exe file.
2. Adjust the **Disassembly bytes** spinner to control how many bytes to disassemble at the entry point.
3. The entry point and disassembly will be shown.
4. Click **Start Emulation** to emulate the entry point and view register/stack state and call stack trace.
5. Click **About** for license and contact information.

## Building a Standalone Binary

To build a standalone binary (Linux):
```zsh
make build
# or, manually:
poetry run pyinstaller src/main.py --onefile --name pe-emulator \
  --add-binary "/data/Code/ptool/.venv/lib/python3.13/site-packages/unicorn/lib/libunicorn.so.2:."
```
The binary will be in the `dist/` directory as `pe-emulator`.

## Project Structure

- `src/peutils.py` – PE file utilities
- `src/emulator.py` – Unicorn emulation helpers
- `src/pe_analysis.py` – High-level PE analysis and emulation logic
- `src/gui.py` – PyQt5 GUI
- `src/main.py` – Launches the GUI
- `Makefile` – Common development tasks (install, lint, format, test, build, clean)
- `pyproject.toml` – Poetry/packaging configuration
- `requirements.txt`, `Pipfile` – Exported dependency lists
- `LICENSE`, `COPYING` – License information

## Development

- Edit `pyproject.toml` (or `Pipfile`) to manage dependencies.
- Run `make install` or `poetry install` to set up your environment.
- Use `make lint`, `make format`, `make test`, and `make build` for common tasks.
- To run tests (if/when added):
  ```zsh
  poetry run pytest
  # or
  pipenv run pytest
  ```

## License
This project is licensed under the GNU GPLv3. See the COPYING or LICENSE file for details.

The About box in the GUI provides license and contact information as required by the GPL.
