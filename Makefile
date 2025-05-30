# Makefile for PE Emulator/Disassembler

.PHONY: help install lint format test build clean export-reqs lock run distclean

help:
	@echo "Common development commands:"
	@echo "  make install      - Install all dependencies using poetry"
	@echo "  make lint         - Run ruff linter on src/"
	@echo "  make format       - Run black code formatter on src/"
	@echo "  make test         - Run pytest on tests/ (if present)"
	@echo "  make build        - Build standalone binary with pyinstaller"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make export-reqs  - Export requirements.txt from poetry"
	@echo "  make lock         - Update poetry.lock file"
	@echo "  make run          - Run the app (for development)"
	@echo "  make distclean    - Remove venv, lock, and build files"

install:
	poetry install

lint:
	poetry run ruff src/

format:
	poetry run black src/

test:
	poetry run pytest || echo 'No tests found.'

build:
	poetry run pyinstaller src/main.py --onefile --name pe-emulator \
		--add-binary "/data/Code/ptool/.venv/lib/python3.13/site-packages/unicorn/lib/libunicorn.so.2:." \
		--hidden-import unicorn.unicorn_py3.arch.intel \
		--hidden-import unicorn.unicorn_py3.arch

clean:
	rm -rf dist build __pycache__ src/__pycache__ *.spec

export-reqs:
	poetry export -f requirements.txt --output requirements.txt --without-hashes

lock:
	poetry lock

run:
	poetry run python src/main.py

distclean: clean
	rm -rf .venv poetry.lock Pipfile.lock requirements.txt
