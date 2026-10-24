#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Cross-platform bootstrap for the OPC-UA type generator.

Creates a virtual environment (if needed), installs dependencies, and
invokes a tooling submodule.  Works on Linux, macOS, and Windows with
any Python >= 3.9.

Usage (generation - the default)::

    python3 tooling/type_generator/run_type_generator.py --manifest <file> --output <dir>

Usage (alternate submodule, e.g. manifest synthesis)::

    python3 tooling/type_generator/run_type_generator.py \\
        --py-module tooling.type_generator.synthesise_manifest \\
        --out <file> ...

``--py-module`` consumes its argument before any other flag and selects
which submodule to run.  Everything after it is forwarded verbatim.

The virtual environment is placed at ``.venv-typegen`` in the
repository root.
"""

# The local ``types/`` package shadows the stdlib ``types`` module.
# Remove this script's directory from sys.path before importing anything else.
import sys as _sys

_script_dir_str = __import__("os").path.dirname(__import__("os").path.abspath(__file__))
if _sys.path and __import__("os").path.abspath(_sys.path[0]) == _script_dir_str:
    _sys.path.pop(0)

import platform
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
VENV_DIR = REPO_ROOT / ".venv-typegen"
REQ_FILE = SCRIPT_DIR / "requirements.txt"


def _venv_python() -> Path:
    if platform.system() == "Windows":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _ensure_venv() -> Path:
    python = _venv_python()
    if not python.exists():
        print(f"Creating virtual environment in {VENV_DIR} ...", file=_sys.stderr)
        subprocess.check_call([_sys.executable, "-m", "venv", str(VENV_DIR)])
    return python


def _ensure_deps(python: Path) -> None:
    subprocess.check_call(
        [str(python), "-m", "pip", "install", "-q", "-r", str(REQ_FILE)],
        stdout=subprocess.DEVNULL,
    )


_DEFAULT_MODULE = "tooling.type_generator"


def _pop_module_arg(argv: list[str]) -> tuple[str, list[str]]:
    """Strip a leading ``--py-module <name>`` pair, if present."""
    if len(argv) >= 2 and argv[0] == "--py-module":
        return argv[1], argv[2:]
    return _DEFAULT_MODULE, argv


def main() -> int:
    module, forwarded = _pop_module_arg(_sys.argv[1:])

    python = _ensure_venv()
    _ensure_deps(python)

    result = subprocess.run(
        [str(python), "-m", module] + forwarded,
        cwd=str(REPO_ROOT),
    )
    return result.returncode


if __name__ == "__main__":
    _sys.exit(main())
