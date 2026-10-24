# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

from pathlib import Path
import glob
import os
import shutil
import subprocess

# Default: use the repo-root .clang-format (two directories up from this file's parent).
_DEFAULT_CLANG_FORMAT = Path(__file__).resolve().parent.parent.parent / ".clang-format"

# clang-format's lambda/brace handling changed between major versions, so the
# generated-code-freshness gate is only meaningful when the binary is pinned to
# the version the committed files were formatted with (currently 18). Honour a
# CLANG_FORMAT override so CI and the dev box can point at a pinned binary; fall
# back to the PATH `clang-format` for local convenience.
_CLANG_FORMAT_BIN = os.environ.get("CLANG_FORMAT", "clang-format")

# Module-level override, set from CLI via set_clang_format_config().
_clang_format_config: Path | None = None


def set_clang_format_config(path: Path | None) -> None:
    """Set the .clang-format config file path for all subsequent formatting calls."""
    global _clang_format_config
    _clang_format_config = path


def _resolve_config() -> Path:
    if _clang_format_config is not None and _clang_format_config.exists():
        return _clang_format_config
    return _DEFAULT_CLANG_FORMAT


def clang_format_directory(output_dir: Path) -> None:
    """Run `clang-format` on generated files in `output_dir`.

    Copies the .clang-format config into the output directory temporarily,
    runs clang-format, then removes the copy.
    """
    clang_format_src = _resolve_config()
    clang_format_dst = output_dir / ".clang-format"

    if not clang_format_src.exists():
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        shutil.copyfile(clang_format_src, clang_format_dst)

        header_files = [Path(p) for p in glob.glob(str(output_dir / "*.h"))]
        source_files = [Path(p) for p in glob.glob(str(output_dir / "*.cpp"))]

        if header_files:
            subprocess.run(
                [_CLANG_FORMAT_BIN, "-i", *[str(p) for p in header_files]],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if source_files:
            subprocess.run(
                [_CLANG_FORMAT_BIN, "-i", *[str(p) for p in source_files]],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except FileNotFoundError:
        # clang-format missing
        return
    finally:
        try:
            clang_format_dst.unlink(missing_ok=True)
        except Exception:
            pass
