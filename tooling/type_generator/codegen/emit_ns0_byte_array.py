# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit the NS0 NodeSet2.xml as a compiled-in byte array (NS0-only).

The NS0 byte array is used by ``AddressSpace`` to bootstrap the
standard namespace at server startup without parsing XML at runtime.
NS0-only by construction: downstream specs load their own NodeSets at
runtime through the import API.

``Ns0ByteArrayEmitter`` exists for shape parity with the other
emitters.
"""

from __future__ import annotations

from pathlib import Path

from ..io import write_file
from .context import EmitContext


class Ns0ByteArrayEmitter:
    """Emits ``nodeset_ns0.h`` + ``nodeset_ns0.cpp`` (NS0-only)."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit(self, nodeset_xml_path: Path) -> tuple[Path, Path]:
        return emit_ns0_byte_array(
            self._ctx.interface_dir_for("ns0"),
            self._ctx.implementation_dir_for("ns0"),
            nodeset_xml_path,
        )


def emit_ns0_byte_array(
    interface_dir: Path,
    implementation_dir: Path,
    nodeset_xml_path: Path,
) -> tuple[Path, Path]:
    """Read a NodeSet XML file and emit a C++ header + source with hex byte array.

    Returns (header_path, source_path).
    """
    # Append the NUL byte rapidxml uses as its end sentinel, and emit the array as `const`. The
    # `const` is what lets the linker place the 4 MB NS0 image in `.rodata` (clean, file-backed,
    # demand-paged, shareable) instead of `.data` (dirty, private, resident for process life). The
    # trailing NUL lets the importer parse this buffer in place with rapidxml's non-destructive mode
    # (no terminator insertion, no in-place entity expansion), so the source is never written and the
    # transient heap copy can be skipped.
    data = nodeset_xml_path.read_bytes() + b"\x00"
    size = len(data)
    array_name = "nodesetNs0"

    # Header
    header = (
        f"#include <array>\n"
        f"\n"
        f"namespace ua\n"
        f"{{\n"
        f"\n"
        f"extern const std::array<char, {size}> {array_name};\n"
        f"\n"
        f"}}\n"
    )
    header_path = interface_dir / "nodeset_ns0.h"
    write_file(header_path, header)

    # Source - emit hex bytes, 17 per line (matching the original C++ tool's behavior:
    # first byte on its own conceptual line, then wrap every 16 bytes)
    parts: list[str] = []
    parts.append("#include <array>\n\nnamespace ua\n{\n\n")
    # `extern` is required: a namespace-scope `const` has internal linkage by default, so without it
    # this definition would not satisfy the `extern const` declaration in the header (link error).
    # `extern const` keeps the array read-only (.rodata) while giving it external linkage.
    parts.append(f"extern const std::array<char, {size}> {array_name} =\n{{\n")

    for i, b in enumerate(data):
        parts.append(f"0x{b:02x}")
        if i < size - 1:
            parts.append(", ")
            # The original C++ tool wraps after byte index i when (i != 0) and (i % 16 == 0).
            if i != 0 and i % 16 == 0:
                parts.append("\n")

    parts.append("\n};\n\n}\n")

    source_path = implementation_dir / "nodeset_ns0.cpp"
    write_file(source_path, "".join(parts))

    return header_path, source_path
