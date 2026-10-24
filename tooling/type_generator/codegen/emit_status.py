# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit ``ua_status.h``, ``ua_status_to_string.{h,cpp}`` (NS0-only).

``StatusCodeEmitter`` is bound to one ``EmitContext`` - kept for shape
parity with the other emitters even though status codes are
spec-global.  Downstream specs do not invoke this emitter.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import List, Tuple

from ..io import write_file
from .context import EmitContext


class StatusCodeEmitter:
    """Emits the NS0 status-code header + ``to_string`` helpers."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit_header(self, statuscode_csv: Path) -> Path:
        return emit_status_header(self._ctx.interface_dir_for("status"), statuscode_csv)

    def emit_to_string_header(self, statuscode_csv: Path) -> Path:
        return emit_status_to_string_header(
            self._ctx.interface_dir_for("status"), statuscode_csv
        )

    def emit_to_string_source(self, statuscode_csv: Path) -> Path:
        return emit_status_to_string_source(
            self._ctx.implementation_dir_for("status"), statuscode_csv
        )


def _parse_status_csv(statuscode_csv: Path) -> List[Tuple[str, int, str]]:
    """Parse StatusCode.csv and return sorted (name, code, description) triples.

    The third CSV column holds the human description for each status code; it is
    threaded through so the generated enumerators can carry a ``///<`` brief.
    Codes with no description yield an empty string (the caller leaves them bare).
    """
    entries: list[tuple[str, int, str]] = []

    with open(statuscode_csv, encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            symbolic_name = row[0].strip()
            hex_code_str = row[1].strip()
            if not symbolic_name or not hex_code_str:
                continue
            try:
                code_value = int(hex_code_str, 16)
            except ValueError:
                continue
            description = row[2].strip() if len(row) >= 3 else ""
            entries.append((symbolic_name, code_value, description))

    entries.sort(key=lambda x: x[1])
    return entries


def emit_status_header(output_dir: Path, statuscode_csv: Path) -> Path:
    """Parse StatusCode.csv and emit ua_status.h.

    Returns the path to the generated file.
    """
    entries = _parse_status_csv(statuscode_csv)

    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    ln("#ifndef UA_STATUS_H")
    ln("#define UA_STATUS_H")
    ln()
    # ua_includes.h includes ua_exceptions.h, which includes this header: the enum needs only the fixed-width
    # integers, so a file that includes this header first compiles.
    ln("#include <cstdint>")
    ln()
    ln("namespace ua")
    ln("{")
    ln()
    ln("/// OPC UA status-code constants.")
    ln("/// @ingroup ua_node_ids")
    ln("enum class Status : uint32_t")
    ln("{")
    for i, (name, val, description) in enumerate(entries):
        comma = "," if i < len(entries) - 1 else ""
        # Each enumerator carries the StatusCode.csv description as a trailing
        # ///< brief, which also resolves @ref Status::BadXxx links elsewhere.
        # Codes with no CSV description are left bare (no placeholder).
        doc = f"  ///< {description}" if description else ""
        ln(f"  {name} = 0x{val:08X}U{comma}{doc}")
    ln("};")
    ln()
    ln("}  // namespace ua")
    ln()
    ln("#endif  // UA_STATUS_H")

    out_path = output_dir / "ua_status.h"
    write_file(out_path, "".join(lines))
    return out_path


def emit_status_to_string_header(output_dir: Path, statuscode_csv: Path) -> Path:
    """Emit ua_status_to_string.h with declaration of to_string(Status)."""
    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    ln("// Auto-generated - do not edit.")
    ln("#ifndef UA_STATUS_TO_STRING_H")
    ln("#define UA_STATUS_TO_STRING_H")
    ln()
    ln("#include <string>")
    ln("#include <string_view>")
    ln('#include "ua_status.h"')
    ln()
    ln("namespace ua")
    ln("{")
    ln()
    ln("std::string to_string(Status status);")
    ln()
    ln("/// The specification's description of @p status (OPC Foundation StatusCode.csv), or empty for a")
    ln("/// code the table does not know. Fixed, public text: safe to send to a peer.")
    ln("std::string_view description(Status status);")
    ln()
    ln("}  // namespace ua")
    ln()
    ln("#endif  // UA_STATUS_TO_STRING_H")

    out_path = output_dir / "ua_status_to_string.h"
    write_file(out_path, "".join(lines))
    return out_path


def emit_status_to_string_source(output_dir: Path, statuscode_csv: Path) -> Path:
    """Emit ua_status_to_string.cpp with a sorted lookup table and binary search."""
    entries = _parse_status_csv(statuscode_csv)

    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    ln("// Auto-generated - do not edit.")
    ln('#include "ua_includes.h"')
    ln('#include "ua_status_to_string.h"')
    ln('#include "ua_utilities.h"')
    ln()
    ln("#include <algorithm>")
    ln("#include <string_view>")
    ln()
    ln('#include "fmt/format.h"')
    ln()
    ln("namespace ua")
    ln("{")
    ln()
    ln("namespace")
    ln("{")
    ln()
    ln("struct StatusEntry")
    ln("{")
    ln("  uint32_t code;")
    ln("  std::string_view name;")
    ln("  std::string_view description;")
    ln("};")
    ln()
    ln(f"constexpr StatusEntry sTable[] = {{")
    for name, val, description in entries:
        escaped = description.replace("\\", "\\\\").replace('"', '\\"')
        ln(f'    {{0x{val:08X}U, "{name}", "{escaped}"}},')
    ln("};")
    ln()
    ln("const StatusEntry* find_entry(Status status)")
    ln("{")
    ln("  auto code = utils::to_underlying(status);")
    ln("  auto it = std::lower_bound(std::begin(sTable), std::end(sTable), code,")
    ln("    [](const StatusEntry& entry, uint32_t value) { return entry.code < value; });")
    ln("  return it != std::end(sTable) && it->code == code ? it : nullptr;")
    ln("}")
    ln()
    ln("}  // namespace")
    ln()
    ln("std::string to_string(Status status)")
    ln("{")
    ln("  if (const auto* entry = find_entry(status))")
    ln("  {")
    ln("    return std::string{entry->name};")
    ln("  }")
    ln('  return fmt::format("Unknown(0x{:08X})", utils::to_underlying(status));')
    ln("}")
    ln()
    ln("std::string_view description(Status status)")
    ln("{")
    ln("  const auto* entry = find_entry(status);")
    ln("  return entry != nullptr ? entry->description : std::string_view{};")
    ln("}")
    ln()
    ln("}  // namespace ua")

    out_path = output_dir / "ua_status_to_string.cpp"
    write_file(out_path, "".join(lines))
    return out_path
