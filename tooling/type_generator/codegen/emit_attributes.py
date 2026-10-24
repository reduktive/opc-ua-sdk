# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit ``ua_attribute_id.h`` (NS0-only).

``AttributeIdEmitter`` is bound to one ``EmitContext`` - kept for
shape parity with other emitters; attribute IDs are spec-global.
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..io import write_file
from .context import EmitContext


class AttributeIdEmitter:
    """Emits the NS0 attribute-id header from ``AttributeIds.csv``."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit(self, attribute_ids_csv: Path) -> Path:
        return emit_attribute_id_header(
            self._ctx.interface_dir_for("ids"), attribute_ids_csv
        )


def emit_attribute_id_header(output_dir: Path, attribute_ids_csv: Path) -> Path:
    """Parse AttributeIds.csv and emit ua_attribute_id.h.

    Returns the path to the generated file.
    """
    entries: list[tuple[str, int]] = []

    with open(attribute_ids_csv, encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            name = row[0].strip()
            try:
                numeric_id = int(row[1].strip())
            except ValueError:
                continue
            if name:
                entries.append((name, numeric_id))

    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    ln("#ifndef UA_ATTRIBUTE_ID_H")
    ln("#define UA_ATTRIBUTE_ID_H")
    ln()
    ln('#include "ua_includes.h"')
    ln()
    ln("namespace ua")
    ln("{")
    ln()
    ln("enum class AttributeId : uint32_t")
    ln("{")
    for i, (name, val) in enumerate(entries):
        comma = "," if i < len(entries) - 1 else ""
        ln(f"  {name} = {val}{comma}")
    ln("};")
    ln()
    ln("}  // namespace ua")
    ln()
    ln("#endif  // UA_ATTRIBUTE_ID_H")

    out_path = output_dir / "ua_attribute_id.h"
    write_file(out_path, "".join(lines))
    return out_path
