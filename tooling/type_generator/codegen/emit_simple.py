# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit ``ua_<snake>.h`` for simple alias DataTypes (UADataType with a parent
but no Definition - typically typedefs like ``UriString``, ``CounterDataType``).
"""

from __future__ import annotations

from pathlib import Path

from ..io import load_template, write_file
from ..naming import get_symbolic_name, to_snake_case
from .context import EmitContext

_NATIVE_MAP: dict[str, str] = {
    "Boolean": "bool",
    "Byte": "uint8_t",
    "SByte": "int8_t",
    "UInt16": "uint16_t",
    "UInt32": "uint32_t",
    "UInt64": "uint64_t",
    "Int16": "int16_t",
    "Int32": "int32_t",
    "Int64": "int64_t",
    "Double": "double",
    "Float": "float",
}


def is_native_type(symbolic_name: str) -> bool:
    return symbolic_name in _NATIVE_MAP


def native_type(symbolic_name: str) -> str:
    return _NATIVE_MAP[symbolic_name]


class SimpleAliasEmitter:
    """Emits one ``<prefix><snake>.h`` per simple alias data type."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit(self, node_id: str) -> Path:
        return _emit_simple_header(self._ctx, node_id)


def _emit_simple_header(ctx: EmitContext, node_id: str) -> Path:
    index = ctx.index
    node = index.find(node_id)
    if node is None:
        raise KeyError(node_id)

    symbolic = get_symbolic_name(node.browse_name)
    header_guard = ctx.header_guard("DATA_TYPE", symbolic)

    parent = index.find(node.parent_node_id or "")
    parent_symbolic = get_symbolic_name(parent.browse_name) if parent is not None else ""

    if parent_symbolic == "BaseDataType":
        # Match C++ generator: BaseDataType is represented as Variant in generated C++.
        base_class_name = "Variant"
        include_base = '#include "ua_variant.h"'
    elif parent_symbolic and is_native_type(parent_symbolic):
        base_class_name = native_type(parent_symbolic)
        include_base = ""
    elif parent_symbolic:
        # Cross-spec safe: the resolver picks the right header from
        # whichever spec owns the parent (NS0 ``ua_<snake>.h``, DI
        # ``ua_di_<snake>.h``, etc.).  In-spec parents resolve to
        # ``ctx``'s own prefix; bare class name is correct for the
        # local namespace.
        parent_ref = ctx.resolver.resolve(parent.node_id) if parent else None
        base_class_name = parent_ref.qualified_class_name if parent_ref else parent_symbolic
        include_base = (
            f'#include "{parent_ref.header_include}"' if parent_ref else ""
        )
    else:
        base_class_name = ""
        include_base = ""

    text = ctx.apply_template(load_template("simple_header.in"))
    text = text.replace(
        "PLACEHOLDER_DOC",
        ctx.doc_comment(f"OPC UA {symbolic} simple data type.", "ua_data_types"),
    )
    text = text.replace("PLACEHOLDER_HEADER_GUARD", header_guard)
    text = text.replace("PLACEHOLDER_INCLUDE_BASE_CLASS", include_base)
    text = text.replace("PLACEHOLDER_CLASS_NAME", symbolic)
    text = text.replace("PLACEHOLDER_BASE_CLASS_NAME", base_class_name)

    out_path = ctx.interface_dir / ctx.header_file_name(symbolic)
    write_file(out_path, text)
    return out_path
