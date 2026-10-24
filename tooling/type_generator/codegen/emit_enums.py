# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit headers + aggregated helpers for enum and option-set data types.

Two emitter classes - ``EnumEmitter`` and ``OptionSetEmitter`` - share the
field-aggregation helper since both walk the same parent-chain pattern.
Each is bound to one ``EmitContext`` and emits both the per-type header
and the spec-level aggregated helpers source.
"""

from __future__ import annotations

from pathlib import Path

from ..io import load_template, write_file
from ..naming import clean_brief_text, cpp_identifier, get_symbolic_name
from ..nodeset.index import NodeSetIndex
from .context import EmitContext


# --- Shared helpers --------------------------------------------------------


def _aggregate_definition_fields(
    index: NodeSetIndex, node_id: str
) -> list[tuple[str, int, str | None]]:
    """Return `(name, value, description)` enum/bit fields aggregated across inheritance.

    Mirrors the C++ `aggregate_fields()` approach: walk parent chain and prepend.
    `description` is the field's NodeSet `<Description>` text, or `None`.
    """

    result: list[tuple[str, int, str | None]] = []
    visited: set[str] = set()
    current = node_id
    while current and current not in visited:
        visited.add(current)
        node = index.find(current)
        if node is None:
            break

        if node.definition is not None:
            fields: list[tuple[str, int, str | None]] = []
            for f in node.definition.fields:
                if f.value is None:
                    continue
                fields.append(
                    (cpp_identifier(f.name, f.symbolic_name), int(f.value), f.description)
                )
            result = fields + result

        current = node.parent_node_id or ""

    return result


def _is_contiguous(fields: list[tuple[str, int, str | None]]) -> bool:
    if not fields:
        return True
    values = sorted(v for _, v, _ in fields)
    return values == list(range(values[0], values[0] + len(values)))


def _build_to_string_body(symbolic: str, fields: list[tuple[str, int, str | None]]) -> list[str]:
    lines: list[str] = []
    lines.append(f"std::string to_string({symbolic} value)")
    lines.append("{")
    lines.append("  switch (value)")
    lines.append("  {")
    for name, value, _ in fields:
        lines.append(f"  case {symbolic}::{name}:")
        lines.append(f'    return "{name}";')
    lines.append("  default:")
    lines.append(f'    return "{symbolic}(" + std::to_string(utils::to_underlying(value)) + ")";')
    lines.append("  }")
    lines.append("}")
    return lines


def _build_is_valid_body(symbolic: str, fields: list[tuple[str, int, str | None]]) -> list[str]:
    lines: list[str] = []
    lines.append(f"bool is_valid({symbolic} value)")
    lines.append("{")

    if not fields:
        lines.append("  UA_UNUSED(value);")
        lines.append("  return false;")
    elif _is_contiguous(fields):
        values = sorted(v for _, v, _ in fields)
        min_val = values[0]
        max_val = values[-1]
        lines.append(f"  auto v = utils::as_int32(value);")
        lines.append(f"  return v >= {min_val} && v <= {max_val};")
    else:
        lines.append("  switch (value)")
        lines.append("  {")
        for name, _, _ in fields:
            lines.append(f"  case {symbolic}::{name}:")
        lines.append("    return true;")
        lines.append("  default:")
        lines.append("    return false;")
        lines.append("  }")

    lines.append("}")
    return lines


# --- Enum emitter ----------------------------------------------------------


class EnumEmitter:
    """Emits one ``<prefix><snake>.h`` per UAEnum + a per-spec helpers source."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit_header(self, node_id: str) -> Path:
        return _emit_enum_header(self._ctx, node_id)

    def emit_helpers_source(
        self,
        node_ids_in_order: list[str],
        headers_in_order: list[str],
    ) -> Path:
        return _emit_enum_helpers_cpp(
            self._ctx, node_ids_in_order, headers_in_order
        )


def _emit_enum_header(ctx: EmitContext, node_id: str) -> Path:
    index = ctx.index
    node = index.find(node_id)
    if node is None:
        raise KeyError(node_id)

    symbolic = get_symbolic_name(node.browse_name)
    header_guard = ctx.header_guard("DATA_TYPE", symbolic)

    fields = _aggregate_definition_fields(index, node_id)
    values_lines = [
        f"  {name} = {value},  ///< {clean_brief_text(desc)}" if desc else f"  {name} = {value},"
        for name, value, desc in fields
    ]
    values = "\n".join(values_lines)
    if values.endswith(","):
        values = values[:-1]

    to_string_decl = (
        f"/// Converts an enumerator to its name.\n"
        f"/// @param value The enumerator to name.\n"
        f"/// @return The enumerator's name, or a numeric fallback if unrecognised.\n"
        f"std::string to_string({symbolic} value);"
    )
    is_valid_decl = (
        f"/// Tests whether a value is a defined enumerator.\n"
        f"/// @param value The value to check.\n"
        f"/// @return `true` if `value` is a defined enumerator of {symbolic}.\n"
        f"bool is_valid({symbolic} value);"
    )

    text = ctx.apply_template(load_template("enum_header.in"))
    text = text.replace(
        "PLACEHOLDER_DOC",
        ctx.doc_comment(f"OPC UA {symbolic} enumeration data type.", "ua_data_types"),
    )
    text = text.replace("PLACEHOLDER_HEADER_GUARD", header_guard)
    text = text.replace("PLACEHOLDER_CLASS_NAME", symbolic)
    text = text.replace("PLACEHOLDER_VALUES", values)
    text = text.replace("PLACEHOLDER_TO_STRING_DECLARATION", to_string_decl)
    text = text.replace("PLACEHOLDER_IS_VALID_DECLARATION", is_valid_decl)
    text = text.replace("PLACEHOLDER_CPP_NAMESPACE", ctx.cpp_namespace)

    out_path = ctx.interface_dir / ctx.header_file_name(symbolic)
    write_file(out_path, text)
    return out_path


def _emit_enum_helpers_cpp(
    ctx: EmitContext,
    node_ids_in_order: list[str],
    headers_in_order: list[str],
) -> Path:
    """Aggregated ``<prefix>enum_helpers.cpp`` - to_string + is_valid."""

    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    seen: set[str] = set()
    for h in headers_in_order:
        if h not in seen:
            seen.add(h)
            ln(f'#include "{h}"')
    ln('#include "ua_utilities.h"')
    ln()
    ln(ctx.cpp_namespace_open())
    ln()

    for node_id in node_ids_in_order:
        node = ctx.index.find(node_id)
        if node is None:
            continue
        symbolic = get_symbolic_name(node.browse_name)
        fields = _aggregate_definition_fields(ctx.index, node_id)

        for line in _build_to_string_body(symbolic, fields):
            ln(line)
        ln()

        for line in _build_is_valid_body(symbolic, fields):
            ln(line)
        ln()

    ln(ctx.cpp_namespace_close())

    out_path = ctx.implementation_dir / f"{ctx.include_prefix}enum_helpers.cpp"
    write_file(out_path, "".join(lines))
    return out_path


# --- OptionSet emitter -----------------------------------------------------


class OptionSetEmitter:
    """Emits one ``<prefix><snake>.h`` per UAOptionSet + a per-spec helpers source."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit_header(self, node_id: str) -> Path:
        return _emit_optionset_header(self._ctx, node_id)

    def emit_helpers_source(
        self,
        node_ids_in_order: list[str],
        headers_in_order: list[str],
    ) -> Path:
        return _emit_optionset_helpers_cpp(
            self._ctx, node_ids_in_order, headers_in_order
        )


def _emit_optionset_header(ctx: EmitContext, node_id: str) -> Path:
    index = ctx.index
    node = index.find(node_id)
    if node is None:
        raise KeyError(node_id)

    symbolic = get_symbolic_name(node.browse_name)
    header_guard = ctx.header_guard("DATA_TYPE", symbolic)

    parent = index.find(node.parent_node_id or "")
    parent_symbolic = get_symbolic_name(parent.browse_name) if parent is not None else ""
    native_map = {
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
    underlying = native_map.get(parent_symbolic, parent_symbolic)

    bits = _aggregate_definition_fields(index, node_id)

    # Some option sets (common in companion specs) subtype the abstract
    # ``OptionSet`` base directly rather than a concrete integer type, so the
    # parent gives no usable C++ underlying type. Pick the smallest standard
    # unsigned integer that holds every declared bit position. NS0 option sets
    # subtype a concrete integer (e.g. UInt16), so ``underlying`` is already a
    # native type and this fallback is not taken - output stays byte-identical.
    if underlying not in native_map.values():
        max_bit = max((value for _name, value, _ in bits), default=0)
        underlying = (
            "uint8_t" if max_bit < 8
            else "uint16_t" if max_bit < 16
            else "uint32_t" if max_bit < 32
            else "uint64_t"
        )

    bits_lines = [
        f"{name} = {value},  ///< {clean_brief_text(desc)}" if desc else f"{name} = {value},"
        for name, value, desc in bits
    ]
    bits_text = "\n    ".join(bits_lines)
    if bits_text.endswith(","):
        bits_text = bits_text[:-1]

    to_string_decl = (
        f"/// Formats an option set as a brace-listed string of its set bits.\n"
        f"/// @param value The option set to format.\n"
        f"/// @return A brace-listed string of the names of the set bits.\n"
        f"std::string to_string(const {symbolic}& value);"
    )

    text = ctx.apply_template(load_template("optionset_header.in"))
    text = text.replace(
        "PLACEHOLDER_DOC",
        ctx.doc_comment(
            f"OPC UA {symbolic} option-set (bit mask) data type.", "ua_data_types"
        ),
    )
    text = text.replace("PLACEHOLDER_HEADER_GUARD", header_guard)
    text = text.replace("PLACEHOLDER_CLASS_NAME", symbolic)
    text = text.replace("PLACEHOLDER_UNDERLYING_TYPE", underlying)
    text = text.replace("PLACEHOLDER_BITS", bits_text)
    text = text.replace("PLACEHOLDER_TO_STRING_DECLARATION", to_string_decl)

    out_path = ctx.interface_dir / ctx.header_file_name(symbolic)
    write_file(out_path, text)
    return out_path


def _emit_optionset_helpers_cpp(
    ctx: EmitContext,
    node_ids_in_order: list[str],
    headers_in_order: list[str],
) -> Path:
    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    seen: set[str] = set()
    for h in headers_in_order:
        if h not in seen:
            seen.add(h)
            ln(f'#include "{h}"')
    ln()
    ln("#include <string>")
    ln("#include <string_view>")
    ln("#include <vector>")
    ln()
    ln(ctx.cpp_namespace_open())
    ln()

    for node_id in node_ids_in_order:
        node = ctx.index.find(node_id)
        if node is None:
            continue
        symbolic = get_symbolic_name(node.browse_name)
        bits = _aggregate_definition_fields(ctx.index, node_id)

        # Collect the set bit-names first, then join with ", ". This deliberately avoids the
        # `bool first` separator idiom: that pattern makes the first flag's `if (!first)` a provably-
        # false condition and the last flag's `first = false` a dead store, which the static analyzers
        # (cppcheck knownConditionTrueFalse / unreadVariable, clang-analyzer deadcode.DeadStores) flag
        # on every generated to_string. The index-guarded join has no constant condition and no dead
        # store.
        ln(f"std::string to_string(const {symbolic}& value)")
        ln("{")
        ln("  std::vector<std::string_view> parts;")
        for name, value, _ in bits:
            ln(f"  if (value.test({symbolic}::Bit::{name}))")
            ln("  {")
            ln(f'    parts.push_back("{name}");')
            ln("  }")
        ln(f'  std::string result = "{symbolic}{{";')
        ln("  for (std::size_t i = 0; i < parts.size(); ++i)")
        ln("  {")
        ln("    if (i != 0)")
        ln("    {")
        ln('      result += ", ";')
        ln("    }")
        ln("    result += parts[i];")
        ln("  }")
        ln('  result += "}";')
        ln("  return result;")
        ln("}")
        ln()

    ln(ctx.cpp_namespace_close())

    out_path = ctx.implementation_dir / f"{ctx.include_prefix}optionset_helpers.cpp"
    write_file(out_path, "".join(lines))
    return out_path
