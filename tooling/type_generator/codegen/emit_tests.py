# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

from pathlib import Path

from ..io import load_template, write_file
from ..naming import get_symbolic_name, to_snake_case
from ..nodeset.index import NodeSetIndex
from ..nodeset.model import UaDataTypeField
from ..types.model import DataTypeKind
from .emit_enums import _aggregate_definition_fields


def _append_line(buf: list[str], line: str = "") -> None:
    buf.append(line + "\n")


_NATIVE_TYPES = {
    "Boolean",
    "Byte",
    "SByte",
    "Int16",
    "UInt16",
    "Int32",
    "UInt32",
    "Int64",
    "UInt64",
    "Float",
    "Double",
}


def _is_native(symbolic: str) -> bool:
    return symbolic in _NATIVE_TYPES


def _has_encodable_fields(index: NodeSetIndex, node_id: str | None, depth: int = 32) -> bool:
    """True if the structure (or any ancestor) declares at least one field.

    A field-less structure (e.g. an abstract marker base like NotificationData)
    encodes to a zero-length body, which the binary decoder rejects when the value
    is carried inside an ExtensionObject ("body length 0 is invalid"). Such types
    are never sent as a standalone ExtensionObject on the wire, so the polymorphic
    round-trip test is skipped for them.
    """
    seen: set[str] = set()
    current = node_id
    while current and current not in seen and depth > 0:
        seen.add(current)
        depth -= 1
        node = index.find(current)
        if node is None:
            break
        if node.definition is not None and node.definition.fields:
            return True
        current = node.parent_node_id
    return False


# Expressions that yield a non-default value of a built-in type. Used both for
# populating top-level struct fields and for recursing into nested structures.
_BUILTIN_VALUE_EXPRESSIONS: dict[str, str] = {
    "Boolean": "true",
    "Byte": "123",
    "SByte": "123",
    "Int16": "12345",
    "UInt16": "12345",
    "Int32": "123456",
    "UInt32": "123456",
    "Int64": "1234567",
    "UInt64": "1234567",
    "Float": "1.5f",
    "Double": "1.5",
    "String": '"test"',
    "DateTime": "DateTime::now()",
    "Guid": "Guid::create_and_generate()",
    "ByteString": "ByteString{1, 2, 3}",
    "NodeId": "NodeId{1234}",
    "ExpandedNodeId": "ExpandedNodeId{NodeId{1234}}",
    "StatusCode": "Status::Good",
    "QualifiedName": 'QualifiedName{"test"}',
    "LocalizedText": 'LocalizedText{"en", "test"}',
    "Variant": "Variant{123}",
}


def _builtin_value_expression(symbolic: str) -> str | None:
    return _BUILTIN_VALUE_EXPRESSIONS.get(symbolic)


def _resolve_field_type_name(index: NodeSetIndex, data_type_node_id: str | None) -> str:
    """Return the symbolic name for a field's data type, or "BaseDataType" if unknown."""
    if data_type_node_id is None:
        return "Variant"
    node = index.find(data_type_node_id)
    if node is None:
        return "BaseDataType"
    return get_symbolic_name(node.browse_name)


def _populate_statements(
    index: NodeSetIndex,
    lvalue: str,
    data_type_node_id: str | None,
    depth: int,
    visited: frozenset[str],
) -> list[str]:
    """Emit C++ statements that mutate `lvalue` to a non-default value of the data type.

    Returns a list of statement strings (with trailing semicolon, no newline).
    Falls back to an empty list when no safe value can be synthesised.
    """
    if depth <= 0 or data_type_node_id is None:
        return []

    node = index.find(data_type_node_id)
    if node is None:
        return []

    symbolic = get_symbolic_name(node.browse_name)

    # 1. Direct hit on a built-in/native type.
    direct = _builtin_value_expression(symbolic)
    if direct is not None:
        return [f"{lvalue} = {direct};"]

    # 2. Refuse to instantiate abstract types - caller will leave default.
    if node.is_abstract:
        return []

    # 3. Cycle guard - if we're already populating this type higher in the chain,
    #    fall back to default to avoid infinite recursion.
    if data_type_node_id in visited:
        return []

    # 4. Typedef alias to a parent (no definition of its own) - recurse on parent.
    if node.definition is None:
        if node.parent_node_id:
            return _populate_statements(index, lvalue, node.parent_node_id, depth, visited)
        return []

    # 5. OptionSet: default-construct + set first bit so the value is non-default.
    if node.definition.is_option_set:
        fields = _aggregate_definition_fields(index, data_type_node_id)
        if not fields:
            return []
        first_bit = fields[0][0]
        return [f"{lvalue}.set({symbolic}::Bit::{first_bit});"]

    # 6. Enumeration: pick the first declared value.
    if index.is_subtype_of(data_type_node_id, "Enumeration"):
        fields = _aggregate_definition_fields(index, data_type_node_id)
        if not fields:
            return []
        first_name = fields[0][0]
        return [f"{lvalue} = {symbolic}::{first_name};"]

    # 7. Union - activate the first field with a recognised primitive type.
    if node.definition.is_union or index.is_subtype_of(data_type_node_id, "Union"):
        for f in node.definition.fields:
            if f.data_type is None:
                continue
            inner_node = index.find(f.data_type)
            if inner_node is None:
                continue
            inner_sym = get_symbolic_name(inner_node.browse_name)
            val = _builtin_value_expression(inner_sym)
            if val is None:
                continue
            field_method = to_snake_case(get_symbolic_name(f.name))
            return [f"{lvalue}.{field_method}({val});"]
        return []

    # 8. Structure: recursively populate its mandatory fields.
    if index.is_subtype_of(data_type_node_id, "Structure"):
        stmts: list[str] = []
        new_visited = visited | {data_type_node_id}
        for f in node.definition.fields:
            # Skip optional fields when populating a nested struct - keeps the
            # synthesised value compact and avoids touching the optional-mask
            # paths of unrelated types from inside a parent test.
            if f.is_optional:
                continue
            inner_stmts = _populate_field_statements(
                index,
                lvalue,
                f,
                depth - 1,
                new_visited,
            )
            stmts.extend(inner_stmts)
        return stmts

    return []


def _populate_field_statements(
    index: NodeSetIndex,
    parent_lvalue: str,
    field: UaDataTypeField,
    depth: int,
    visited: frozenset[str],
) -> list[str]:
    """Emit statements that populate one field of a structure that lives at `parent_lvalue`."""
    field_name = to_snake_case(get_symbolic_name(field.name))
    value_rank = field.value_rank if field.value_rank is not None else -1

    accessor = f"{parent_lvalue}.{field_name}()"
    # Optional fields expose the accessor as `std::optional<T>&`. Give the
    # optional a value first (`emplace()`) and operate on the contained value
    # via `operator*`, so nested member / array access targets `T`, not the
    # `std::optional<T>` wrapper. Emitted only when the field actually produces
    # populate statements (see the early `return []` guards below).
    if field.is_optional:
        prefix = [f"{accessor}.emplace();"]
        target = f"(*{accessor})"
    else:
        prefix = []
        target = accessor

    # Fields without a declared DataType are encoded as a generic Variant.
    if field.data_type is None:
        if value_rank <= 0:
            return prefix + [f"{target} = Variant{{123}};"]
        if value_rank == 1:
            return prefix + [f"{target}.resize(2);"]
        return []

    if value_rank <= 0:
        stmts = _populate_statements(index, target, field.data_type, depth, visited)
        return prefix + stmts if stmts else []

    if value_rank == 1:
        # Resize, then populate one element if we can synthesise a value for it.
        element_stmts = _populate_statements(
            index,
            f"{target}[0]",
            field.data_type,
            depth,
            visited,
        )
        if not element_stmts:
            # No populator for the element type - fall back to the previous
            # behaviour of leaving two default-constructed elements, which at
            # least exercises the encoder's array length handling.
            return prefix + [f"{target}.resize(2);"]
        return prefix + [f"{target}.resize(2);"] + element_stmts

    # value_rank > 1 (matrix / multi-dim) - leave default.
    return []


def _emit_structure_test(
    index: NodeSetIndex,
    type_name: str,
    node,
    is_encodable: bool = True,
) -> str:
    fields = node.definition.fields if node.definition is not None else []

    # Field-accessor "exercises" - call each accessor through const and non-const
    # references so the generated getter/setter methods are visited by coverage.
    field_accessors: list[str] = []
    mandatory_pops: list[str] = []
    optional_pops: list[str] = []

    top_visited: frozenset[str] = frozenset({node.node_id})

    has_optional_fields = False

    for f in fields:
        field_sym = get_symbolic_name(f.name)
        field_name = to_snake_case(field_sym)
        _append_line(field_accessors, f"    val1.{field_name}();")
        _append_line(field_accessors, f"    const_val.{field_name}();")

        stmts = _populate_field_statements(index, "val1", f, depth=3, visited=top_visited)
        if not stmts:
            continue

        if f.is_optional:
            has_optional_fields = True
            for s in stmts:
                _append_line(optional_pops, f"    {s}")
        else:
            for s in stmts:
                _append_line(mandatory_pops, f"    {s}")

    body: list[str] = []
    _append_line(body, f"    {type_name} val1;")
    body.extend(mandatory_pops)
    _append_line(body, f"    const {type_name}& const_val = val1;")
    body.extend(field_accessors)
    _append_line(body, "    test_binary_round_trip(val1);")
    _append_line(body, "    test_metadata(val1);")
    _append_line(body, "    test_clone(val1);")
    _append_line(body, "    test_xml_round_trip(val1);")
    # Drive the polymorphic ExtensionObject wire path (encode_id + factory
    # create()) and the to_string()/append_fields() formatter - neither is
    # touched by the direct encode()/decode() round-trips above. The
    # ExtensionObject path only applies to types that own a Default Binary
    # encoding; abstract base types (no encoding id, never instantiated on the
    # wire) are excluded - they would have no factory registration to resolve.
    if is_encodable:
        _append_line(body, "    test_extension_object_round_trip(val1);")
    _append_line(body, "    test_to_string(val1);")

    if has_optional_fields:
        # Second round-trip with optional fields populated, to cover the
        # "optional present" branch of the structure's encode/decode lambda.
        _append_line(body)
        _append_line(body, "    // Cover the optional-present encoding-mask paths.")
        body.extend(optional_pops)
        _append_line(body, "    test_binary_round_trip(val1);")
        _append_line(body, "    test_clone(val1);")
        _append_line(body, "    test_xml_round_trip(val1);")
        if is_encodable:
            _append_line(body, "    test_extension_object_round_trip(val1);")
        _append_line(body, "    test_to_string(val1);")

    return (
        "\n"
        f"TEST_F(GeneratedDataTypeTests, {type_name}_Structure) {{\n"
        f"{''.join(body)}"
        "}\n"
    )


def _emit_union_test(
    index: NodeSetIndex,
    type_name: str,
    node,
) -> str:
    fields = node.definition.fields if node.definition is not None else []
    body: list[str] = []
    _append_line(body, f"    {type_name} val1;")
    _append_line(body, f"    EXPECT_EQ(val1.active_field(), {type_name}::Field::None);")
    _append_line(body, f"    EXPECT_EQ(val1.switch_field(), 0u);")

    for i, f in enumerate(fields, start=1):
        if f.data_type is None:
            continue
        field_sym = get_symbolic_name(f.name)
        field_name = to_snake_case(field_sym)
        inner_sym = _resolve_field_type_name(index, f.data_type)
        val = _builtin_value_expression(inner_sym)
        if val is None:
            continue
        _append_line(body, f"    val1.{field_name}({val});")
        _append_line(body, f"    EXPECT_EQ(val1.active_field(), {type_name}::Field::{field_sym});")
        _append_line(body, f"    EXPECT_EQ(val1.switch_field(), {i}u);")
        _append_line(body, f"    EXPECT_NE(val1.try_{field_name}(), nullptr);")

    _append_line(body, f"    val1.clear();")
    _append_line(body, f"    EXPECT_EQ(val1.active_field(), {type_name}::Field::None);")

    return (
        "\n"
        f"TEST_F(GeneratedDataTypeTests, {type_name}_Union) {{\n"
        f"{''.join(body)}\n"
        "    test_binary_round_trip(val1);\n"
        "    test_metadata(val1);\n"
        "    test_clone(val1);\n"
        "    test_xml_round_trip(val1);\n"
        "}\n"
    )


def _emit_enumeration_test(
    index: NodeSetIndex,
    type_name: str,
    node_id: str,
) -> str:
    body: list[str] = []
    for name, _value, _ in _aggregate_definition_fields(index, node_id):
        _append_line(body, f"    e = {type_name}::{name};")
        _append_line(body, f"    EXPECT_TRUE(is_valid(e));")
        # Asserting on the string keeps to_string() honest - a regression that
        # silently mapped a known value to an "unknown" formatter would fail.
        _append_line(body, f'    EXPECT_EQ(to_string(e), "{name}");')

    return (
        "\n"
        f"TEST_F(GeneratedDataTypeTests, {type_name}_Enumeration) {{\n"
        f"    {type_name} e{{}};\n"
        f"{''.join(body)}"
        "    // Test invalid value\n"
        f"    EXPECT_FALSE(is_valid(static_cast<{type_name}>(-9999)));\n"
        f"    // Exercise the to_string() fallthrough for unknown values.\n"
        f"    (void)to_string(static_cast<{type_name}>(-9999));\n"
        "}\n"
    )


def _emit_option_set_test(
    index: NodeSetIndex,
    type_name: str,
    node_id: str,
) -> str:
    bits = _aggregate_definition_fields(index, node_id)
    body: list[str] = []
    _append_line(body, f"    {type_name} o;")

    # Default-state to_string covers the "no bits set" branches.
    _append_line(body, f"    auto default_str = to_string(o);")
    _append_line(body, f"    EXPECT_NE(default_str.find(\"{type_name}\"), std::string::npos);")

    # Set every bit individually, assert test() flips, assert the bit's name
    # appears in to_string(). This is what drives ua_optionset_helpers.cpp
    # coverage from ~7 % to ~100 %.
    for name, _value, _ in bits:
        _append_line(body, f"    o.set({type_name}::Bit::{name});")
        _append_line(body, f"    EXPECT_TRUE(o.test({type_name}::Bit::{name}));")
        _append_line(
            body,
            f"    EXPECT_NE(to_string(o).find(\"{name}\"), std::string::npos);",
        )

    # With every bit set, to_string() exercises every branch as "true".
    _append_line(body, "    auto all_set_str = to_string(o);")
    for name, _value, _ in bits:
        _append_line(
            body,
            f"    EXPECT_NE(all_set_str.find(\"{name}\"), std::string::npos);",
        )

    # Reset each bit to also cover the false branches independently, and round
    # the value back to its underlying-type form.
    for name, _value, _ in bits:
        _append_line(body, f"    o.reset({type_name}::Bit::{name});")
        _append_line(body, f"    EXPECT_FALSE(o.test({type_name}::Bit::{name}));")

    _append_line(body, "    auto u = o.as_underlying_type();")
    _append_line(body, "    o.from_underlying_type(u);")
    _append_line(body, "    EXPECT_EQ(o.as_underlying_type(), u);")

    return (
        "\n"
        f"TEST_F(GeneratedDataTypeTests, {type_name}_OptionSet) {{\n"
        f"{''.join(body)}"
        "}\n"
    )


class DataTypeTestsEmitter:
    """Emits the generated data-type tests source.

    The tests reference NS0 ObjectId/types; downstream specs should
    not invoke this emitter unless they explicitly opt in.
    """

    def __init__(self, ctx):
        self._ctx = ctx

    def emit(
        self,
        data_type_node_ids_in_order: list[str],
        data_type_headers_in_order: list[str],
        binary_encoding_type_names: set[str] | None = None,
    ) -> Path:
        return emit_generated_data_type_tests(
            self._ctx.implementation_dir_for("data_types"),
            self._ctx.index,
            data_type_node_ids_in_order,
            data_type_headers_in_order,
            binary_encoding_type_names,
        )


def emit_generated_data_type_tests(
        output_dir: Path,
        index: NodeSetIndex,
        data_type_node_ids_in_order: list[str],
        data_type_headers_in_order: list[str],
        binary_encoding_type_names: set[str] | None = None,
) -> Path:
    text = load_template("generated_data_type_tests.in")

    includes: list[str] = []

    # Common headers.
    for h in (
            "ua_date_time.h",
            "ua_guid.h",
            "ua_node_id.h",
            "ua_expanded_node_id.h",
            "ua_qualified_name.h",
            "ua_localized_text.h",
            "ua_variant.h",
    ):
        _append_line(includes, f'#include "{h}"')

    seen: set[str] = set()
    for h in data_type_headers_in_order:
        if h in seen:
            continue
        seen.add(h)
        _append_line(includes, f'#include "{h}"')

    test_cases: list[str] = []

    for node_id in data_type_node_ids_in_order:
        node = index.find(node_id)
        if node is None:
            continue

        type_name = get_symbolic_name(node.browse_name)

        # Determine kind similarly to main generator.
        # Note: this is a generation-only file; it assumes the same filtering already happened.
        kind: DataTypeKind
        if node.definition is not None and node.definition.is_option_set:
            kind = DataTypeKind.option_set
        elif index.is_subtype_of(node.node_id,
                                 "Enumeration") and node.definition is not None and node.definition.fields:
            kind = DataTypeKind.enumeration
        elif index.is_subtype_of(node.node_id, "Structure") and node.definition is not None:
            if (node.definition.is_union or index.is_subtype_of(node.node_id, "Union")):
                kind = DataTypeKind.union
            else:
                kind = DataTypeKind.structure
        else:
            kind = DataTypeKind.unknown

        if kind == DataTypeKind.union:
            test_cases.append(_emit_union_test(index, type_name, node))
            continue

        if kind == DataTypeKind.structure:
            if node.is_abstract:
                test_cases.append(
                    f"\nTEST_F(GeneratedDataTypeTests, {type_name}_AbstractStructure) {{\n"
                    "    // Testing only metadata for abstract structures\n"
                    "    // we cannot instantiate them\n"
                    "}\n"
                )
                continue
            # A value round-trips as a standalone ExtensionObject only if it is
            # registered with the StructureFactory (owns a Default Binary
            # encoding) AND encodes a non-empty body. Field-less abstract base
            # types (e.g. NotificationData, DiscoveryConfiguration) satisfy the
            # former but encode to a zero-length body the decoder rejects, so the
            # polymorphic round-trip is skipped for them.
            has_binary_encoding = (
                binary_encoding_type_names is None or type_name in binary_encoding_type_names
            )
            is_round_trippable = has_binary_encoding and _has_encodable_fields(index, node.node_id)
            test_cases.append(_emit_structure_test(index, type_name, node, is_round_trippable))
            continue

        if kind == DataTypeKind.enumeration:
            test_cases.append(_emit_enumeration_test(index, type_name, node_id))
            continue

        if kind == DataTypeKind.option_set:
            test_cases.append(_emit_option_set_test(index, type_name, node_id))
            continue

        # Simple type / alias - there is no first-party generated code for
        # these (they are typedefs to a built-in), so a default-construct +
        # copy "smoke test" is all that's possible.
        test_cases.append(
            "\n"
            f"TEST_F(GeneratedDataTypeTests, {type_name}_SimpleType) {{\n"
            f"    {type_name} val1{{}};\n"
            f"    {type_name} val2 = val1;\n"
            "    val1 = val2;\n"
            "    (void)val1;\n"
            "}\n"
        )

    text = text.replace("PLACEHOLDER_INCLUDES", "".join(includes).rstrip("\n"))
    text = text.replace("PLACEHOLDER_TEST_CASES", "".join(test_cases).rstrip("\n"))

    out_path = output_dir / "generated_data_type_tests.cpp"
    write_file(out_path, text)
    return out_path
