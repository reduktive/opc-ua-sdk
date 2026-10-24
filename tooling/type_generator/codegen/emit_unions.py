# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit headers for ``UAUnion`` types.

``UnionEmitter`` mirrors ``StructureEmitter`` - one class owning the
spec's ``EmitContext`` with an ``emit(node_id)`` method.
"""

from __future__ import annotations

from pathlib import Path

from ..io import load_template, write_file
from ..naming import cpp_identifier, get_symbolic_name, to_snake_case
from ..nodeset.index import NodeSetIndex
from ..nodeset.nodeid import parse_numeric_node_id
from .context import EmitContext
from .emit_structures import (
    _LT_CONTAINS_MEMO,
    _field_cpp_type,
    _field_is_abstract_value,
    _field_is_variant,
    _field_references_lt,
    _safe_snake,
    _struct_own_fields_need_resolve,
)


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


def _is_native(symbolic: str) -> bool:
    return symbolic in _NATIVE_MAP


def _field_inner_cpp_type(index: NodeSetIndex, field, resolver=None) -> str:
    """Return the C++ type for a union field (never wrapped in optional<>).

    When ``resolver`` is supplied, the base struct/enum type name is qualified
    for cross-spec references (bare for in-spec); see
    ``emit_structures._field_cpp_type``."""
    # Union fields are never optional in the optional<> sense - exactly one is active.
    # We need the raw type. _field_cpp_type may wrap in optional if is_optional is set,
    # but for unions the is_optional flag means "can be absent from the union" which
    # is not the same. So we compute the type ignoring is_optional.
    if field.data_type is None:
        type_name = "Variant"
        is_array = (field.value_rank is not None) and (field.value_rank > 0)
        if is_array:
            type_name = f"Array<{type_name}>"
        return type_name

    type_id = field.data_type
    type_node = index.find(type_id)
    type_name = get_symbolic_name(type_node.browse_name) if type_node is not None else "Structure"

    is_array = (field.value_rank is not None) and (field.value_rank > 0)
    is_native = _is_native(type_name)
    is_structure = (type_name == "Structure") or index.is_subtype_of(type_id, "Structure")
    is_variant = (type_name == "Variant")

    # Abstract, non-Structure, non-native field types carry a concrete subtype
    # value with no common C++ base class -> represented as a Variant. (See
    # emit_structures._field_is_abstract_value.)
    if _field_is_abstract_value(index, field):
        type_name = "Variant"
        is_variant = True
        is_structure = False
        is_native = False

    if is_native:
        type_name = _NATIVE_MAP[type_name]
    elif resolver is not None and not is_variant and type_node is not None:
        # Qualify the base struct/enum type name for cross-spec references
        # (bare for in-spec -> NS0 byte-identical; NS0 has no unions anyway).
        type_name = resolver.resolve(type_id).qualified_class_name

    ref_type_name = "RefMember"
    if is_structure:
        ref_type_name = "RefStructure"

    allow_subtypes = bool(field.allow_subtypes) if field.allow_subtypes is not None else False
    is_abstract = bool(type_node.is_abstract) if type_node is not None else False

    if is_array:
        if (not is_variant) and (is_abstract or allow_subtypes):
            type_name = f"Array<{ref_type_name}<{type_name}>>"
        else:
            type_name = f"Array<{type_name}>"
    else:
        if (not is_variant) and (is_abstract or allow_subtypes):
            type_name = f"{ref_type_name}<{type_name}>"

    return type_name


class UnionEmitter:
    """Emits one ``ua_<snake>.h`` per UAUnion for the spec in ``ctx``."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit(self, node_id: str) -> Path:
        return _emit_union_header(self._ctx, node_id)


def _emit_union_header(ctx: EmitContext, node_id: str) -> Path:
    index = ctx.index
    node = index.find(node_id)
    if node is None:
        raise KeyError(node_id)

    text = ctx.apply_template(load_template("union_header.in"))

    type_name = get_symbolic_name(node.browse_name)
    text = text.replace(
        "PLACEHOLDER_DOC",
        ctx.doc_comment(f"OPC UA {type_name} union data type.", "ua_data_types"),
    )
    header_guard = ctx.header_guard("DATA_TYPE", type_name)

    numeric = parse_numeric_node_id(node.node_id)
    if numeric is None:
        raise ValueError(f"Only numeric NodeIds supported: {node.node_id}")

    fields = node.definition.fields if node.definition is not None else []

    # Field enum values: Field1 = 1, Field2 = 2, ...
    enum_lines: list[str] = []
    for i, f in enumerate(fields, start=1):
        sym = cpp_identifier(f.name, f.symbolic_name)
        # Each Field enumerator names a concrete union field - an honest
        # noun-phrase brief (the NodeSet supplies no per-field documentation).
        enum_lines.append(f"    {sym} = {i},  ///< Selects the `{sym}` field as the active value.")
    # Remove trailing comma from last
    if enum_lines:
        enum_lines[-1] = enum_lines[-1].replace(",  ///<", "  ///<", 1)
    enum_text = "\n".join(enum_lines)

    # Field accessors: const T& field() const; const T* try_field() const; void field(T value);
    accessor_lines: list[str] = []
    for f in fields:
        sym = cpp_identifier(f.name, f.symbolic_name)
        snake = _safe_snake(sym)
        cpp_type = _field_inner_cpp_type(index, f, ctx.resolver)

        accessor_lines.append(f"  /// Reads the `{sym}` field value.")
        accessor_lines.append(f"  /// @return A const reference to the `{sym}` value.")
        accessor_lines.append(f"  /// @throws UaException if `{sym}` is not the active field.")
        accessor_lines.append(f"  const {cpp_type}& {snake}() const;")
        accessor_lines.append(f"")
        accessor_lines.append(f"  /// Reads the `{sym}` field value if it is active.")
        accessor_lines.append(f"  /// @return A pointer to the `{sym}` value, or nullptr if it is not the active field.")
        accessor_lines.append(f"  const {cpp_type}* try_{snake}() const;")
        accessor_lines.append(f"")
        accessor_lines.append(f"  /// Sets this union to hold `{sym}`, clearing any previously active field.")
        accessor_lines.append(f"  /// @param value The new `{sym}` value.")
        accessor_lines.append(f"  void {snake}({cpp_type} value);")
        accessor_lines.append(f"")
    accessors_text = "\n".join(accessor_lines)

    # Field member declarations. The NodeSet carries no per-field documentation,
    # so each member gets an honest noun-phrase brief derived from its field name;
    # only one member is active at a time (selected by mActiveField).
    member_lines: list[str] = []
    for f in fields:
        sym = cpp_identifier(f.name, f.symbolic_name)
        cpp_type = _field_inner_cpp_type(index, f, ctx.resolver)
        phrase = _safe_snake(sym).replace("_", " ")
        member_lines.append(
            f"  {cpp_type} m{sym}{{}};  ///< Storage for the `{phrase}` field; valid when it is the active field."
        )
    members_text = "\n".join(member_lines)

    # Field includes
    include_lines = ""
    field_data_type_ids: list[str] = []
    uses_array = False
    for f in fields:
        value_rank = f.value_rank if f.value_rank is not None else -1
        if value_rank > 0:
            uses_array = True
        if f.data_type is None:
            if "Variant" not in field_data_type_ids:
                field_data_type_ids.append("Variant")
        elif _field_is_abstract_value(index, f):
            # Abstract non-Structure field -> Variant.
            if "Variant" not in field_data_type_ids:
                field_data_type_ids.append("Variant")
        else:
            dt_node = index.find(f.data_type)
            dt_sym = get_symbolic_name(dt_node.browse_name) if dt_node is not None else "Structure"
            if dt_node is not None and not _is_native(dt_sym) and f.data_type not in field_data_type_ids:
                field_data_type_ids.append(f.data_type)

    for type_id in field_data_type_ids:
        if type_id == "Variant":
            include_lines += '#include "ua_variant.h"\n'
            continue
        dt_node = index.find(type_id)
        if dt_node is None:
            continue
        include_lines += f'#include "{ctx.resolver.resolve(type_id).header_include}"\n'
    if uses_array:
        include_lines += '#include "ua_array.h"\n'

    # StructureFactory fwd-decl: NS0 forward-declares ua::StructureFactory; a
    # companion spec pulls it in via <prefix>aliases.h (a fwd decl would declare
    # the wrong, nested-namespace type and clash with the alias).
    if ctx.cpp_namespace == "ua":
        text = text.replace("PLACEHOLDER_STRUCTURE_FACTORY_FWD", "class StructureFactory;")
    else:
        text = text.replace("PLACEHOLDER_STRUCTURE_FACTORY_FWD", "")

    # get_typename<T> specialisation must live in the primary template's
    # namespace (``ua``): NS0 emits it inline; a companion spec closes its own
    # namespace and reopens ``namespace ua`` with the fully-qualified type.
    if ctx.cpp_namespace == "ua":
        get_typename_block = (
            f"template<>\ninline string_view get_typename<{type_name}>()\n"
            f"{{\n  return {type_name}::typeName;\n}}\n\n{ctx.cpp_namespace_close()}"
        )
    else:
        qualified = f"{ctx.cpp_namespace}::{type_name}"
        get_typename_block = (
            f"{ctx.cpp_namespace_close()}\n\nnamespace ua\n{{\n"
            f"template<>\ninline string_view get_typename<{qualified}>()\n"
            f"{{\n  return {qualified}::typeName;\n}}\n}}  // namespace ua"
        )
    text = text.replace("PLACEHOLDER_GET_TYPENAME_BLOCK", get_typename_block)

    text = text.replace("PLACEHOLDER_HEADER_GUARD", header_guard)
    # ``PLACEHOLDER_CLASS_NAME`` also rewrites the ``DataTypeId::PLACEHOLDER_CLASS_NAME``
    # token the header template uses to source ``typeId`` from the named
    # identifier (in place of a bare numeric literal).
    text = text.replace("PLACEHOLDER_CLASS_NAME", type_name)
    text = text.replace("PLACEHOLDER_FIELD_ENUM_VALUES", enum_text)
    text = text.replace("PLACEHOLDER_FIELD_ACCESSORS", accessors_text)
    text = text.replace("PLACEHOLDER_FIELD_MEMBERS", members_text)
    text = text.replace("PLACEHOLDER_FIELD_INCLUDES", include_lines.rstrip("\n"))

    if _struct_own_fields_need_resolve(index, node_id):
        text = text.replace(
            "PLACEHOLDER_RESOLVE_DECLARATION",
            "\n  /// Resolves the active field's localized-text values to the preferred locales.\n"
            "  /// @param locales Preferred locales, most-preferred first.\n"
            "  void resolve(span<const LocaleId> locales) override;")
    else:
        text = text.replace("PLACEHOLDER_RESOLVE_DECLARATION", "")

    out_path = ctx.interface_dir / ctx.header_file_name(type_name)
    write_file(out_path, text)
    return out_path


def _append_line(buf: list[str], line: str = "") -> None:
    buf.append(line + "\n")


def _create_union_source_content(
    index: NodeSetIndex, node_id: str, cpp_namespace: str = "ua", resolver=None
) -> str:
    """Generate source code for a single union type.

    ``cpp_namespace`` is the emitting spec's namespace (``ua`` for NS0,
    ``ua::di`` etc. for companion specs). The detail:: encode/decode bodies must
    name the type fully-qualified (``ua::Foo`` / ``ua::pn::Foo``); for NS0 the
    fully-qualified form equals the existing literal so output stays byte-identical.
    """
    node = index.find(node_id)
    if node is None:
        raise KeyError(node_id)

    type_name = get_symbolic_name(node.browse_name)
    qualified = f"{cpp_namespace}::{type_name}"
    fields = node.definition.fields if node.definition is not None else []

    lines: list[str] = []

    def ln(s: str = "") -> None:
        lines.append(s + "\n")

    # --- Encode/decode detail functions ---
    ln(f"namespace detail::{type_name}")
    ln("{")
    ln("namespace")
    ln("{")

    # Binary encode
    ln(f"void encode(StackDepth limit, const ua::{type_name}& value, UaBinaryEncoder& encoder)")
    ln("{")
    ln(f"  encoder.encode(limit, utils::to_underlying(value.active_field()));")
    ln(f"  switch (value.active_field())")
    ln("  {")
    ln(f"  case ua::{type_name}::Field::None:")
    ln("    break;")
    for f in fields:
        sym = cpp_identifier(f.name, f.symbolic_name)
        snake = _safe_snake(sym)
        cpp_type = _field_inner_cpp_type(index, f, resolver)

        ln(f"  case ua::{type_name}::Field::{sym}:")
        if (f.data_type is not None and index.is_subtype_of(f.data_type, "Enumeration")
                and not _field_is_variant(index, f)):
            ln(f"    encoder.encode(limit, utils::as_int32(value.{snake}()));")
        elif cpp_type.startswith("RefMember<") or cpp_type.startswith("RefStructure<"):
            ln(f"    encoder.encode(limit, value.{snake}().get());")
        else:
            ln(f"    encoder.encode(limit, value.{snake}());")
        ln("    break;")
    ln("  }")
    ln("}")
    ln()

    # XML encode
    ln(f"void encode(StackDepth limit, const ua::{type_name}& value, XmlEncoder& encoder)")
    ln("{")
    ln(f"  encoder.encode(limit, \"SwitchField\", utils::to_underlying(value.active_field()));")
    ln(f"  switch (value.active_field())")
    ln("  {")
    ln(f"  case ua::{type_name}::Field::None:")
    ln("    break;")
    for f in fields:
        sym = cpp_identifier(f.name, f.symbolic_name)
        snake = _safe_snake(sym)
        cpp_type = _field_inner_cpp_type(index, f, resolver)

        ln(f"  case ua::{type_name}::Field::{sym}:")
        if (f.data_type is not None and index.is_subtype_of(f.data_type, "Enumeration")
                and not _field_is_variant(index, f)):
            ln(f"    encoder.encode(limit, \"{get_symbolic_name(f.name)}\", utils::as_int32(value.{snake}()));")
        elif cpp_type.startswith("RefMember<") or cpp_type.startswith("RefStructure<"):
            ln(f"    encoder.encode(limit, \"{get_symbolic_name(f.name)}\", value.{snake}().get());")
        else:
            ln(f"    encoder.encode(limit, \"{get_symbolic_name(f.name)}\", value.{snake}());")
        ln("    break;")
    ln("  }")
    ln("}")
    ln()

    # Binary decode
    ln(f"void decode(StackDepth limit, UaBinaryDecoder& decoder, ua::{type_name}& value)")
    ln("{")
    ln("  uint32_t switchField{};")
    ln("  decoder.decode(limit, switchField);")
    ln(f"  if (switchField > {len(fields)})")
    ln("    throw UaException(Status::BadDecodingError);")
    ln("  value.clear();")
    ln(f"  switch (static_cast<ua::{type_name}::Field>(switchField))")
    ln("  {")
    ln(f"  case ua::{type_name}::Field::None:")
    ln("    break;")
    for f in fields:
        sym = cpp_identifier(f.name, f.symbolic_name)
        snake = _safe_snake(sym)
        cpp_type = _field_inner_cpp_type(index, f, resolver)

        ln(f"  case ua::{type_name}::Field::{sym}:")
        ln("  {")
        if (f.data_type is not None and index.is_subtype_of(f.data_type, "Enumeration")
                and not _field_is_variant(index, f)):
            enum_type_node = index.find(f.data_type)
            if resolver is not None and enum_type_node is not None:
                enum_type_name = resolver.resolve(f.data_type).qualified_class_name
            elif enum_type_node is not None:
                enum_type_name = get_symbolic_name(enum_type_node.browse_name)
            else:
                enum_type_name = "int32_t"
            ln("    int32_t enumVal{};")
            ln("    decoder.decode(limit, enumVal);")
            ln(f"    value.{snake}(utils::from_underlying<{enum_type_name}>(enumVal));")
        elif cpp_type.startswith("RefMember<") or cpp_type.startswith("RefStructure<"):
            # Spell the local via decltype of the accessor: a bare type name (e.g.
            # ``BACnetDate``) would be shadowed by the sibling ``detail::BACnetDate``
            # codec namespace during unqualified lookup inside this detail namespace.
            ln(f"    std::remove_cvref_t<decltype(value.{snake}())> v;")
            ln("    decoder.decode(limit, v.inner_unique_ptr());")
            ln(f"    value.{snake}(std::move(v));")
        else:
            ln(f"    std::remove_cvref_t<decltype(value.{snake}())> v{{}};")
            ln("    decoder.decode(limit, v);")
            ln(f"    value.{snake}(std::move(v));")
        ln("    break;")
        ln("  }")
    ln("  }")
    ln("}")
    ln()

    # XML decode
    ln(f"void decode(StackDepth limit, XmlDecoder& decoder, ua::{type_name}& value)")
    ln("{")
    ln("  uint32_t switchField{};")
    ln("  decoder.decode(limit, \"SwitchField\", true, switchField);")
    ln(f"  if (switchField > {len(fields)})")
    ln("    throw UaException(Status::BadDecodingError);")
    ln("  value.clear();")
    ln(f"  switch (static_cast<ua::{type_name}::Field>(switchField))")
    ln("  {")
    ln(f"  case ua::{type_name}::Field::None:")
    ln("    break;")
    for f in fields:
        sym = cpp_identifier(f.name, f.symbolic_name)
        snake = _safe_snake(sym)
        cpp_type = _field_inner_cpp_type(index, f, resolver)

        ln(f"  case ua::{type_name}::Field::{sym}:")
        ln("  {")
        if (f.data_type is not None and index.is_subtype_of(f.data_type, "Enumeration")
                and not _field_is_variant(index, f)):
            enum_type_node = index.find(f.data_type)
            if resolver is not None and enum_type_node is not None:
                enum_type_name = resolver.resolve(f.data_type).qualified_class_name
            elif enum_type_node is not None:
                enum_type_name = get_symbolic_name(enum_type_node.browse_name)
            else:
                enum_type_name = "int32_t"
            ln("    int32_t enumVal{};")
            ln(f"    decoder.decode(limit, \"{get_symbolic_name(f.name)}\", true, enumVal);")
            ln(f"    value.{snake}(utils::from_underlying<{enum_type_name}>(enumVal));")
        elif cpp_type.startswith("RefMember<") or cpp_type.startswith("RefStructure<"):
            # decltype of the accessor avoids the sibling detail:: namespace shadow.
            ln(f"    std::remove_cvref_t<decltype(value.{snake}())> v;")
            ln(f"    decoder.decode(limit, \"{get_symbolic_name(f.name)}\", true, v.inner_unique_ptr());")
            ln(f"    value.{snake}(std::move(v));")
        else:
            ln(f"    std::remove_cvref_t<decltype(value.{snake}())> v{{}};")
            ln(f"    decoder.decode(limit, \"{get_symbolic_name(f.name)}\", true, v);")
            ln(f"    value.{snake}(std::move(v));")
        ln("    break;")
        ln("  }")
    ln("  }")
    ln("}")
    ln()

    # Encode ID - NS0 encoding ids live in ns 0 (ObjectId enum ctor); a companion
    # spec resolves its namespace index at runtime from the codec context.
    if cpp_namespace == "ua":
        bin_id = f"UA_UNUSED(ns);\nencoder.encode(limit, NodeId{{{qualified}::defaultBinaryEncodingId}});"
        xml_id = (f"UA_UNUSED(ns);\nencoder.encode(limit, \"TypeId\", "
                  f"NodeId{{{qualified}::defaultXmlEncodingId}});")
    else:
        bin_id = (f"encoder.encode(limit, NodeId{{ns.getNamespaceIndex(specNamespaceUri), "
                  f"static_cast<uint32_t>({qualified}::defaultBinaryEncodingId)}});")
        xml_id = (f"encoder.encode(limit, \"TypeId\", NodeId{{ns.getNamespaceIndex(specNamespaceUri), "
                  f"static_cast<uint32_t>({qualified}::defaultXmlEncodingId)}});")
    ln(f"void encode_id(StackDepth limit, const CodecNamespaceContext& ns, UaBinaryEncoder& encoder)")
    ln("{")
    ln(bin_id)
    ln("}")
    ln()
    ln(f"void encode_id(StackDepth limit, const CodecNamespaceContext& ns, XmlEncoder& encoder)")
    ln("{")
    ln(xml_id)
    ln("}")
    ln()

    # Factory create
    ln(f"unique_ptr<Structure> create()")
    ln("{")
    ln(f"  return make_unique<{qualified}>();")
    ln("}")
    ln()
    ln("}  // namespace")
    ln(f"}}  // namespace detail::{type_name}")
    ln()

    # --- Methods on the class ---
    # is_of_type
    ln(f"bool {type_name}::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const")
    ln("{")
    ln(f"  NodeId myTypeId{{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)}};")
    ln("  if (dataTypeId == myTypeId)")
    ln("  {")
    ln("    return true;")
    ln("  }")
    ln("  return Union::is_of_type(ns, dataTypeId);")
    ln("}")
    ln()

    # type_id
    ln(f"NodeId {type_name}::type_id(const CodecNamespaceContext& ns) const")
    ln("{")
    ln(f"  return NodeId{{ns.getNamespaceIndex(typeNamespaceUri), utils::to_underlying(typeId)}};")
    ln("}")
    ln()
    ln(f"ExpandedNodeId {type_name}::type_id() const")
    ln("{")
    ln(f"  return ExpandedNodeId{{NodeId{{0, utils::to_underlying(typeId)}}, typeNamespaceUri}};")
    ln("}")
    ln()
    ln(f"String {type_name}::type_name() const")
    ln("{")
    ln("  return typeName;")
    ln("}")
    ln()

    # encode
    ln(f"void {type_name}::encode(StackDepth limit, Encoder& encoder) const")
    ln("{")
    ln("  Structure::encode(limit, encoder);")
    ln(f"  if (auto uaBinary = encoder.get_ua_binary())")
    ln("  {")
    ln(f"    detail::{type_name}::encode(limit, *this, *uaBinary);")
    ln("  }")
    ln(f"  else if (auto xml = encoder.get_xml())")
    ln("  {")
    ln(f"    detail::{type_name}::encode(limit, *this, *xml);")
    ln("  }")
    ln("}")
    ln()

    # encode_id
    ln(f"void {type_name}::encode_id(")
    ln("  StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const")
    ln("{")
    ln(f"  if (auto uaBinary = encoder.get_ua_binary())")
    ln("  {")
    ln(f"    detail::{type_name}::encode_id(limit, ns, *uaBinary);")
    ln("  }")
    ln(f"  else if (auto xml = encoder.get_xml())")
    ln("  {")
    ln(f"    detail::{type_name}::encode_id(limit, ns, *xml);")
    ln("  }")
    ln("}")
    ln()

    # decode
    ln(f"void {type_name}::decode(StackDepth limit, Decoder& decoder)")
    ln("{")
    ln("  Structure::decode(limit, decoder);")
    ln(f"  if (auto uaBinary = decoder.get_ua_binary())")
    ln("  {")
    ln(f"    detail::{type_name}::decode(limit, *uaBinary, *this);")
    ln("  }")
    ln(f"  else if (auto xml = decoder.get_xml())")
    ln("  {")
    ln(f"    detail::{type_name}::decode(limit, *xml, *this);")
    ln("  }")
    ln("}")
    ln()

    # clone
    ln(f"unique_ptr<Structure> {type_name}::clone() const")
    ln("{")
    ln(f"  return make_unique<{type_name}>(*this);")
    ln("}")
    ln()

    # Union interface
    ln(f"uint32_t {type_name}::switch_field() const")
    ln("{")
    ln("  return utils::to_underlying(mActiveField);")
    ln("}")
    ln()
    ln(f"uint32_t {type_name}::field_count() const")
    ln("{")
    ln(f"  return {len(fields)};")
    ln("}")
    ln()
    ln(f"void {type_name}::clear()")
    ln("{")
    ln("  mActiveField = Field::None;")
    for f in fields:
        sym = cpp_identifier(f.name, f.symbolic_name)
        # Naming the member type explicitly avoids the ambiguous ``= {}`` overload
        # resolution that bites container/ref members (Array<>, RefStructure<>).
        ln(f"  m{sym} = std::remove_cvref_t<decltype(m{sym})>{{}};")
    ln("}")
    ln()
    ln(f"{type_name}::Field {type_name}::active_field() const")
    ln("{")
    ln("  return mActiveField;")
    ln("}")
    ln()

    # Field accessors
    for i, f in enumerate(fields, start=1):
        sym = cpp_identifier(f.name, f.symbolic_name)
        snake = _safe_snake(sym)
        cpp_type = _field_inner_cpp_type(index, f, resolver)

        # Const throwing accessor
        ln(f"const {cpp_type}& {type_name}::{snake}() const")
        ln("{")
        ln(f"  if (mActiveField != Field::{sym})")
        ln("    throw UaException(Status::BadInvalidState);")
        ln(f"  return m{sym};")
        ln("}")
        ln()

        # Try accessor - returns pointer
        ln(f"const {cpp_type}* {type_name}::try_{snake}() const")
        ln("{")
        ln(f"  if (mActiveField != Field::{sym})")
        ln("    return nullptr;")
        ln(f"  return &m{sym};")
        ln("}")
        ln()

        # Setter
        ln(f"void {type_name}::{snake}({cpp_type} value)")
        ln("{")
        ln("  clear();")
        ln(f"  mActiveField = Field::{sym};")
        ln(f"  m{sym} = std::move(value);")
        ln("}")
        ln()

    # resolve - only emitted if any field references LocalizedText.
    if _struct_own_fields_need_resolve(index, node_id):
        ln(f"void {type_name}::resolve(span<const LocaleId> locales)")
        ln("{")
        ln("  Union::resolve(locales);")
        ln("  switch (mActiveField)")
        ln("  {")
        ln(f"  case Field::None: break;")
        for f in fields:
            sym = cpp_identifier(f.name, f.symbolic_name)
            cpp_type = _field_inner_cpp_type(index, f, resolver)
            visiting: set[str] = set()
            if not _field_references_lt(index, f, _LT_CONTAINS_MEMO, visiting):
                ln(f"  case Field::{sym}: break;")
                continue
            ln(f"  case Field::{sym}:")
            ln("  {")
            dt_node = index.find(f.data_type) if f.data_type is not None else None
            dt_sym = get_symbolic_name(dt_node.browse_name) if dt_node is not None else ""
            is_lt = (dt_sym == "LocalizedText")
            is_array = cpp_type.startswith("Array<") and cpp_type.endswith(">")
            elem = cpp_type[len("Array<"):-1] if is_array else cpp_type
            is_ref = elem.startswith("RefStructure<") or elem.startswith("RefMember<")
            if is_array:
                ln(f"    for (size_t i = 0; i < m{sym}.size(); ++i)")
                ln("    {")
                if is_lt:
                    ln(f"      m{sym}[i] = m{sym}[i].resolve(locales);")
                elif is_ref:
                    ln(f"      if (auto* structure = m{sym}[i].get())")
                    ln("      {")
                    ln("        structure->resolve(locales);")
                    ln("      }")
                else:
                    ln(f"      m{sym}[i].resolve(locales);")
                ln("    }")
            else:
                if is_lt:
                    ln(f"    m{sym} = m{sym}.resolve(locales);")
                elif is_ref:
                    ln(f"    if (auto* structure = m{sym}.get())")
                    ln("    {")
                    ln("      structure->resolve(locales);")
                    ln("    }")
                else:
                    ln(f"    m{sym}.resolve(locales);")
            ln("    break;")
            ln("  }")
        ln("  }")
        ln("}")
        ln()

    # register_type
    ln(f"void {type_name}::register_type(const CodecNamespaceContext& ns,")
    ln("  StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory)")
    ln("{")
    if cpp_namespace == "ua":
        ln("  UA_UNUSED(ns);")
        reg_bin = "NodeId(defaultBinaryEncodingId)"
        reg_xml = "NodeId(defaultXmlEncodingId)"
    else:
        reg_bin = "NodeId(ns.getNamespaceIndex(specNamespaceUri), static_cast<uint32_t>(defaultBinaryEncodingId))"
        reg_xml = "NodeId(ns.getNamespaceIndex(specNamespaceUri), static_cast<uint32_t>(defaultXmlEncodingId))"
    ln("  if (uaBinaryFactory)")
    ln("  {")
    ln(f"    uaBinaryFactory->register_type(")
    ln(f"      {reg_bin}, detail::{type_name}::create);")
    ln("  }")
    ln("  if (xmlFactory)")
    ln("  {")
    ln(f"    xmlFactory->register_type({reg_xml}, detail::{type_name}::create);")
    ln("  }")
    ln("}")
    ln()

    # to_string
    ln(f"void {type_name}::append_fields(std::string& output, int indent) const")
    ln("{")
    ln("  Union::append_fields(output, indent);")
    ln("  if (indent > 0)")
    ln("  {")
    ln("    std::string pad(numeric_cast<size_t>(indent), ' ');")
    ln('    if (!output.empty()) { output += ",\\n"; }')
    ln(f'    output += pad + "active_field=" + std::to_string(utils::to_underlying(mActiveField));')
    ln("    switch (mActiveField)")
    ln("    {")
    ln(f"    case Field::None: break;")
    for f in fields:
        sym = cpp_identifier(f.name, f.symbolic_name)
        snake = _safe_snake(sym)
        ln(f"    case Field::{sym}:")
        ln('      output += ",\\n";')
        ln(f'      output += pad + "{snake}=" + ua::to_string(m{sym});')
        ln("      break;")
    ln("    }")
    ln("    return;")
    ln("  }")
    # Compact path
    ln('  if (!output.empty()) { output += ", "; }')
    ln(f'  output += "active_field=" + std::to_string(utils::to_underlying(mActiveField));')
    ln("  switch (mActiveField)")
    ln("  {")
    ln(f"  case Field::None: break;")
    for f in fields:
        sym = cpp_identifier(f.name, f.symbolic_name)
        snake = _safe_snake(sym)
        ln(f"  case Field::{sym}:")
        ln(f'    output += ", {snake}=" + ua::to_string(m{sym});')
        ln("    break;")
    ln("  }")
    ln("}")
    ln()

    ln(f"std::string {type_name}::to_string(int indent) const")
    ln("{")
    ln('  if (indent > 0)')
    ln('  {')
    # `renderedFields`, not `fields`: a type with a "Fields" member emits a `fields()` accessor,
    # which a local named `fields` would shadow (cppcheck shadowFunction).
    ln('    std::string renderedFields;')
    ln('    append_fields(renderedFields, indent + 2);')
    ln('    if (renderedFields.empty()) { return std::string(typeName) + "{}"; }')
    ln("    std::string pad(numeric_cast<size_t>(indent), ' ');")
    ln('    return std::string(typeName) + "{\\n" + renderedFields + "\\n" + pad + "}";')
    ln('  }')
    ln('  std::string renderedFields;')
    ln('  append_fields(renderedFields);')
    ln('  return std::string(typeName) + "{" + renderedFields + "}";')
    ln("}")
    ln()

    # built_in_type_id
    ln(f"BuiltInTypeId {type_name}::built_in_type_id()")
    ln("{")
    ln("  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};")
    ln("}")
    ln()

    result = "".join(lines)
    # Qualify the remaining ``ua::<Type>`` references (encode/decode signatures,
    # is_of_type, etc.) with the emitting spec's namespace. For NS0 the target
    # equals the literal, so this is a no-op (byte-identical). The encode_id /
    # register_type / create bodies were already built fully-qualified above and
    # are unaffected (they no longer contain the bare ``ua::<Type>`` literal).
    if cpp_namespace != "ua":
        result = result.replace(f"ua::{type_name}", qualified)
    return result


def emit_union_sources_into(
        index: NodeSetIndex,
        union_node_ids: list[str],
) -> str:
    """Generate source content for all union types (to be included in the data-type body TU(s))."""
    source_lines: list[str] = []
    for node_id in union_node_ids:
        source_lines.append(_create_union_source_content(index, node_id))
    return "".join(source_lines)
