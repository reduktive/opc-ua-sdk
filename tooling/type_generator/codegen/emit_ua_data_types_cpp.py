# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit the data-type encode/decode/register bodies.

When amalgamating (NS0) the bodies are sharded across a fixed number of
``<prefix>data_types_<k>.cpp`` TUs (no single monolithic aggregate is emitted);
otherwise one ``<prefix><snake>.cpp`` is emitted per structure / union.

``AggregateSourceEmitter`` wraps both per-structure and per-union body
generation behind a single ``emit(...)`` method.  The per-structure /
per-union body builders stay as module-level helpers (they read the
index but don't carry any per-emitter state) so they can also be
imported by the union emitter without going through a class boundary.
"""

from __future__ import annotations

from pathlib import Path

from ..io import load_template, write_file
from ..naming import cpp_identifier, get_symbolic_name
from ..nodeset.index import NodeSetIndex
from ..types.model import DataTypeKind
from .context import EmitContext
from .emit_structures import (
    _emit_resolve_field_lines,
    _field_cpp_type,
    _field_is_variant,
    _safe_snake,
    _struct_own_fields_need_resolve,
)
from .parts import get_part


def _append_line(buf: list[str], line: str = "") -> None:
    buf.append(line + "\n")


def _field_to_string_expression(type_name: str, field_name: str, fallback: str) -> str:
    """Return a field renderer for specification-defined textual forms."""
    if (type_name, field_name) == ("CurrencyUnitType", "NumericCode"):
        return ("[&]{ const auto code = numeric_code(); const auto text = ua::to_string(code); "
                "if (code >= 0 && code < 10) return std::string{\"00\"} + text; "
                "if (code >= 10 && code < 100) return std::string{\"0\"} + text; return text; }()")
    return fallback


def _create_structure_source_content(
    index: NodeSetIndex, node_id: str, binary_encoding_type_names: set[str] | None = None,
    cpp_namespace: str = "ua", resolver=None,
) -> str:
    node = index.find(node_id)
    if node is None:
        raise KeyError(node_id)

    text = load_template("structure_source.in")
    parts = load_template("structure_parts.in")

    type_name = get_symbolic_name(node.browse_name)
    parent = index.find(node.parent_node_id or "")
    parent_name = get_symbolic_name(parent.browse_name) if parent is not None else "Structure"

    fields = node.definition.fields if node.definition is not None else []

    # A concrete structure without a Default Binary encoding Object is not
    # encodable (the encode-id/register bodies reference
    # `ObjectId::<Type>_Encoding_DefaultBinary`), so it is emitted without codec
    # machinery, exactly like an abstract type. See `emit_structure_header`.
    is_encodable = binary_encoding_type_names is None or type_name in binary_encoding_type_names
    omit_codec = node.is_abstract or not is_encodable

    if omit_codec:
        text = text.replace("PLACEHOLDER_ENCODE_ID_DETAILS", "")
        text = text.replace("PLACEHOLDER_CREATE", "")
        text = text.replace("PLACEHOLDER_CLONE_DEFINITION", "")
        text = text.replace("PLACEHOLDER_REGISTER_DEFINITION", "")
        text = text.replace("PLACEHOLDER_ENCODE_ID_BODY", get_part(parts, "PLACEHOLDER_ENCODE_ID_EMPTY_BODY"))
    else:
        text = text.replace("PLACEHOLDER_ENCODE_ID_DETAILS", get_part(parts, "PLACEHOLDER_ENCODE_ID_DETAILS"))
        text = text.replace("PLACEHOLDER_CREATE", get_part(parts, "PLACEHOLDER_CREATE"))
        text = text.replace("PLACEHOLDER_CLONE_DEFINITION", get_part(parts, "PLACEHOLDER_CLONE_DEFINITION"))
        text = text.replace("PLACEHOLDER_REGISTER_DEFINITION", get_part(parts, "PLACEHOLDER_REGISTER_DEFINITION"))
        text = text.replace("PLACEHOLDER_ENCODE_ID_BODY", get_part(parts, "PLACEHOLDER_ENCODE_ID_BODY"))

    if not fields:
        text = text.replace("PLACEHOLDER_ENCODING_DETAILS", "")
        text = text.replace("PLACEHOLDER_ENCODE_BODY", get_part(parts, "PLACEHOLDER_ENCODE_EMPTY_BODY"))
        text = text.replace("PLACEHOLDER_DECODE_BODY", get_part(parts, "PLACEHOLDER_DECODE_EMPTY_BODY"))
        encode_bin = ""
        encode_xml = ""
        decode_bin = ""
        decode_xml = ""
    else:
        text = text.replace("PLACEHOLDER_ENCODING_DETAILS", get_part(parts, "PLACEHOLDER_ENCODING_DETAILS"))
        text = text.replace("PLACEHOLDER_ENCODE_BODY", get_part(parts, "PLACEHOLDER_ENCODE_BODY"))
        text = text.replace("PLACEHOLDER_DECODE_BODY", get_part(parts, "PLACEHOLDER_DECODE_BODY"))

        # Encode/decode emission: handles enums, option sets, ref wrappers, optional fields.
        enc_bin_lines: list[str] = []
        enc_xml_lines: list[str] = []
        dec_bin_lines: list[str] = []
        dec_xml_lines: list[str] = []

        from ..naming import to_snake_case

        needs_enum_temp = False

        # Identify optional fields and assign bit indices for the encoding mask.
        optional_fields = [(i, f) for i, f in enumerate(fields) if f.is_optional]
        has_optional = len(optional_fields) > 0
        optional_bit_index: dict[int, int] = {}  # field index -> bit index
        for bit_idx, (field_idx, _) in enumerate(optional_fields):
            optional_bit_index[field_idx] = bit_idx

        if has_optional:
            # Encode: compute and write the encoding mask.
            _append_line(enc_bin_lines, "  uint32_t encodingMask = 0;")
            _append_line(enc_xml_lines, "  uint32_t encodingMask = 0;")
            for field_idx, bit_idx in optional_bit_index.items():
                f = fields[field_idx]
                snake = _safe_snake(cpp_identifier(f.name, f.symbolic_name))
                _append_line(enc_bin_lines,
                             f"  if (value.{snake}().has_value()) encodingMask |= (1u << {bit_idx});")
                _append_line(enc_xml_lines,
                             f"  if (value.{snake}().has_value()) encodingMask |= (1u << {bit_idx});")
            _append_line(enc_bin_lines, "  encoder.encode(limit, encodingMask);")
            _append_line(enc_xml_lines, "  encoder.encode(limit, \"EncodingMask\", encodingMask);")

            # Decode: read the encoding mask and validate.
            valid_bits_hex = hex((1 << len(optional_fields)) - 1) + "u"
            _append_line(dec_bin_lines, "  uint32_t encodingMask{};")
            _append_line(dec_bin_lines, "  decoder.decode(limit, encodingMask);")
            _append_line(dec_bin_lines, f"  if ((encodingMask & ~{valid_bits_hex}) != 0)")
            _append_line(dec_bin_lines, "    throw UaException(Status::BadDecodingError);")
            _append_line(dec_xml_lines, "  uint32_t encodingMask{};")
            _append_line(dec_xml_lines, "  decoder.decode(limit, \"EncodingMask\", true, encodingMask);")
            _append_line(dec_xml_lines, f"  if ((encodingMask & ~{valid_bits_hex}) != 0)")
            _append_line(dec_xml_lines, "    throw UaException(Status::BadDecodingError);")

        for field_idx, f in enumerate(fields):
            field_sym = cpp_identifier(f.name, f.symbolic_name)
            # The XML wire element name must stay the original spec field name -
            # SymbolicName only affects the C++ identifier, never the encoding.
            # (``get_symbolic_name`` here preserves the exact pre-existing wire
            # spelling so NS0 output stays byte-identical.)
            field_wire = get_symbolic_name(f.name)
            snake = _safe_snake(field_sym)
            is_opt = field_idx in optional_bit_index

            # Access expression for the field VALUE - dereference for optional
            # fields. Presence of an optional field is gated by its encoding-mask
            # bit (see the optional wrapping below), so after `.emplace()` we
            # encode/decode straight into the emplaced value; no `decode(optional<T>)`
            # overload is needed. `member_expr` (the optional itself) is retained
            # only for `.emplace()` / `.has_value()`.
            member_expr = f"value.{snake}()"
            # For optional fields the encode/decode blocks below bind the optional to a local
            # `optField`, so the per-field access dereferences that bound local rather than a fresh
            # `value.{snake}()` call. This keeps the has_value()/emplace() check and the deref on the
            # SAME optional instance - clang-tidy bugprone-unchecked-optional-access cannot prove that
            # two separate getter calls return the same optional.
            member_access = "(*optField)" if is_opt else member_expr

            # Array fields use the codec's `Array<T>` overloads (which include the
            # `requires IsEnum<T>` specialisation that converts enum elements to
            # int32), not the scalar enum / option-set paths below.
            is_array = f.value_rank is not None and f.value_rank > 0

            # Determine the encode/decode lines for this field (without optional wrapping).
            enc_bin_field: list[str] = []
            enc_xml_field: list[str] = []
            dec_bin_field: list[str] = []
            dec_xml_field: list[str] = []

            if f.data_type is None:
                enc_bin_field.append(f"  encoder.encode(limit, {member_access});")
                enc_xml_field.append(f"  encoder.encode(limit, \"{field_wire}\", {member_access});")
                dec_bin_field.append(f"  decoder.decode(limit, {member_access});")
                dec_xml_field.append(f"  decoder.decode(limit, \"{field_wire}\", true, {member_access});")
            else:
                dt_node = index.find(f.data_type)

                if (dt_node is not None and dt_node.definition is not None
                        and dt_node.definition.is_option_set and not is_array):
                    option_type_name = get_symbolic_name(dt_node.browse_name)
                    enc_bin_field.append(f"  encoder.encode(limit, {member_access}.as_underlying_type());")
                    enc_xml_field.append(
                        f"  encoder.encode(limit, \"{field_wire}\", {member_access}.as_underlying_type());")
                    dec_bin_field.append("  {")
                    dec_bin_field.append(f"    {option_type_name}::UnderlyingType val{{}};")
                    dec_bin_field.append("    decoder.decode(limit, val);")
                    dec_bin_field.append(f"    {member_access}.from_underlying_type(val);")
                    dec_bin_field.append("  }")
                    dec_xml_field.append("  {")
                    dec_xml_field.append(f"    {option_type_name}::UnderlyingType val{{}};")
                    dec_xml_field.append(f"    decoder.decode(limit, \"{field_wire}\", true, val);")
                    dec_xml_field.append(f"    {member_access}.from_underlying_type(val);")
                    dec_xml_field.append("  }")

                elif (index.is_subtype_of(f.data_type, "Enumeration") and not is_array
                      and not _field_is_variant(index, f)):
                    # A field stored as Variant (AllowSubTypes/abstract) is not the
                    # concrete enum, so the enum->int32 path would not compile. Fall
                    # through to the generic (Variant) encode below.
                    enum_type_node = index.find(f.data_type)
                    # Resolver-qualified so a cross-spec enum (e.g.
                    # ::ua::machinery_result::ResultEvaluationEnum from ua::ijt_base) is
                    # declared; the member type is qualified the same way. NS0 resolves
                    # to the bare name -> byte-identical.
                    if resolver is not None and enum_type_node is not None:
                        enum_type_name = resolver.resolve(f.data_type).qualified_class_name
                    elif enum_type_node is not None:
                        enum_type_name = get_symbolic_name(enum_type_node.browse_name)
                    else:
                        enum_type_name = "int32_t"
                    enc_bin_field.append(f"  encoder.encode(limit, utils::as_int32({member_access}));")
                    enc_xml_field.append(
                        f"  encoder.encode(limit, \"{field_wire}\", utils::as_int32({member_access}));")
                    needs_enum_temp = True
                    dec_bin_field.append("  decoder.decode(limit, enumVal);")
                    dec_bin_field.append(
                        f"  {member_access} = utils::from_underlying<{enum_type_name}>(enumVal);")
                    dec_xml_field.append(f"  decoder.decode(limit, \"{field_wire}\", true, enumVal);")
                    dec_xml_field.append(
                        f"  {member_access} = utils::from_underlying<{enum_type_name}>(enumVal);")

                else:
                    field_cpp_type = _field_cpp_type(index, f, resolver)
                    # Strip optional<> wrapper to check inner type for RefMember/RefStructure.
                    inner_cpp_type = field_cpp_type
                    if inner_cpp_type.startswith("optional<") and inner_cpp_type.endswith(">"):
                        inner_cpp_type = inner_cpp_type[len("optional<"):-1]

                    if inner_cpp_type.startswith("RefMember<") or inner_cpp_type.startswith("RefStructure<"):
                        enc_bin_field.append(f"  encoder.encode(limit, {member_access}.get());")
                        enc_xml_field.append(
                            f"  encoder.encode(limit, \"{field_wire}\", {member_access}.get());")
                        dec_bin_field.append(f"  decoder.decode(limit, {member_access}.inner_unique_ptr());")
                        dec_xml_field.append(
                            f"  decoder.decode(limit, \"{field_wire}\", true, {member_access}.inner_unique_ptr());")
                    else:
                        encode_access = member_access
                        if (type_name, field_sym) == ("PortableNodeId", "Identifier"):
                            encode_access = ("[&]{ auto identifier = value.identifier(); "
                                             "identifier.namespace_index() = 0; return identifier; }()")
                        enc_bin_field.append(f"  encoder.encode(limit, {encode_access});")
                        enc_xml_field.append(f"  encoder.encode(limit, \"{field_wire}\", {encode_access});")
                        dec_bin_field.append(f"  decoder.decode(limit, {member_access});")
                        dec_xml_field.append(
                            f"  decoder.decode(limit, \"{field_wire}\", true, {member_access});")

            # Wrap optional fields in conditionals.
            if is_opt:
                bit_idx = optional_bit_index[field_idx]
                # Encode: only if has_value. Bind the optional to `optField` (init-statement) so the
                # has_value() check and the *optField deref in the field lines are the SAME optional.
                _append_line(enc_bin_lines, f"  if (const auto& optField = value.{snake}(); optField.has_value())")
                _append_line(enc_bin_lines, "  {")
                for line in enc_bin_field:
                    _append_line(enc_bin_lines, "  " + line)
                _append_line(enc_bin_lines, "  }")

                _append_line(enc_xml_lines, f"  if (const auto& optField = value.{snake}(); optField.has_value())")
                _append_line(enc_xml_lines, "  {")
                for line in enc_xml_field:
                    _append_line(enc_xml_lines, "  " + line)
                _append_line(enc_xml_lines, "  }")

                # Decode: only if bit set in encoding mask; bind + emplace, then decode into *optField.
                _append_line(dec_bin_lines, f"  if (encodingMask & (1u << {bit_idx}))")
                _append_line(dec_bin_lines, "  {")
                _append_line(dec_bin_lines, f"    auto& optField = {member_expr};")
                _append_line(dec_bin_lines, f"    optField.emplace();")
                for line in dec_bin_field:
                    _append_line(dec_bin_lines, "  " + line)
                _append_line(dec_bin_lines, "  }")

                _append_line(dec_xml_lines, f"  if (encodingMask & (1u << {bit_idx}))")
                _append_line(dec_xml_lines, "  {")
                _append_line(dec_xml_lines, f"    auto& optField = {member_expr};")
                _append_line(dec_xml_lines, f"    optField.emplace();")
                for line in dec_xml_field:
                    _append_line(dec_xml_lines, "  " + line)
                _append_line(dec_xml_lines, "  }")
            else:
                for line in enc_bin_field:
                    _append_line(enc_bin_lines, line)
                for line in enc_xml_field:
                    _append_line(enc_xml_lines, line)
                for line in dec_bin_field:
                    _append_line(dec_bin_lines, line)
                for line in dec_xml_field:
                    _append_line(dec_xml_lines, line)

        encode_bin = "".join(enc_bin_lines).rstrip("\n")
        encode_xml = "".join(enc_xml_lines).rstrip("\n")
        decode_bin = "".join(dec_bin_lines).rstrip("\n")
        decode_xml = "".join(dec_xml_lines).rstrip("\n")

        if needs_enum_temp:
            decode_bin = "  int32_t enumVal{};\n" + decode_bin
            decode_xml = "  int32_t enumVal{};\n" + decode_xml

    # Fully-qualified class name (``ua::Foo`` for NS0, ``ua::di::Foo`` for a
    # companion spec) - must precede the bare PLACEHOLDER_CLASS_NAME replace
    # since the qualified token embeds it. Used in the detail:: encode/decode/
    # create bodies where the bare name would otherwise resolve to the
    # enclosing ``detail::Foo`` namespace, not the type.
    qualified = f"{cpp_namespace}::{type_name}"

    # encode_id writes the type's Default{Binary,Xml} encoding NodeId on the wire.
    # NS0's encoding ids live in namespace 0, so ``NodeId{ObjectId}`` (the enum
    # ctor) is correct and ``ns`` is unused.  A companion spec's encoding ids live
    # in the spec's namespace, whose runtime index isn't known at compile time -
    # resolve it from ``ns`` via the spec URI and build the NodeId from the numeric
    # id obtained with ``utils::to_underlying`` (no ``static_cast`` for enums per
    # cpp_style.md).  (``NodeId`` has no ctor for a companion ``ObjectId`` enum, and
    # the index is dynamic, so this is the only correct form - and it is exactly the
    # runtime ns-index resolution Phase 7 row 6 validates.)
    if cpp_namespace == "ua":
        encode_id_bin = (
            f"UA_UNUSED(ns);\n"
            f"encoder.encode(limit, NodeId{{{qualified}::defaultBinaryEncodingId}});"
        )
        encode_id_xml = (
            f"UA_UNUSED(ns);\n"
            f'encoder.encode(limit, "TypeId", NodeId{{{qualified}::defaultXmlEncodingId}});'
        )
    else:
        encode_id_bin = (
            f"encoder.encode(limit, NodeId{{ns.getNamespaceIndex(specNamespaceUri), "
            f"utils::to_underlying({qualified}::defaultBinaryEncodingId)}});"
        )
        encode_id_xml = (
            f'encoder.encode(limit, "TypeId", NodeId{{ns.getNamespaceIndex(specNamespaceUri), '
            f"utils::to_underlying({qualified}::defaultXmlEncodingId)}});"
        )
    text = text.replace("PLACEHOLDER_ENCODE_ID_BIN_BODY", encode_id_bin)
    text = text.replace("PLACEHOLDER_ENCODE_ID_XML_BODY", encode_id_xml)

    # register_type registers the encoding NodeIds with the StructureFactory.
    # Same NS0-vs-companion split as encode_id: NS0 uses the ObjectId enum ctor
    # (ns 0, ``ns`` unused); a companion spec resolves its namespace index from
    # ``ns`` at runtime and builds the NodeId from the numeric encoding id.
    if cpp_namespace == "ua":
        text = text.replace("PLACEHOLDER_REGISTER_NS_UNUSED", "  UA_UNUSED(ns);\n")
        text = text.replace("PLACEHOLDER_REGISTER_BIN_ID", "NodeId(defaultBinaryEncodingId)")
        text = text.replace("PLACEHOLDER_REGISTER_XML_ID", "NodeId(defaultXmlEncodingId)")
    else:
        text = text.replace("PLACEHOLDER_REGISTER_NS_UNUSED", "")
        text = text.replace(
            "PLACEHOLDER_REGISTER_BIN_ID",
            "NodeId(ns.getNamespaceIndex(specNamespaceUri), "
            "utils::to_underlying(defaultBinaryEncodingId))")
        text = text.replace(
            "PLACEHOLDER_REGISTER_XML_ID",
            "NodeId(ns.getNamespaceIndex(specNamespaceUri), "
            "utils::to_underlying(defaultXmlEncodingId))")

    text = text.replace("PLACEHOLDER_QUALIFIED_CLASS_NAME", qualified)
    text = text.replace("PLACEHOLDER_CLASS_NAME", type_name)
    text = text.replace("PLACEHOLDER_BASE_CLASS_NAME", parent_name)

    # These placeholders are used only inside template parts.
    text = text.replace("PLACEHOLDER_ENCODE_BIN_CONTENTS", encode_bin)
    text = text.replace("PLACEHOLDER_ENCODE_XML_CONTENTS", encode_xml)
    text = text.replace("PLACEHOLDER_DECODE_BIN_CONTENTS", decode_bin)
    text = text.replace("PLACEHOLDER_DECODE_XML_CONTENTS", decode_xml)

    # Field accessor definitions.
    accessor_defs: list[str] = []
    from ..naming import to_snake_case

    for f in fields:
        field_sym = cpp_identifier(f.name, f.symbolic_name)
        type_text = _field_cpp_type(index, f, resolver)
        snake = _safe_snake(field_sym)
        _append_line(accessor_defs, f"{type_text}& {type_name}::{snake}()")
        _append_line(accessor_defs, "{")
        if (type_name, field_sym) == ("PortableNodeId", "Identifier"):
            _append_line(accessor_defs, "  mIdentifier.namespace_index() = 0;")
        _append_line(accessor_defs, f"  return m{field_sym};")
        _append_line(accessor_defs, "}")
        _append_line(accessor_defs)
        _append_line(accessor_defs, f"const {type_text}& {type_name}::{snake}() const")
        _append_line(accessor_defs, "{")
        if (type_name, field_sym) == ("PortableNodeId", "Identifier"):
            _append_line(accessor_defs, "  mIdentifier.namespace_index() = 0;")
        _append_line(accessor_defs, f"  return m{field_sym};")
        _append_line(accessor_defs, "}")
        _append_line(accessor_defs)

    text = text.replace("PLACEHOLDER_FIELD_ACCESSORS", "".join(accessor_defs).rstrip("\n"))

    # to_string() and append_fields() definitions
    to_string_lines: list[str] = []

    # append_fields(output, indent) - branches on indent for compact vs indented output
    if fields:
        _append_line(to_string_lines, f"void {type_name}::append_fields(std::string& output, int indent) const")
        _append_line(to_string_lines, "{")
        _append_line(to_string_lines, f"  {parent_name}::append_fields(output, indent);")
        _append_line(to_string_lines, f"  if (indent > 0)")
        _append_line(to_string_lines, f"  {{")
        _append_line(to_string_lines, f"    std::string pad(numeric_cast<size_t>(indent), ' ');")

        for i, f in enumerate(fields):
            field_sym = cpp_identifier(f.name, f.symbolic_name)
            snake = _safe_snake(field_sym)
            field_cpp_type = _field_cpp_type(index, f, resolver)

            _append_line(to_string_lines, '    if (!output.empty()) { output += ",\\n"; }')

            is_array = f.value_rank is not None and f.value_rank > 0

            # Determine value expression with indent threading for nested structures/arrays.
            # The scalar enum->int32 stringify only applies to scalar enum fields; an
            # array-of-enum falls through to the generic `Array<...>` to_string path.
            dt_node = index.find(f.data_type) if f.data_type is not None else None
            is_enum_scalar = (f.data_type is not None
                              and index.is_subtype_of(f.data_type, "Enumeration")
                              and not is_array
                              and not _field_is_variant(index, f))
            is_option_set = (dt_node is not None and dt_node.definition is not None
                             and dt_node.definition.is_option_set)

            # Branch on the C++ field type (not on data_type being set) so a
            # no-DataType field (defaults to Variant) that is optional<>/Array<>
            # still picks a valid path instead of the bare scalar else - there is
            # no ua::to_string(optional<Variant>) / to_string(Array<...>) overload.
            if is_enum_scalar:
                if f.is_optional:
                    val_expr = (f'[&]{{ const auto& o = {snake}(); return o.has_value() ? '
                                f'ua::to_string(utils::as_int32(*o)) : "null"; }}()')
                else:
                    val_expr = f'ua::to_string(utils::as_int32({snake}()))'
            elif is_option_set:
                val_expr = f'ua::to_string({snake}().as_underlying_type())'
            elif field_cpp_type.startswith("RefStructure<") or field_cpp_type.startswith("RefMember<"):
                val_expr = f'({snake}() ? {snake}()->to_string(indent) : "null")'
            elif field_cpp_type.startswith("optional<"):
                inner = field_cpp_type[len("optional<"):-1]
                if inner.startswith("RefStructure<") or inner.startswith("RefMember<"):
                    val_expr = f'[&]{{ const auto& o = {snake}(); return o.has_value() && *o ? (*o)->to_string(indent) : "null"; }}()'
                else:
                    val_expr = f'[&]{{ const auto& o = {snake}(); return o.has_value() ? ua::to_string(*o) : "null"; }}()'
            elif field_cpp_type.startswith("Array<RefStructure<") or field_cpp_type.startswith("Array<RefMember<"):
                val_expr = f'ua::to_string({snake}(), indent)'
            elif field_cpp_type.startswith("Array<"):
                val_expr = f'ua::to_string({snake}())'
            else:
                val_expr = f'ua::to_string({snake}())'

            val_expr = _field_to_string_expression(type_name, field_sym, val_expr)
            _append_line(to_string_lines,
                         f'    output += pad + "{snake}=" + {val_expr};')

        _append_line(to_string_lines, f"    return;")
        _append_line(to_string_lines, f"  }}")

        # Compact (indent == 0) path
        for i, f in enumerate(fields):
            field_sym = cpp_identifier(f.name, f.symbolic_name)
            snake = _safe_snake(field_sym)
            field_cpp_type = _field_cpp_type(index, f, resolver)

            _append_line(to_string_lines, "  if (!output.empty()) { output += \", \"; }")

            is_array = f.value_rank is not None and f.value_rank > 0

            # Scalar enum->int32 stringify only; array-of-enum falls through to the
            # generic `Array<...>` to_string path below.
            dt_node = index.find(f.data_type) if f.data_type is not None else None
            is_enum_scalar = (f.data_type is not None
                              and index.is_subtype_of(f.data_type, "Enumeration")
                              and not is_array
                              and not _field_is_variant(index, f))
            is_option_set = (dt_node is not None and dt_node.definition is not None
                             and dt_node.definition.is_option_set)

            # Type-driven branch (see the indented loop above): a no-DataType
            # optional<>/Array<> field must not fall to the bare scalar else.
            if is_enum_scalar:
                if f.is_optional:
                    _append_line(to_string_lines,
                                 f'  output += "{snake}=" + [&]{{ const auto& o = {snake}(); return o.has_value() ? '
                                 f'ua::to_string(utils::as_int32(*o)) : "null"; }}();')
                else:
                    _append_line(to_string_lines,
                                 f'  output += "{snake}=" + ua::to_string(utils::as_int32({snake}()));')
            elif is_option_set:
                _append_line(to_string_lines,
                             f'  output += "{snake}=" + ua::to_string({snake}().as_underlying_type());')
            elif field_cpp_type.startswith("RefStructure<") or field_cpp_type.startswith("RefMember<"):
                _append_line(to_string_lines,
                             f'  output += "{snake}=" + ({snake}() ? {snake}()->to_string(0) : "null");')
            elif field_cpp_type.startswith("optional<"):
                inner = field_cpp_type[len("optional<"):-1]
                if inner.startswith("RefStructure<") or inner.startswith("RefMember<"):
                    _append_line(to_string_lines,
                                 f'  output += "{snake}=" + [&]{{ const auto& o = {snake}(); return o.has_value() && *o ? (*o)->to_string(0) : "null"; }}();')
                else:
                    _append_line(to_string_lines,
                                 f'  output += "{snake}=" + [&]{{ const auto& o = {snake}(); return o.has_value() ? ua::to_string(*o) : "null"; }}();')
            elif field_cpp_type.startswith("Array<"):
                _append_line(to_string_lines,
                             f'  output += "{snake}=" + ua::to_string({snake}());')
            else:
                val_expr = _field_to_string_expression(type_name, field_sym, f'ua::to_string({snake}())')
                _append_line(to_string_lines,
                             f'  output += "{snake}=" + {val_expr};')

        _append_line(to_string_lines, "}")
        _append_line(to_string_lines)

    # to_string(indent) - branches on indent for compact vs indented output
    if not node.is_abstract:
        _append_line(to_string_lines, f"std::string {type_name}::to_string(int indent) const")
        _append_line(to_string_lines, "{")
        _append_line(to_string_lines, f'  if (indent > 0)')
        _append_line(to_string_lines, f'  {{')
        # `renderedFields`, not `fields`: a type with a "Fields" member emits a `fields()` accessor,
        # which a local named `fields` would shadow (cppcheck shadowFunction).
        _append_line(to_string_lines, f'    std::string renderedFields;')
        _append_line(to_string_lines, f'    append_fields(renderedFields, indent + 2);')
        _append_line(to_string_lines, f'    if (renderedFields.empty()) {{ return std::string(typeName) + "{{}}"; }}')
        _append_line(to_string_lines, f'    std::string pad(numeric_cast<size_t>(indent), \' \');')
        _append_line(to_string_lines, f'    return std::string(typeName) + "{{\\n" + renderedFields + "\\n" + pad + "}}";')
        _append_line(to_string_lines, f'  }}')
        _append_line(to_string_lines, f'  std::string renderedFields;')
        _append_line(to_string_lines, f'  append_fields(renderedFields);')
        _append_line(to_string_lines, f'  return std::string(typeName) + "{{" + renderedFields + "}}";')
        _append_line(to_string_lines, "}")

    text = text.replace("PLACEHOLDER_TO_STRING_DEFINITION", "".join(to_string_lines).rstrip("\n"))

    # resolve(span<const LocaleId>) override body - emitted only when
    # this struct's OWN fields transitively reference LocalizedText.
    if _struct_own_fields_need_resolve(index, node_id):
        resolve_lines: list[str] = []
        resolve_lines.append(f"void {type_name}::resolve(span<const LocaleId> locales)\n")
        resolve_lines.append("{\n")
        resolve_lines.append(f"  {parent_name}::resolve(locales);\n")
        for f in fields:
            _emit_resolve_field_lines(index, f, resolve_lines)
        resolve_lines.append("}\n")
        text = text.replace("PLACEHOLDER_RESOLVE_DEFINITION", "".join(resolve_lines).rstrip("\n"))
    else:
        text = text.replace("PLACEHOLDER_RESOLVE_DEFINITION", "")

    return text


class AggregateSourceEmitter:
    """Emits the structure / union encode/decode/register bodies.

    With ``ctx.amalgamate_sources`` (NS0) the bodies are amalgamated across a
    small, fixed number of shard TUs (``<prefix>data_types_<k>.cpp``) - a
    build-time optimisation. One monolithic TU compiles on a single core (a
    ~30s serial long-pole) and is a coarse ccache/memory unit; a handful of
    shards restores build parallelism while still parsing the heavy codec
    headers only a few times (vs once-per-type if fully split). Otherwise
    (consumer specs) one ``<prefix><snake>.cpp`` is emitted per structure /
    union. Either way ``emit`` returns ``(paths, source_names)`` so the CMake
    emitter can list the produced sources.
    """

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit(
        self,
        structure_node_ids_in_order: list[str],
        generated_headers: list[str],
        binary_encoding_type_names: set[str] | None = None,
    ) -> tuple[list[Path], list[str]]:
        if self._ctx.amalgamate_sources:
            return _emit_aggregate_sources(
                self._ctx,
                structure_node_ids_in_order,
                generated_headers,
                binary_encoding_type_names,
            )
        return _emit_per_type_sources(
            self._ctx,
            structure_node_ids_in_order,
            generated_headers,
            binary_encoding_type_names,
        )


def _structure_body(
    ctx: EmitContext, node_id: str, binary_encoding_type_names: set[str] | None
) -> str:
    """Encode/decode/method body for one structure or union (no file wrapper)."""
    from .emit_unions import _create_union_source_content

    node = ctx.index.find(node_id)
    definition = node.definition if node is not None else None
    is_union = (
        (definition is not None and definition.is_union)
        or ctx.index.is_subtype_of(node_id, "Union")
    )
    if is_union:
        return _create_union_source_content(
            ctx.index, node_id, ctx.cpp_namespace, ctx.resolver
        ).rstrip("\n")
    return _create_structure_source_content(
        ctx.index, node_id, binary_encoding_type_names, ctx.cpp_namespace, ctx.resolver
    ).rstrip("\n")


def _emit_per_type_sources(
    ctx: EmitContext,
    structure_node_ids_in_order: list[str],
    generated_headers: list[str],
    binary_encoding_type_names: set[str] | None,
) -> tuple[list[Path], list[str]]:
    """One ``<prefix><snake>.cpp`` per structure / union.

    Each TU pulls the shared codec prologue (from ``structure_type_source.in``)
    plus only its own generated header - which already includes the type's base
    class and field-type headers.
    """
    paths: list[Path] = []
    names: list[str] = []
    for node_id, header in zip(structure_node_ids_in_order, generated_headers):
        body = _structure_body(ctx, node_id, binary_encoding_type_names)
        wrapper = ctx.apply_template(load_template("structure_type_source.in"))
        wrapper = wrapper.replace("PLACEHOLDER_INCLUDES", f'#include "{header}"')
        wrapper = wrapper.replace("PLACEHOLDER_SOURCE_CODE", body)
        basename = header.removesuffix(".h") + ".cpp"
        out_path = ctx.implementation_dir_for("data_types") / basename
        write_file(out_path, wrapper)
        paths.append(out_path)
        names.append(basename)
    return paths, names


# Number of shard TUs the amalgamated data-type bodies are split across. One
# monolithic TU compiles on a single core (a ~30s serial build long-pole) and is a
# coarse ccache/memory unit; splitting the bodies into a few balanced shards
# restores build parallelism while parsing the heavy codec headers only this many
# times (vs once-per-type if fully reverted to per-type files - measured ~3s each
# even with PCH, since the codec headers are not in the PCH). 8 bounds that
# header re-parse and fits CI's -j width in roughly one wave. Generated code is
# regenerated wholesale, so the usual unity-build "edit one file, rebuild the
# batch" downside does not apply here.
_AGGREGATE_SHARD_COUNT = 8


def _emit_aggregate_sources(
    ctx: EmitContext,
    structure_node_ids_in_order: list[str],
    generated_headers: list[str],
    binary_encoding_type_names: set[str] | None,
) -> tuple[list[Path], list[str]]:
    # Shared include block: every shard includes all generated type headers so a
    # body in any shard can reference any other generated type (field types, bases).
    include_lines: list[str] = []
    seen: set[str] = set()
    for h in generated_headers:
        if h in seen:
            continue
        seen.add(h)
        _append_line(include_lines, f'#include "{h}"')
    includes = "".join(include_lines).rstrip("\n")

    # Partition bodies across shards round-robin by emission index: equal counts,
    # with large/small types interleaved for size balance. Deterministic (same
    # input order -> same assignment); order within a shard preserves emission
    # order so the generated output stays stable diff-to-diff.
    shard_count = max(1, min(_AGGREGATE_SHARD_COUNT, len(structure_node_ids_in_order)))
    buckets: list[list[str]] = [[] for _ in range(shard_count)]
    for idx, node_id in enumerate(structure_node_ids_in_order):
        buckets[idx % shard_count].append(node_id)

    paths: list[Path] = []
    names: list[str] = []
    for shard_idx, bucket in enumerate(buckets):
        if not bucket:
            continue
        source_lines: list[str] = []
        for node_id in bucket:
            _append_line(source_lines, _structure_body(ctx, node_id, binary_encoding_type_names))
            _append_line(source_lines)
        source_code = "".join(source_lines).rstrip("\n")

        wrapper = ctx.apply_template(load_template("structure_type_source.in"))
        wrapper = wrapper.replace("PLACEHOLDER_INCLUDES", includes)
        wrapper = wrapper.replace("PLACEHOLDER_SOURCE_CODE", source_code)

        basename = f"{ctx.include_prefix}data_types_{shard_idx}.cpp"
        out_path = ctx.implementation_dir / basename
        write_file(out_path, wrapper)
        paths.append(out_path)
        names.append(basename)
    return paths, names
