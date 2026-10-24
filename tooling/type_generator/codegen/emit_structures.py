# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit headers for ``UAStructure`` types.

``StructureEmitter`` owns one ``EmitContext`` (one spec) and exposes
``emit(node_id, binary_encoding_type_names)`` returning the path of the
emitted header.  All ad-hoc helpers used to live as module-level free
functions; they still do (they are referentially transparent and don't
need to be class methods), but the entry point is now a method on a
class so future per-emitter state has somewhere to live.
"""

from __future__ import annotations

from pathlib import Path

from ..io import load_template, write_file
from ..naming import clean_brief_text, cpp_identifier, get_symbolic_name, to_snake_case
from ..nodeset.index import NodeSetIndex
from ..nodeset.nodeid import parse_numeric_node_id
from .context import EmitContext
from .parts import get_part

# Memoisation cache for `_struct_contains_lt`. Shared across all
# emission calls in a generator run.
_LT_CONTAINS_MEMO: dict[str, bool] = {}

# Specification-defined field defaults that differ from C++ value-initialisation.
_FIELD_INITIALIZERS: dict[tuple[str, str], str] = {
    ("CurrencyUnitType", "NumericCode"): "{-1}",
    ("CurrencyUnitType", "Exponent"): "{-1}",
}


def _field_references_lt(index: NodeSetIndex, field, memo: dict[str, bool], visiting: set[str]) -> bool:
    """True if a field references LocalizedText directly or transitively via a nested struct."""
    if _field_is_variant(index, field):
        # Field is stored as Variant (no DataType, or abstract/AllowSubTypes) -
        # variant-level resolution is handled by `resolve_in_variant` at service
        # boundaries, not the struct walk, and a Variant has no `.resolve()`.
        return False

    dt_node = index.find(field.data_type)
    if dt_node is None:
        return False

    symbolic = get_symbolic_name(dt_node.browse_name)
    if symbolic == "LocalizedText":
        return True

    if (symbolic == "Structure") or index.is_subtype_of(field.data_type, "Structure"):
        return _struct_contains_lt(index, field.data_type, memo, visiting)

    return False


def _struct_contains_lt(index: NodeSetIndex, node_id: str, memo: dict[str, bool], visiting: set[str]) -> bool:
    """Does this struct type (including its parent chain) transitively reference LocalizedText?"""
    if node_id in memo:
        return memo[node_id]
    if node_id in visiting:
        return False
    visiting.add(node_id)

    node = index.find(node_id)
    if node is None:
        visiting.remove(node_id)
        memo[node_id] = False
        return False

    result = False

    parent_id = node.parent_node_id
    if parent_id:
        parent_node = index.find(parent_id)
        if parent_node is not None:
            parent_sym = get_symbolic_name(parent_node.browse_name)
            if parent_sym != "Structure" and _struct_contains_lt(index, parent_id, memo, visiting):
                result = True

    if not result:
        definition = node.definition
        fields = definition.fields if definition is not None else []
        for f in fields:
            if _field_references_lt(index, f, memo, visiting):
                result = True
                break

    visiting.remove(node_id)
    memo[node_id] = result
    return result


def _struct_own_fields_need_resolve(index: NodeSetIndex, node_id: str) -> bool:
    """Should this struct emit a `resolve` override for its OWN fields?"""
    node = index.find(node_id)
    if node is None:
        return False
    definition = node.definition
    if definition is None or not definition.fields:
        return False
    visiting: set[str] = set()
    for f in definition.fields:
        if _field_references_lt(index, f, _LT_CONTAINS_MEMO, visiting):
            return True
    return False


def _emit_resolve_field_lines(
    index: NodeSetIndex,
    field,
    lines: list[str],
) -> None:
    """Emit the resolve-body lines for a single field, if it references LocalizedText.

    Lines are appended with a leading two-space indent (the outer block
    already opens with `{` at column 0).
    """
    from ..naming import to_snake_case

    visiting: set[str] = set()
    if not _field_references_lt(index, field, _LT_CONTAINS_MEMO, visiting):
        return

    field_sym = cpp_identifier(field.name, field.symbolic_name)
    member = f"m{field_sym}"
    type_text = _field_cpp_type(index, field)

    is_optional = type_text.startswith("optional<") and type_text.endswith(">")
    inner = type_text[len("optional<"):-1] if is_optional else type_text

    is_array = inner.startswith("Array<") and inner.endswith(">")
    elem = inner[len("Array<"):-1] if is_array else inner

    is_ref_struct = elem.startswith("RefStructure<") or elem.startswith("RefMember<")

    dt_node = index.find(field.data_type) if field.data_type is not None else None
    dt_sym = get_symbolic_name(dt_node.browse_name) if dt_node is not None else ""
    is_lt = (dt_sym == "LocalizedText")

    def emit_walk(base_expr: str, indent: str) -> None:
        if is_array:
            lines.append(f"{indent}for (size_t i = 0; i < {base_expr}.size(); ++i)\n")
            lines.append(f"{indent}{{\n")
            elem_expr = f"{base_expr}[i]"
            if is_lt:
                lines.append(f"{indent}  {elem_expr} = {elem_expr}.resolve(locales);\n")
            elif is_ref_struct:
                lines.append(f"{indent}  if (auto* structure = {elem_expr}.get())\n")
                lines.append(f"{indent}  {{\n")
                lines.append(f"{indent}    structure->resolve(locales);\n")
                lines.append(f"{indent}  }}\n")
            else:
                lines.append(f"{indent}  {elem_expr}.resolve(locales);\n")
            lines.append(f"{indent}}}\n")
        else:
            if is_lt:
                lines.append(f"{indent}{base_expr} = {base_expr}.resolve(locales);\n")
            elif is_ref_struct:
                lines.append(f"{indent}if (auto* structure = {base_expr}.get())\n")
                lines.append(f"{indent}{{\n")
                lines.append(f"{indent}  structure->resolve(locales);\n")
                lines.append(f"{indent}}}\n")
            else:
                lines.append(f"{indent}{base_expr}.resolve(locales);\n")

    if is_optional:
        lines.append(f"  if ({member}.has_value())\n")
        lines.append(f"  {{\n")
        emit_walk(f"(*{member})", "    ")
        lines.append(f"  }}\n")
    else:
        emit_walk(member, "  ")


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


# C++ keywords that a snake_cased field name can collide with when used as a
# *bare* accessor (e.g. a BACnet union field ``Unsigned`` -> ``unsigned()``).
# Object-type method/property accessors never collide because they are always
# suffixed (``delete_method_async`` etc.), so this set is applied only to
# struct/union field accessors via _safe_snake().
_CPP_KEYWORDS: frozenset[str] = frozenset({
    "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor",
    "bool", "break", "case", "catch", "char", "char8_t", "char16_t",
    "char32_t", "class", "compl", "concept", "const", "consteval", "constexpr",
    "constinit", "const_cast", "continue", "co_await", "co_return", "co_yield",
    "decltype", "default", "delete", "do", "double", "dynamic_cast", "else",
    "enum", "explicit", "export", "extern", "false", "float", "for", "friend",
    "goto", "if", "inline", "int", "long", "mutable", "namespace", "new",
    "noexcept", "not", "not_eq", "nullptr", "operator", "or", "or_eq",
    "private", "protected", "public", "register", "reinterpret_cast",
    "requires", "return", "short", "signed", "sizeof", "static",
    "static_assert", "static_cast", "struct", "switch", "template", "this",
    "thread_local", "throw", "true", "try", "typedef", "typeid", "typename",
    "union", "unsigned", "using", "virtual", "void", "volatile", "wchar_t",
    "while", "xor", "xor_eq",
})


def _safe_snake(name: str) -> str:
    """snake_case ``name``, appending ``_`` if the result is a C++ keyword.

    Used for *bare* struct/union field accessors. A no-op for any name whose
    snake form is not a keyword, so NS0 output stays byte-identical (NS0 has no
    struct/union field whose accessor would be a bare keyword - it would not
    compile today)."""
    snaked = to_snake_case(name)
    if snaked in _CPP_KEYWORDS:
        return snaked + "_"
    return snaked


# Tokens that should stay upper-case when a field brief is derived from the
# field name (so `serverUri` reads "Server URI.", not "Server uri."). Conservative
# and unambiguous only - ambiguous abbreviations (e.g. "ns") are left alone.
_FIELD_ACRONYMS = {
    "id", "uri", "url", "xml", "json", "guid", "ip", "tcp", "udp", "dns", "mac",
    "cpu", "crl", "csr", "rsa", "ecc", "aes", "sha", "pem", "der", "ua", "http",
    "https", "api", "io", "sql", "utc", "uuid", "cn",
}


def field_brief(field, sym_field: str) -> str:
    """A high-quality Doxygen brief for a struct field / enum value.

    Prefers the NodeSet ``<Description>`` for the field (real spec text) when one
    is present; otherwise falls back to an honest, acronym-aware noun phrase
    derived from the field's C++ identifier (e.g. ``serverUri`` -> "Server URI.",
    ``sourceTimestamp`` -> "Source timestamp."). Never invents contract."""
    spec = getattr(field, "description", None)
    if spec and spec.strip():
        return clean_brief_text(spec)
    words = [w for w in to_snake_case(sym_field).split("_") if w]
    if not words:
        return f"The {sym_field} field."
    pretty = []
    for i, word in enumerate(words):
        if word.lower() in _FIELD_ACRONYMS:
            pretty.append(word.upper())
        elif i == 0:
            pretty.append(word[0].upper() + word[1:])
        else:
            pretty.append(word.lower())
    return " ".join(pretty) + "."


def _field_is_abstract_value(index: NodeSetIndex, field) -> bool:
    """True if the field's declared type is an abstract, non-Structure, non-native
    DataType (e.g. UInteger / Integer / Number / BaseDataType).

    Such a field carries a concrete subtype value whose type is not known at
    compile time and which has no common C++ base class (only Structure-derived
    types get the ``RefStructure`` polymorphic mechanism). It is therefore
    represented - and encoded - as a ``Variant``.

    NS0 has no such field (it produces zero ``RefMember`` output), so routing
    these to ``Variant`` leaves NS0 generation byte-identical; the path is first
    exercised by companion specs such as BACnet.
    """
    if field.data_type is None:
        return False
    type_node = index.find(field.data_type)
    if type_node is None:
        return False
    type_name = get_symbolic_name(type_node.browse_name)
    if type_name == "Variant" or _is_native(type_name):
        return False
    if (type_name == "Structure") or index.is_subtype_of(field.data_type, "Structure"):
        return False
    allow_subtypes = bool(field.allow_subtypes) if field.allow_subtypes is not None else False
    is_abstract = bool(type_node.is_abstract)
    return is_abstract or allow_subtypes


def _field_is_variant(index: NodeSetIndex, field) -> bool:
    """True if the field is stored as ``ua::Variant`` - no DataType, or an
    abstract / AllowSubTypes type (the two Variant-producing branches of
    ``_field_cpp_type``). Such a field has no ``.resolve()`` and is not an enum at
    the C++ level, so every concrete-type-assuming emit path must skip it. NS0 has
    none, so gating on this is byte-identical for NS0."""
    return field.data_type is None or _field_is_abstract_value(index, field)


def _field_cpp_type(index: NodeSetIndex, field, resolver=None) -> str:
    """Mirror C++ `get_field_type_name_from_data_type_field` for structure headers.

    When ``resolver`` is supplied, the base struct/enum type name is qualified
    via the resolver: bare for in-spec types (NS0 byte-identical) and
    fully-qualified (``::ua::lvl1::Foo``) for cross-spec references - required
    for multi-level companion stacks where a field references a non-NS0 lookup
    spec (a bare name has no alias in the dependent spec). When ``resolver`` is
    ``None`` the legacy bare name is used (no cross-spec qualification)."""

    # In the C++ generator's XML model, missing `DataType` for a field defaults to `Variant`.
    # This notably appears in service types (e.g. `CallMethodRequest.InputArguments`).
    if field.data_type is None:
        type_name = "Variant"
        is_array = (field.value_rank is not None) and (field.value_rank > 0)
        if is_array:
            type_name = f"Array<{type_name}>"
        if field.is_optional:
            type_name = f"optional<{type_name}>"
        return type_name

    type_id = field.data_type

    type_node = index.find(type_id)
    type_name = get_symbolic_name(type_node.browse_name) if type_node is not None else "Structure"

    is_array = (field.value_rank is not None) and (field.value_rank > 0)
    is_native = _is_native(type_name)
    is_structure = (type_name == "Structure") or index.is_subtype_of(type_id, "Structure")
    is_variant = (type_name == "Variant")

    # Abstract, non-Structure, non-native field types (UInteger / Integer /
    # Number / BaseDataType ...) have no common C++ base class, so they are carried
    # as a Variant. Marking is_variant here makes the wrapping below skip the
    # (inapplicable) RefMember path and just apply array/optional wrapping.
    if _field_is_abstract_value(index, field):
        type_name = "Variant"
        is_variant = True
        is_structure = False
        is_native = False

    if is_native:
        type_name = _NATIVE_MAP[type_name]
    elif resolver is not None and not is_variant and type_node is not None:
        # Qualify the base struct/enum type name for cross-spec references
        # (bare for in-spec -> NS0 byte-identical).
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

        if field.is_optional:
            type_name = f"optional<{type_name}>"
    else:
        if (not is_variant) and (is_abstract or allow_subtypes):
            type_name = f"{ref_type_name}<{type_name}>"
        if field.is_optional:
            type_name = f"optional<{type_name}>"

    return type_name


class StructureEmitter:
    """Emits one ``ua_<snake>.h`` per UAStructure for the spec in ``ctx``."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit(
        self,
        node_id: str,
        binary_encoding_type_names: set[str] | None = None,
    ) -> Path:
        return _emit_structure_header(self._ctx, node_id, binary_encoding_type_names)


def _emit_structure_header(
    ctx: EmitContext,
    node_id: str,
    binary_encoding_type_names: set[str] | None,
) -> Path:
    index = ctx.index
    node = index.find(node_id)
    if node is None:
        raise KeyError(node_id)

    text = ctx.apply_template(load_template("structure_header.in"))
    parts = load_template("structure_parts.in")

    type_name = get_symbolic_name(node.browse_name)

    # A concrete structure is only encodable if it owns a Default Binary encoding
    # Object - the encode/register machinery references
    # `ObjectId::<Type>_Encoding_DefaultBinary`. A type that has none (e.g. a
    # JSON-only mapping type) cannot be encoded, so it is emitted without the
    # codec machinery, exactly like an abstract type. `None` (callers that don't
    # supply the set) means "assume encodable" - preserves prior behaviour.
    is_encodable = binary_encoding_type_names is None or type_name in binary_encoding_type_names
    omit_codec = node.is_abstract or not is_encodable
    header_guard = ctx.header_guard("DATA_TYPE", type_name)

    parent = index.find(node.parent_node_id or "")
    if parent is None:
        raise ValueError(f"Structure type has no parent: {node.node_id} {node.browse_name}")

    # Validate the node id is numeric. ``typeId`` is sourced from the
    # named ``DataTypeId::<Type>`` enum constant (emitted by the template), not
    # from this value - but a non-numeric DataType id is still unsupported.
    if parse_numeric_node_id(node.node_id) is None:
        raise ValueError(f"Only numeric NodeIds supported: {node.node_id}")

    # Parent class - resolver always returns a TypeRef; no in-spec /
    # external branch at the emitter level.
    parent_ref = ctx.resolver.resolve(parent.node_id)

    # ``typeNamespaceUri`` is now an alias to ``specNamespaceUri`` defined
    # once per spec in ``<prefix>namespace.h``; the template emits the
    # alias, so no per-type URI substitution is needed.
    # `<Service>Request`/`<Service>Response` covers both the top-level service
    # messages and nested request/response sub-structures (e.g. CallMethodRequest);
    # "request/response structure" is accurate for both, so we don't claim "service".
    if type_name.endswith("Request"):
        brief = f"OPC UA {type_name} request structure."
    elif type_name.endswith("Response"):
        brief = f"OPC UA {type_name} response structure."
    else:
        brief = f"OPC UA {type_name} structured data type."
    text = text.replace("PLACEHOLDER_DOC", ctx.doc_comment(brief, "ua_data_types"))

    text = text.replace("PLACEHOLDER_HEADER_GUARD", header_guard)
    text = text.replace("PLACEHOLDER_INCLUDE_BASE_CLASS", f'"{parent_ref.header_include}"')

    # to_string declarations (public): concrete types get to_string override
    # append_fields declarations (protected): types with fields get append_fields override
    has_fields = node.definition is not None and len(node.definition.fields) > 0
    if node.is_abstract:
        text = text.replace("PLACEHOLDER_TO_STRING_DECLARATIONS", "")
    else:
        text = text.replace("PLACEHOLDER_TO_STRING_DECLARATIONS",
                            "  /// Formats this value as human-readable text, for logging and debugging.\n"
                            "  /// @param indent Indentation depth applied to nested structures.\n"
                            "  /// @return The formatted representation.\n"
                            "  std::string to_string(int indent = 0) const override;")

    if has_fields:
        text = text.replace("PLACEHOLDER_PROTECTED_DECLARATIONS",
                            "protected:\n"
                            "  /// Appends this value's fields to a buffer; used by to_string().\n"
                            "  /// @param[in,out] output Buffer the field lines are appended to.\n"
                            "  /// @param indent         Indentation depth applied to nested structures.\n"
                            "  void append_fields(std::string& output, int indent = 0) const override;\n\n")
    else:
        text = text.replace("PLACEHOLDER_PROTECTED_DECLARATIONS", "")

    if omit_codec:
        text = text.replace("PLACEHOLDER_HEADER_ENCODE_ID_DECLARATIONS", "")
        text = text.replace("PLACEHOLDER_PROTECTED_CONSTRUCTOR_START", "protected:")
        text = text.replace("PLACEHOLDER_PROTECTED_CONSTRUCTOR_END", "public:")
        text = text.replace("PLACEHOLDER_CLONE_DECLARATION", "")
        text = text.replace("PLACEHOLDER_REGISTER_DECLARATION", "")
    else:
        encode_ids = get_part(parts, "PLACEHOLDER_HEADER_ENCODE_ID_DECLARATIONS")
        encode_ids = encode_ids.replace("PLACEHOLDER_CLASS_NAME", type_name)
        # C++ output has a blank line between `typeId` and the encoding IDs.
        text = text.replace("PLACEHOLDER_HEADER_ENCODE_ID_DECLARATIONS", "\n" + encode_ids)
        text = text.replace("PLACEHOLDER_PROTECTED_CONSTRUCTOR_START", "")
        text = text.replace("PLACEHOLDER_PROTECTED_CONSTRUCTOR_END", "")

        clone_decl = get_part(parts, "PLACEHOLDER_CLONE_DECLARATION")
        text = text.replace("PLACEHOLDER_CLONE_DECLARATION", clone_decl)

        reg_decl = get_part(parts, "PLACEHOLDER_REGISTER_DECLARATION")
        text = text.replace("PLACEHOLDER_REGISTER_DECLARATION", reg_decl)

    # StructureFactory forward-decl: NS0 forward-declares ``ua::StructureFactory``;
    # a companion spec instead pulls it in via ``<prefix>aliases.h`` (a forward
    # decl here would declare ``ua::di::StructureFactory`` and clash with the
    # ``using`` alias).
    if ctx.cpp_namespace == "ua":
        text = text.replace("PLACEHOLDER_STRUCTURE_FACTORY_FWD", "class StructureFactory;")
    else:
        text = text.replace("PLACEHOLDER_STRUCTURE_FACTORY_FWD", "")

    # get_typename<T> specialisation must live in the primary template's
    # namespace (``ua``).  NS0 emits it inline (it already emits in ``ua``);
    # a companion spec closes its own namespace and reopens ``namespace ua``
    # with the fully-qualified type.
    if ctx.cpp_namespace == "ua":
        get_typename_block = (
            f"template<>\n"
            f"inline string_view get_typename<{type_name}>()\n"
            f"{{\n"
            f"  return {type_name}::typeName;\n"
            f"}}\n"
            f"\n"
            f"{ctx.cpp_namespace_close()}"
        )
    else:
        qualified = f"{ctx.cpp_namespace}::{type_name}"
        get_typename_block = (
            f"{ctx.cpp_namespace_close()}\n"
            f"\n"
            f"namespace ua\n"
            f"{{\n"
            f"template<>\n"
            f"inline string_view get_typename<{qualified}>()\n"
            f"{{\n"
            f"  return {qualified}::typeName;\n"
            f"}}\n"
            f"}}  // namespace ua"
        )
    text = text.replace("PLACEHOLDER_GET_TYPENAME_BLOCK", get_typename_block)

    text = text.replace("PLACEHOLDER_QUALIFIED_CLASS_NAME", f"{ctx.cpp_namespace}::{type_name}")
    text = text.replace("PLACEHOLDER_CLASS_NAME", type_name)
    text = text.replace("PLACEHOLDER_BASE_CLASS_NAME", parent_ref.qualified_class_name)

    if _struct_own_fields_need_resolve(index, node_id):
        text = text.replace(
            "PLACEHOLDER_RESOLVE_DECLARATION",
            "\n  /// Resolves this value's localized-text fields to the preferred locales.\n"
            "  /// @param locales Preferred locales, most-preferred first.\n"
            "  void resolve(span<const LocaleId> locales) override;")
    else:
        text = text.replace("PLACEHOLDER_RESOLVE_DECLARATION", "")

    definition = node.definition
    fields = definition.fields if definition is not None else []

    fields_text = ""
    accessors_text = ""
    field_data_type_ids: list[str] = []
    uses_array = False

    for f in fields:
        type_text = _field_cpp_type(index, f, ctx.resolver)
        sym_field = cpp_identifier(f.name, f.symbolic_name)
        # Trailing ///< brief: prefer the NodeSet <Description> for the field,
        # else an honest acronym-aware noun phrase from the field name.
        brief = field_brief(f, sym_field)
        initializer = _FIELD_INITIALIZERS.get((type_name, sym_field), "{}")
        mutable_qualifier = "mutable " if (type_name, sym_field) == ("PortableNodeId", "Identifier") else ""
        fields_text += f"  {mutable_qualifier}{type_text} m{sym_field}{initializer};  ///< {brief}\n"

        snake = _safe_snake(sym_field)
        accessors_text += f"  /// Accesses the `{sym_field}` field.\n"
        accessors_text += f"  /// @return A mutable reference to the `{sym_field}` field.\n"
        accessors_text += f"  {type_text}& {snake}();\n"
        accessors_text += f"  /// @return A const reference to the `{sym_field}` field.\n"
        accessors_text += f"  const {type_text}& {snake}() const;\n\n"

        value_rank = f.value_rank if f.value_rank is not None else -1
        if value_rank > 0:
            uses_array = True

        if f.data_type is None:
            # Default field type (Variant) needs its header.
            if "Variant" not in field_data_type_ids:
                field_data_type_ids.append("Variant")
        elif _field_is_abstract_value(index, f):
            # Abstract non-Structure field -> Variant (see _field_is_abstract_value).
            if "Variant" not in field_data_type_ids:
                field_data_type_ids.append("Variant")
        else:
            type_id = f.data_type
            dt_node = index.find(type_id)
            dt_symbolic = get_symbolic_name(dt_node.browse_name) if dt_node is not None else "Structure"
            if dt_node is not None and not _is_native(dt_symbolic) and type_id not in field_data_type_ids:
                field_data_type_ids.append(type_id)

    include_lines = ""
    for type_id in field_data_type_ids:
        if type_id == "Variant":
            include_lines += '#include "ua_variant.h"\n'
            continue
        dt_node = index.find(type_id)
        if dt_node is None:
            continue
        # Field type include - resolver computes the right header from
        # whichever spec owns the type.
        include_lines += f'#include "{ctx.resolver.resolve(type_id).header_include}"\n'
    if uses_array:
        include_lines += '#include "ua_array.h"\n'

    text = text.replace("PLACEHOLDER_FIELDS", fields_text.rstrip("\n"))
    text = text.replace("PLACEHOLDER_FIELD_ACCESSORS", accessors_text.rstrip("\n"))
    text = text.replace("PLACEHOLDER_FIELD_INCLUDES", include_lines.rstrip("\n"))

    out_path = ctx.interface_dir / ctx.header_file_name(type_name)
    write_file(out_path, text)
    return out_path
