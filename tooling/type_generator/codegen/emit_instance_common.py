# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Shared code-generation helpers for object-type and variable-type instance handles.

Functions in this module are type-kind-agnostic - they work for both object types
and variable types.
"""
from __future__ import annotations

import re

from ..naming import to_snake_case
from ..types.model import ChildInfo, ChildKind


def snake(name: str) -> str:
    return to_snake_case(name)


# A `*_sync` wrapper blocks the calling thread waiting for work queued to an address space's
# executor. A thread OF that executor cannot do that: it is the thread that would have run the
# completion it is waiting for. So every wrapper waits through `ua::async::detail::blocking_call`, which
# refuses on that executor with Bad_WouldBlock BEFORE starting the operation, and otherwise starts it and
# waits (public API review 2026-10, D8). The wrapper is emitted in two halves around the asynchronous
# call: :func:`sync_guard` opens the blocking call and its start lambda, the template then emits the
# `*_async` call with `std::move(complete)` as its completion, and :func:`sync_wait_expr` closes it.
def sync_guard(result_type: str, executor_expr: str) -> str:
    """Opens the blocking call: the executor it must not wait on, and the start lambda."""
    return f"""    return ua::async::detail::blocking_call<{result_type}>({executor_expr},
      [&](std::function<void({result_type})> complete)
      {{
"""


def sync_wait_expr() -> str:
    """Closes the start lambda and the blocking call opened by :func:`sync_guard`."""
    return "      });"


# The executor an instance handle waits on. Empty for a default-constructed or moved-from handle,
# which `on_executor_context` tolerates (it reports false) - the *_async call below then fails with
# its own error, exactly as it did before the guard existed.
HANDLE_EXECUTOR = (
    "mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{}"
)


def child_browse_name_expr(ctx, traits_name: str, sn: str, child: ChildInfo) -> str:
    """C++ expression for a child's lookup BrowseName.

    NS0 children (and any child whose BrowseName is in namespace 0) use the
    static ``Traits::<sn>_browse_name()`` accessor (``QualifiedName{0, ...}``) -
    byte-identical for NS0. A companion spec's own child has its BrowseName in the
    companion namespace, whose runtime index is only known at runtime, so we
    resolve the spec URI against the live namespace array (mirrors how
    ``type_definition_id`` resolves the type's namespace). ``mAddressSpace`` is a
    member of the handle, available in every accessor impl."""
    if ctx.cpp_namespace == "ua" or child.browse_name_ns_zero:
        return f"{traits_name}::{sn}_browse_name()"
    return (
        f'QualifiedName{{(*mAddressSpace).namespace_array().get_namespace_index(specNamespaceUri), '
        f'"{child.browse_name}"}}'
    )


# Standard NS0 reference types (HasComponent / HasProperty / ...) referenced by
# every instance handle.  ``ReferenceTypeId`` is the NS0 enum; a companion spec
# emits its OWN (HasComponent-less) ``ua::di::ReferenceTypeId`` for its
# spec-defined reference types, so an unqualified ``ReferenceTypeId::HasComponent``
# inside ``namespace ua::di`` would bind to the wrong enum.  Qualify those
# references with the core (``::ua::``) qualifier for companion specs; for NS0
# the qualifier is empty and the text is unchanged (byte-identical output).
_CORE_REFERENCE_TYPE_RE = re.compile(r"(?<![:\w])ReferenceTypeId::")


def qualify_core_references(text: str, ctx) -> str:
    """Qualify NS0-owned ``ReferenceTypeId::`` usages for companion specs.

    The type's OWN ``ObjectTypeId`` / ``VariableTypeId`` references are left
    unqualified on purpose - they must bind to the spec's own identifier enum
    in the enclosing ``cpp_namespace``.
    """
    qualifier = ctx.core_qualifier
    if not qualifier:
        return text
    return _CORE_REFERENCE_TYPE_RE.sub(f"{qualifier}ReferenceTypeId::", text)


# Mapping from C++ type to its Result<T> alias name.
_RESULT_ALIAS_MAP: dict[str, str] = {
    "bool": "BoolResult",
    "uint8_t": "UInt8Result",
    "uint16_t": "UInt16Result",
    "uint32_t": "UInt32Result",
    "uint64_t": "UInt64Result",
    "int8_t": "Int8Result",
    "int16_t": "Int16Result",
    "int32_t": "Int32Result",
    "int64_t": "Int64Result",
    "int": "IntResult",
    "float": "FloatResult",
    "double": "DoubleResult",
    "ByteString": "ByteStringResult",
    "String": "StringResult",
    "DateTime": "DateTimeResult",
    "NodeId": "NodeIdResult",
    "QualifiedName": "QualifiedNameResult",
    "LocalizedText": "LocalizedTextResult",
    "DataValue": "DataValueResult",
}


def result_alias(cpp_type: str) -> str:
    """Return the Result alias for a C++ type, or Result<cpp_type> if no alias exists."""
    return _RESULT_ALIAS_MAP.get(cpp_type, f"Result<{cpp_type}>")


def default_value(cpp_type: str) -> str:
    """Return the default/zero value for a C++ type."""
    if cpp_type == "bool":
        return "false"
    if cpp_type in ("uint8_t", "uint16_t", "uint32_t", "uint64_t",
                     "int8_t", "int16_t", "int32_t", "int64_t"):
        return f"{cpp_type}{{0}}"
    if cpp_type in ("float", "double"):
        return f"{cpp_type}{{0}}"
    return f"{cpp_type}{{}}"


# ---------------------------------------------------------------------------
# Header declarations
# ---------------------------------------------------------------------------

def property_accessor_declarations(children: list[ChildInfo]) -> str:
    props = [c for c in children if c.kind == ChildKind.property]
    if not props:
        return ""

    lines: list[str] = []
    lines.append("  // --- Property accessors (return Property handles) ---")
    lines.append("")
    lines.append("  /// Completion callback for a property attach: receives a @ref Property handle,"
                 " or an @ref ErrorDetail on failure.")
    lines.append("  using PropertyCompleteCallback = std::function<void(PropertyResult)>;")
    lines.append("")

    for p in props:
        sn = snake(p.cpp_name)
        lines.append(f"  /// Attaches a `Property` handle for the `{p.cpp_name}` property.")
        lines.append(f"  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure."
                     " Never throws.")
        lines.append(f"  /// @see try_{sn}_property_sync, {sn}_property_sync")
        lines.append(f"  void {sn}_property_async(PropertyCompleteCallback complete) const noexcept;")
        lines.append(f"  /// Attaches a `Property` handle for the `{p.cpp_name}` property, blocking until complete.")
        lines.append(f"  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.")
        lines.append(f"  PropertyResult try_{sn}_property_sync() const noexcept;")
        lines.append(f"  /// Attaches a `Property` handle for the `{p.cpp_name}` property, blocking until complete.")
        lines.append(f"  /// @return The @ref Property handle. A Good subcode is not returned;"
                     f" @ref try_{sn}_property_sync returns it.")
        lines.append(f"  /// @throws UaException when the answer is not Good, an Uncertain one included.")
        lines.append(f"  Property {sn}_property_sync() const;")
        lines.append("")

    return "\n".join(lines) + "\n"


def typed_read_declarations(children: list[ChildInfo]) -> str:
    props = [c for c in children if c.kind == ChildKind.property and c.variant_type_check]
    if not props:
        return ""

    lines: list[str] = []
    lines.append("  // --- Typed value read shortcuts ---")
    lines.append("")

    for p in props:
        sn = snake(p.cpp_name)
        ct = p.cpp_type
        ra = result_alias(ct)
        lines.append(f"  /// Reads the `{p.cpp_name}` property value, typed as `{ct}`.")
        lines.append(f"  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain"
                     " code included; no value when that code is Bad, when an Uncertain reading holds none, or"
                     " with Bad_TypeMismatch when the value is not of that type. Never throws.")
        lines.append(f"  /// @see try_read_{sn}_sync, read_{sn}_sync")
        lines.append(f"  void read_{sn}_async(std::function<void({ra})> complete) const noexcept;")
        lines.append(f"  /// Reads the `{p.cpp_name}` property value as `{ct}`, blocking until complete.")
        lines.append(f"  /// @return The value with the read's code, as @ref read_{sn}_async gives it. Never throws.")
        lines.append(f"  {ra} try_read_{sn}_sync() const noexcept;")
        lines.append(f"  /// Reads the `{p.cpp_name}` property value as `{ct}`, blocking until complete.")
        lines.append(f"  /// @return The property value. A Good subcode is not returned; @ref try_read_{sn}_sync"
                     " returns it.")
        lines.append(f"  /// @throws UaException when the read is not Good, an Uncertain reading included.")
        lines.append(f"  {ct} read_{sn}_sync() const;")
        lines.append("")

    return "\n".join(lines) + "\n"


def typed_write_declarations(children: list[ChildInfo]) -> str:
    props = [c for c in children if c.kind == ChildKind.property and c.variant_type_check]
    if not props:
        return ""

    lines: list[str] = []
    lines.append("  // --- Typed value write shortcuts ---")
    lines.append("")

    for p in props:
        sn = snake(p.cpp_name)
        ct = p.cpp_type
        lines.append(f"  /// Writes the `{p.cpp_name}` property value.")
        lines.append(f"  /// @param value    The new value to write.")
        lines.append(f"  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.")
        lines.append(f"  /// @see try_write_{sn}_sync, write_{sn}_sync")
        lines.append(f"  void write_{sn}_async({ct} value, std::function<void(VoidResult)> complete) const noexcept;")
        lines.append(f"  /// Writes the `{p.cpp_name}` property value, blocking until complete.")
        lines.append(f"  /// @param value The new value to write.")
        lines.append(f"  /// @return Success, or an @ref ErrorDetail on failure. Never throws.")
        lines.append(f"  VoidResult try_write_{sn}_sync({ct} value) const noexcept;")
        lines.append(f"  /// Writes the `{p.cpp_name}` property value, blocking until complete.")
        lines.append(f"  /// @param value The new value to write.")
        lines.append(f"  /// A Good subcode is not returned; @ref try_write_{sn}_sync returns it.")
        lines.append(f"  /// @throws UaException when the write is not Good, an Uncertain answer included.")
        lines.append(f"  void write_{sn}_sync({ct} value) const;")
        lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Source implementations
# ---------------------------------------------------------------------------

def require_bound(callback: str, result_type: str) -> str:
    """Guard emitted at the top of every instance-handle accessor that dereferences the optional
    ``mAddressSpace``. A handle is UNBOUND (``mAddressSpace`` empty) when default-constructed or
    moved-from; calling an accessor on it would dereference an empty optional (undefined behaviour,
    and a bugprone-unchecked-optional-access finding). Report ``BadInvalidState`` through the
    completion instead - matching the hand-written ``if (!mAddressSpace) { ... }`` convention used
    throughout the SDK (e.g. ConditionInstance)."""
    return (
        f"  if (!mAddressSpace)\n"
        f"  {{\n"
        f"    {callback}({result_type}{{StatusCode{{Status::BadInvalidState}}}});\n"
        f"    return;\n"
        f"  }}\n"
    )


def find_property_async(class_name: str) -> str:
    return f"""void {class_name}::find_property_async(QualifiedName browseName,
  std::function<void(PropertyResult)> complete) const noexcept
{{
{require_bound('complete', 'PropertyResult')}  instance_utils::detail::attach_child_async<Property>(*mAddressSpace,
    mNodeId,
    NodeId{{ReferenceTypeId::HasProperty}},
    std::move(browseName),
    "{class_name}",
    std::move(complete));
}}"""


def property_accessor_impls(class_name: str, traits_name: str, children: list[ChildInfo], ctx) -> str:
    props = [c for c in children if c.kind == ChildKind.property]
    if not props:
        return ""

    parts: list[str] = []
    for p in props:
        sn = snake(p.cpp_name)
        browse_name = child_browse_name_expr(ctx, traits_name, sn, p)

        parts.append(f"""void {class_name}::{sn}_property_async(PropertyCompleteCallback complete) const noexcept
{{
{require_bound('complete', 'PropertyResult')}  find_property_async({browse_name}, std::move(complete));
}}""")

        parts.append(f"""PropertyResult {class_name}::try_{sn}_property_sync() const noexcept
{{
  try
  {{
{sync_guard("PropertyResult", HANDLE_EXECUTOR)}    {sn}_property_async(
      std::move(complete));
{sync_wait_expr()}
  }}
  catch (...)
  {{
    return ::ua::exception_to_status_code(std::current_exception());
  }}
}}""")

        parts.append(f"""Property {class_name}::{sn}_property_sync() const
{{
  return ::ua::detail::good_value(try_{sn}_property_sync());
}}""")

    return "\n\n".join(parts)


def typed_read_impls(class_name: str, traits_name: str, children: list[ChildInfo], ctx) -> str:
    props = [c for c in children if c.kind == ChildKind.property and c.variant_type_check]
    if not props:
        return ""

    parts: list[str] = []
    for p in props:
        sn = snake(p.cpp_name)
        ct = p.cpp_type
        ra = result_alias(ct)
        check = p.variant_type_check
        browse_name = child_browse_name_expr(ctx, traits_name, sn, p)

        parts.append(f"""void {class_name}::read_{sn}_async(std::function<void({ra})> complete) const noexcept
{{
{require_bound('complete', ra)}  instance_utils::detail::read_property_value_async<{ct}>(*mAddressSpace,
    mNodeId,
    {browse_name},
    &Variant::{check},
    {{"{class_name}", "{sn}", "{class_name}::read_{sn}_async"}},
    std::move(complete));
}}""")

        parts.append(f"""{ra} {class_name}::try_read_{sn}_sync() const noexcept
{{
  try
  {{
{sync_guard(ra, HANDLE_EXECUTOR)}    read_{sn}_async(std::move(complete));
{sync_wait_expr()}
  }}
  catch (...)
  {{
    return ::ua::exception_to_status_code(std::current_exception());
  }}
}}""")

        parts.append(f"""{ct} {class_name}::read_{sn}_sync() const
{{
  return ::ua::detail::good_value(try_read_{sn}_sync());
}}""")

    return "\n\n".join(parts)


def typed_write_impls(class_name: str, traits_name: str, children: list[ChildInfo], ctx) -> str:
    props = [c for c in children if c.kind == ChildKind.property and c.variant_type_check]
    if not props:
        return ""

    parts: list[str] = []
    for p in props:
        sn = snake(p.cpp_name)
        ct = p.cpp_type
        browse_name = child_browse_name_expr(ctx, traits_name, sn, p)

        parts.append(f"""void {class_name}::write_{sn}_async({ct} value, std::function<void(VoidResult)> complete) const noexcept
{{
{require_bound('complete', 'VoidResult')}  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    {browse_name},
    "{class_name}",
    Variant{{std::move(value)}},
    std::move(complete));
}}""")

        parts.append(f"""VoidResult {class_name}::try_write_{sn}_sync({ct} value) const noexcept
{{
  try
  {{
{sync_guard("VoidResult", HANDLE_EXECUTOR)}    write_{sn}_async(value, std::move(complete));
{sync_wait_expr()}
  }}
  catch (...)
  {{
    return ::ua::exception_to_status_code(std::current_exception());
  }}
}}""")

        parts.append(f"""void {class_name}::write_{sn}_sync({ct} value) const
{{
  try_write_{sn}_sync(value).value();
}}""")

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Child-object / child-variable accessors (return typed instance handles)
# ---------------------------------------------------------------------------

def _is_placeholder_browse_name(name: str) -> bool:
    """Return True for OPC UA placeholder browse names like '<RoleName>'."""
    return "<" in name or ">" in name


def _typed_child_objects(children: list[ChildInfo]) -> list[ChildInfo]:
    """Filter children to those that get typed child-object accessors."""
    return [
        c for c in children
        if c.child_type_class_name
        and c.kind in (ChildKind.child_object, ChildKind.data_variable)
        and not _is_placeholder_browse_name(c.browse_name)
    ]


def child_object_accessor_declarations(children: list[ChildInfo]) -> str:
    """Generate header declarations for child-object/variable accessors."""
    typed = _typed_child_objects(children)
    if not typed:
        return ""

    lines: list[str] = []
    lines.append("  // --- Child-object accessors (return typed instance handles) ---")
    lines.append("")

    for c in typed:
        sn = snake(c.cpp_name)
        cls = f"{c.child_type_qualifier}{c.child_type_class_name}"  # ::ua::Foo for a cross-spec child
        ra = f"{cls}Result"
        lines.append(f"  /// Attaches a typed `{c.child_type_class_name}` handle for the `{c.cpp_name}` child.")
        lines.append(f"  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.")
        lines.append(f"  /// @see try_{sn}_sync, {sn}_sync")
        lines.append(f"  void {sn}_async(std::function<void({ra})> complete) const noexcept;")
        lines.append(f"  /// Attaches a typed `{c.child_type_class_name}` handle for the `{c.cpp_name}` child,"
                     " blocking until complete.")
        lines.append(f"  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.")
        lines.append(f"  {ra} try_{sn}_sync() const noexcept;")
        lines.append(f"  /// Attaches a typed `{c.child_type_class_name}` handle for the `{c.cpp_name}` child,"
                     " blocking until complete.")
        lines.append(f"  /// @return The `{c.child_type_class_name}` handle. A Good subcode is not returned;"
                     f" @ref try_{sn}_sync returns it.")
        lines.append(f"  /// @throws UaException when the answer is not Good, an Uncertain one included.")
        lines.append(f"  {cls} {sn}_sync() const;")
        lines.append("")

    return "\n".join(lines) + "\n"


def child_object_accessor_impls(class_name: str, traits_name: str, children: list[ChildInfo], ctx) -> str:
    """Generate source implementations for child-object/variable accessors."""
    typed = _typed_child_objects(children)
    if not typed:
        return ""

    parts: list[str] = []
    for c in typed:
        sn = snake(c.cpp_name)
        cls = f"{c.child_type_qualifier}{c.child_type_class_name}"  # ::ua::Foo for a cross-spec child
        ra = f"{cls}Result"
        ref_type = "ReferenceTypeId::HasProperty" if c.reference_type == "HasProperty" else "ReferenceTypeId::HasComponent"
        browse_name = child_browse_name_expr(ctx, traits_name, sn, c)

        parts.append(f"""void {class_name}::{sn}_async(std::function<void({ra})> complete) const noexcept
{{
{require_bound('complete', ra)}  instance_utils::detail::attach_child_async<{cls}>(*mAddressSpace,
    mNodeId,
    NodeId{{{ref_type}}},
    {browse_name},
    "{class_name}",
    std::move(complete));
}}""")

        parts.append(f"""{ra} {class_name}::try_{sn}_sync() const noexcept
{{
  try
  {{
{sync_guard(ra, HANDLE_EXECUTOR)}    {sn}_async(
      std::move(complete));
{sync_wait_expr()}
  }}
  catch (...)
  {{
    return ::ua::exception_to_status_code(std::current_exception());
  }}
}}""")

        parts.append(f"""{cls} {class_name}::{sn}_sync() const
{{
  return ::ua::detail::good_value(try_{sn}_sync());
}}""")

    return "\n\n".join(parts)


def child_object_includes(children: list[ChildInfo]) -> list[str]:
    """Return include directives for child-object type handle headers.

    Each child carries the filename prefix of the spec that OWNS its handle type
    (``ua_`` for an NS0 child, ``ua_di_`` for a same-spec DI child, ...), resolved
    per-child during model build. NS0 children always use ``ua_`` so NS0 output
    stays byte-identical.
    """
    typed = _typed_child_objects(children)
    seen: set[str] = set()
    includes: list[str] = []
    for c in typed:
        cls = c.child_type_class_name
        if cls not in seen:
            seen.add(cls)
            includes.append(f'#include "{c.child_type_include_prefix}{snake(cls)}.h"')
    return includes


def traits_browse_name_accessors(children: list[ChildInfo]) -> str:
    """Generate browse name accessor methods for the traits struct (properties and typed child objects/variables)."""
    lines: list[str] = []
    for child in children:
        needs_browse_name = (
            child.kind == ChildKind.property
            or (child.child_type_class_name
                and child.kind in (ChildKind.child_object, ChildKind.data_variable)
                and not _is_placeholder_browse_name(child.browse_name))
        )
        if needs_browse_name:
            sn = snake(child.cpp_name)
            lines.append("")
            lines.append(f"  static QualifiedName {sn}_browse_name()")
            lines.append("  {")
            lines.append(f'    return QualifiedName{{0, "{child.browse_name}"}};')
            lines.append("  }")
    return "\n".join(lines)
