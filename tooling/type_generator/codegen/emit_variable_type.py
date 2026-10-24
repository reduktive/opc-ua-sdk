# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

from __future__ import annotations

from pathlib import Path

from ..io import write_file
from ..naming import cpp_identifier, to_snake_case, to_screaming_snake_case
from ..types.model import ChildInfo, ChildKind, InstanceType
from .emit_instance_common import (
    snake as _snake,
    property_accessor_declarations,
    typed_read_declarations,
    typed_write_declarations,
    find_property_async,
    property_accessor_impls,
    typed_read_impls,
    typed_write_impls,
    traits_browse_name_accessors,
    child_object_accessor_declarations,
    child_object_accessor_impls,
    child_object_includes,
    qualify_core_references as _qualify_core_references,
    sync_guard,
    sync_wait_expr,
    HANDLE_EXECUTOR,
)

# BaseVariableType NodeId (ns=0) - i=62
_BASE_VARIABLE_TYPE_ID = "i=62"

# The ns=0 VariableTypes whose ValueAsText Property is a projection of the Variable's own Value through
# its EnumValues (OPC 10000-8 section 5.3.3.5). The generated create flow wires the Property to answer
# from the Value, so a MonitoredItem sampling it sees the text change with the Value it describes.
_VALUE_AS_TEXT_TYPES: frozenset[str] = frozenset({
    "MultiStateValueDiscreteType",
    "MultiStateDictionaryEntryDiscreteBaseType",
    "MultiStateDictionaryEntryDiscreteType",
})


def projects_value_as_text(type_browse_name: str) -> bool:
    """Whether the ns=0 type with this BrowseName projects its ValueAsText Property from its Value."""
    type_name = type_browse_name if type_browse_name.endswith("Type") else type_browse_name + "Type"
    return type_name in _VALUE_AS_TEXT_TYPES


def _projects_value_as_text(instance_type: InstanceType) -> bool:
    """Whether this ns=0 type's ValueAsText Property is projected from its Value."""
    return projects_value_as_text(instance_type.browse_name)


def _address_space_lock_lines(class_name: str, indent: str, locked: str = "lockedAddressSpace") -> list[str]:
    """Lines that lock a completion's captured ``weakAddressSpace`` into the local named @p locked.

    A completion handed to an ``instance_utils`` call can be held by a namespace, so it captures the
    address space weakly: holding it strongly would keep the address space alive from inside one of
    its own namespaces. When the lock fails the completion answers ``Bad_Shutdown``
    (``AddressSpaceGone``) and returns. A completion nested inside another passes a distinct
    @p locked so its local does not shadow the enclosing one.
    """
    return [
        f"{indent}auto {locked} = weakAddressSpace.lock();",
        f"{indent}if (!{locked})",
        f"{indent}{{",
        f'{indent}  complete({class_name}Result{{::ua::detail::address_space_gone("{class_name}")}});',
        f"{indent}  return;",
        f"{indent}}}",
    ]


def _base_class_for(instance_type: InstanceType) -> tuple[str, str]:
    """Return (base_class_name, include_header) for a variable type.

    If the parent type is BaseVariableType (i=62), the base class is BaseVariable.
    Otherwise it's BaseDataVariable.
    """
    if instance_type.parent_type_id == _BASE_VARIABLE_TYPE_ID:
        return "BaseVariable", '"ua_base_variable.h"'
    return "BaseDataVariable", '"ua_base_data_variable.h"'


class VariableTypeEmitter:
    """Emits variable-type instance-handle header + source."""

    def __init__(self, ctx):
        self._ctx = ctx

    def emit_header(self, instance_type: InstanceType) -> Path:
        return _emit_variable_type_header(self._ctx, instance_type)

    def emit_source(self, instance_type: InstanceType) -> Path:
        return _emit_variable_type_source(self._ctx, instance_type)


def _emit_variable_type_header(ctx, instance_type: InstanceType) -> Path:
    """Emit the .h file for a variable type instance handle."""
    class_name = instance_type.class_name
    header_guard = ctx.simple_header_guard(class_name)

    type_name = instance_type.browse_name
    if not type_name.endswith("Type"):
        type_name = type_name + "Type"

    base_class, base_include = _base_class_for(instance_type)
    final_kw = " final" if instance_type.is_final else ""

    has_props = any(c.kind == ChildKind.property for c in instance_type.children)

    lines: list[str] = []
    lines.append(f"#ifndef {header_guard}")
    lines.append(f"#define {header_guard}")
    lines.append("")
    lines.append(f"#include {base_include}")
    if has_props:
        lines.append('#include "ua_node_accessor.h"')
        lines.append('#include "ua_property.h"')
    for inc in child_object_includes(instance_type.children):
        lines.append(inc)
    lines.append("")
    lines.append(ctx.cpp_namespace_open())
    lines.append("")
    lines.append(f"class {class_name};")
    # Qualify the SDK Result<> template: a companion spec may define a type named
    # `Result`, which (via the aliases.h `using ::ua::Result;`) would otherwise be
    # shadowed by the local class so `Result<Result>` binds to the non-template
    # class. core_qualifier is "" for NS0 (byte-identical) and "::ua::" otherwise.
    lines.append(f"using {class_name}Result = {ctx.core_qualifier}Result<{class_name}>;")
    lines.append("")
    lines.append(
        ctx.doc_comment(
            f"Address-space handle for the OPC UA {type_name} VariableType.",
            "ua_information_model",
            fallback=(
                f"// Helper representing an instantiated OPC UA `{type_name}` "
                "variable in the address space."
            ),
        )
    )
    lines.append(f"class {class_name}{final_kw} : public {base_class}")
    lines.append("{")
    lines.append("public:")
    lines.append(f"  /// Constructs an empty `{class_name}` handle that refers to no node.")
    lines.append(f"  ///")
    lines.append(f"  /// Use create_async / attach_async (or their sync variants) to obtain a handle")
    lines.append(f"  /// bound to a live address-space node.")
    lines.append(f"  {class_name}() = default;")
    lines.append("")
    lines.append(f"  /// Completion callback for create_async: receives the new `{class_name}` handle,")
    lines.append(f"  /// or an @ref ErrorDetail on failure.")
    lines.append(f"  using CreateCompleteCallback = std::function<void({class_name}Result)>;")
    lines.append(f"  /// Completion callback for attach_async: receives the wrapped `{class_name}` handle,")
    lines.append(f"  /// or an @ref ErrorDetail on failure.")
    lines.append(f"  using AttachCompleteCallback = std::function<void({class_name}Result)>;")

    lines.append("")
    lines.append(f"  /// Creates a new `{type_name}` variable under `parent`.")
    lines.append(f"  ///")
    lines.append(f"  /// Completes asynchronously; the callback runs on an unspecified worker thread.")
    lines.append(f"  ///")
    lines.append(f"  /// **The returned handle OWNS the node it creates.** Destroying it removes that node")
    lines.append(f"  /// and its subtree from the address space. Call `release()` to keep the node as")
    lines.append(f"  /// permanent server content, or `remove_async()` to delete it eagerly. A handle")
    lines.append(f"  /// obtained through `attach_*` owns nothing and only references the node.")
    lines.append(f"  /// @param addressSpace Address space the variable is created in.")
    lines.append(f"  /// @param parent       Parent node the new variable is organized under.")
    lines.append(f"  /// @param browseName   Browse name for the new variable.")
    lines.append(f"  /// @param options      Instantiation options (target namespace, node-id allocation, ...).")
    lines.append(f"  /// @param attributes   Variable attributes (data type, value rank, access level, ...).")
    lines.append(f"  /// @param complete     Receives the outcome: on success a `{class_name}` handle,")
    lines.append(f"  ///                     on failure an @ref ErrorDetail. This overload never throws.")
    lines.append(f"  /// @see try_create_sync, create_sync")
    lines.append(f"  static void create_async(AddressSpace addressSpace, const NodeId& parent,")
    lines.append(f"    const QualifiedName& browseName, const InstantiationOptions& options,")
    lines.append(f"    const VariableInstantiationAttributes& attributes, CreateCompleteCallback complete) noexcept;")
    lines.append("")
    lines.append(f"  /// Creates a new `{type_name}` variable under `parent`, blocking until complete.")
    lines.append(f"  ///")
    lines.append(f"  /// **The returned handle OWNS the node it creates.** Destroying it removes that node")
    lines.append(f"  /// and its subtree from the address space. Call `release()` to keep the node as")
    lines.append(f"  /// permanent server content, or `remove_async()` to delete it eagerly. A handle")
    lines.append(f"  /// obtained through `attach_*` owns nothing and only references the node.")
    lines.append(f"  /// @param addressSpace Address space the variable is created in.")
    lines.append(f"  /// @param parent       Parent node the new variable is organized under.")
    lines.append(f"  /// @param browseName   Browse name for the new variable.")
    lines.append(f"  /// @param options      Instantiation options (target namespace, node-id allocation, ...).")
    lines.append(f"  /// @param attributes   Variable attributes (data type, value rank, access level, ...).")
    lines.append(f"  /// @return The new handle, or an @ref ErrorDetail on failure. Never throws.")
    lines.append(f"  /// @see create_async")
    lines.append(f"  static {class_name}Result try_create_sync(AddressSpace addressSpace,")
    lines.append(f"    const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options,")
    lines.append(f"    const VariableInstantiationAttributes& attributes) noexcept;")
    lines.append("")
    lines.append(f"  /// Creates a new `{type_name}` variable under `parent`, blocking until complete.")
    lines.append(f"  ///")
    lines.append(f"  /// **The returned handle OWNS the node it creates.** Destroying it removes that node")
    lines.append(f"  /// and its subtree from the address space. Call `release()` to keep the node as")
    lines.append(f"  /// permanent server content, or `remove_async()` to delete it eagerly. A handle")
    lines.append(f"  /// obtained through `attach_*` owns nothing and only references the node.")
    lines.append(f"  /// @param addressSpace Address space the variable is created in.")
    lines.append(f"  /// @param parent       Parent node the new variable is organized under.")
    lines.append(f"  /// @param browseName   Browse name for the new variable.")
    lines.append(f"  /// @param options      Instantiation options (target namespace, node-id allocation, ...).")
    lines.append(f"  /// @param attributes   Variable attributes (data type, value rank, access level, ...).")
    lines.append(f"  /// @return The new `{class_name}` handle. A Good subcode is not returned; @ref try_create_sync"
                 " returns it.")
    lines.append(f"  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.")
    lines.append(f"  /// @see create_async")
    lines.append(f"  static {class_name} create_sync(AddressSpace addressSpace,")
    lines.append(f"    const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options,")
    lines.append(f"    const VariableInstantiationAttributes& attributes);")
    lines.append("")
    lines.append(f"  /// Wraps an existing node as a `{type_name}` handle, without taking ownership.")
    lines.append(f"  ///")
    lines.append(f"  /// The handle does no RAII cleanup; destroying it leaves the node in place.")
    lines.append(f"  /// @param addressSpace    Address space the node lives in.")
    lines.append(f"  /// @param existingInstance Node id of the existing variable to wrap.")
    lines.append(f"  /// @param complete        Receives the outcome: on success a `{class_name}` handle,")
    lines.append(f"  ///                        on failure an @ref ErrorDetail. This overload never throws.")
    lines.append(f"  /// @see try_attach_sync, attach_sync")
    lines.append(f"  static void attach_async(")
    lines.append(f"    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;")
    lines.append("")
    lines.append(f"  /// Wraps an existing node as a `{type_name}` handle, blocking until complete.")
    lines.append(f"  /// @param addressSpace     Address space the node lives in.")
    lines.append(f"  /// @param existingInstance Node id of the existing variable to wrap.")
    lines.append(f"  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.")
    lines.append(f"  /// @see attach_async")
    lines.append(f"  static {class_name}Result try_attach_sync(")
    lines.append(f"    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;")
    lines.append("")
    lines.append(f"  /// Wraps an existing node as a `{type_name}` handle, blocking until complete.")
    lines.append(f"  /// @param addressSpace     Address space the node lives in.")
    lines.append(f"  /// @param existingInstance Node id of the existing variable to wrap.")
    lines.append(f"  /// @return The `{class_name}` handle. A Good subcode is not returned; @ref try_attach_sync"
                 " returns it.")
    lines.append(f"  /// @throws UaException when the answer is not Good, an Uncertain one included.")
    lines.append(f"  /// @see attach_async")
    lines.append(f"  static {class_name} attach_sync(")
    lines.append(f"    AddressSpace addressSpace, const NodeId& existingInstance);")
    lines.append("")

    # Property accessors
    prop_decls = property_accessor_declarations(instance_type.children)
    if prop_decls:
        lines.append(prop_decls)

    # Typed read
    read_decls = typed_read_declarations(instance_type.children)
    if read_decls:
        lines.append(read_decls)

    # Typed write
    write_decls = typed_write_declarations(instance_type.children)
    if write_decls:
        lines.append(write_decls)

    # Child-object accessors
    child_decls = child_object_accessor_declarations(instance_type.children)
    if child_decls:
        lines.append(child_decls)

    # Protected/private section
    ctor_access = "protected" if not instance_type.is_final else "private"
    lines.append(f"{ctor_access}:")
    lines.append(f"  /// Binds the handle to an existing node; used internally by the create/attach flows.")
    lines.append(f"  ///")
    lines.append(f"  /// @param addressSpace Address space the node lives in.")
    lines.append(f"  /// @param nodeId       Node id this handle refers to.")
    lines.append(f"  /// @param owned        Owned subtree when the handle created the node (drives RAII")
    lines.append(f"  ///                     cleanup), or `nullopt` when wrapping a pre-existing node.")
    lines.append(f"  {class_name}(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);")
    lines.append("")
    lines.append("private:")
    lines.append(f"  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,")
    lines.append(f"    InstantiationOptions options, VariableInstantiationAttributes attributes,")
    lines.append(f"    CreateCompleteCallback complete) noexcept;")
    lines.append("")
    lines.append(f"  static void attach_impl_async(")
    lines.append(f"    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;")

    if has_props:
        lines.append("")
        lines.append("  void find_property_async(QualifiedName browseName,")
        lines.append("    std::function<void(PropertyResult)> complete) const noexcept;")

    lines.append("};")
    lines.append("")
    lines.append(ctx.cpp_namespace_close())
    lines.append("")
    lines.append(f"#endif  // {header_guard}")
    lines.append("")

    out_path = ctx.interface_dir_for("variable_types") / ctx.header_file_name(class_name)
    write_file(out_path, "\n".join(lines))
    return out_path


def _emit_variable_type_source(ctx, instance_type: InstanceType) -> Path:
    """Emit the .cpp file for a variable type instance handle."""
    class_name = instance_type.class_name

    type_name = instance_type.browse_name
    if not type_name.endswith("Type"):
        type_name = type_name + "Type"
    traits_name = f"{cpp_identifier(type_name)}Traits"

    base_class, _ = _base_class_for(instance_type)
    has_props = any(c.kind == ChildKind.property for c in instance_type.children)

    sections: list[str] = []

    # Includes
    sections.append(f'#include "{ctx.header_file_name(class_name)}"')
    sections.append("")
    sections.append('#include "ua_instance_utils.h"')
    sections.append('#include "ua_sync_wait.h"')
    sections.append('#include "ua_to_result.h"')
    sections.append('#include "ua_weak_address_space.h"')
    sections.append("")
    sections.append("#include <boost/asio/any_io_executor.hpp>")
    sections.append("")
    sections.append("#include <functional>")
    sections.append("")
    if has_props:
        sections.append('#include "ua_referencetype_id.h"')
    sections.append(f'#include "{ctx.include_prefix}variabletype_id.h"')
    # Companion specs resolve the type-definition id's namespace index at runtime
    # from the live table (NS0 uses the VariableTypeId enum ctor at ns 0).
    if ctx.cpp_namespace != "ua":
        sections.append(f'#include "{ctx.include_prefix}namespace_uri.h"')
        sections.append('#include "ua_namespace_array.h"')
    sections.append("")

    # Per-spec type-definition id call (NS0: from the enum; companion: resolved
    # from the AddressSpace the create/attach flow already holds).
    td_id_call = "type_definition_id()" if ctx.cpp_namespace == "ua" else "type_definition_id(addressSpace)"

    # Namespace open + traits struct
    sections.append(ctx.cpp_namespace_open())
    sections.append("namespace")
    sections.append("{")
    sections.append("")
    sections.append(f"struct {traits_name}")
    sections.append("{")
    if ctx.cpp_namespace == "ua":
        sections.append(f"  static NodeId type_definition_id()")
        sections.append("  {")
        # Enum member == raw browse name (see emit_identifiers); +Type is docs-only.
        sections.append(f"    return NodeId{{VariableTypeId::{cpp_identifier(instance_type.browse_name)}}};")
        sections.append("  }")
    else:
        sections.append(f"  static NodeId type_definition_id(const AddressSpace& addressSpace)")
        sections.append("  {")
        sections.append("    return NodeId{addressSpace.namespace_array().get_namespace_index(specNamespaceUri),")
        sections.append(f"      static_cast<uint32_t>(VariableTypeId::{cpp_identifier(instance_type.browse_name)})}};")
        sections.append("  }")

    # Add browse name accessors for properties
    bn_accessors = traits_browse_name_accessors(instance_type.children)
    if bn_accessors:
        sections.append(bn_accessors)

    sections.append("};")
    sections.append("")
    sections.append("}  // namespace")
    sections.append("")

    # Constructor
    sections.append(f"{class_name}::{class_name}(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)")
    sections.append(f"  : {base_class}(std::move(addressSpace), std::move(nodeId), std::move(owned))")
    sections.append("{}")
    sections.append("")

    # create_impl_async
    sections.append(f"void {class_name}::create_impl_async(AddressSpace addressSpace, NodeId parent,")
    sections.append(f"  QualifiedName browseName, InstantiationOptions options,")
    sections.append(f"  VariableInstantiationAttributes attributes, CreateCompleteCallback complete) noexcept")
    sections.append("{")
    sections.append(f"  create_variable_impl_async(std::move(addressSpace),")
    sections.append(f"    std::move(parent),")
    sections.append(f"    std::move(browseName),")
    sections.append(f"    {traits_name}::{td_id_call},")
    sections.append(f"    std::move(options),")
    sections.append(f"    std::move(attributes),")
    sections.append(f"    [complete = std::move(complete)](BaseVariable::CreateResult r) mutable")
    sections.append("    {")
    sections.append(f"      if (!r.has_value())")
    sections.append("      {")
    sections.append(f"        complete({class_name}Result{{r.status_code(), r.shared_detail()}});")
    sections.append("        return;")
    sections.append("      }")
    sections.append(f"      const StatusCode code = r.status_code();")
    sections.append(f"      auto data = std::move(r).value();")
    if _projects_value_as_text(instance_type):
        # Wire ValueAsText to answer from the Value (OPC 10000-8 5.3.3.5), then hand the caller the handle.
        # Best-effort: a namespace whose Nodes offer no value source is left as it is. The completion must be
        # copyable (it goes into a std::function), so the move-only owned subtree is carried via shared_ptr
        # rather than captured by move.
        sections.append(f"      auto wireAddressSpace = data.addressSpace;")
        sections.append(f"      auto wireNodeId = data.nodeId;")
        sections.append(f"      auto ownedSubtree = std::make_shared<decltype(data.subtree)>(std::move(data.subtree));")
        sections.append("      instance_utils::wire_value_as_text_async(std::move(wireAddressSpace),")
        sections.append("        std::move(wireNodeId),")
        sections.append(f"        [weakAddressSpace = data.addressSpace.weak(), nodeId = std::move(data.nodeId),")
        sections.append(f"          ownedSubtree, code, complete = std::move(complete)](VoidResult) mutable")
        sections.append("        {")
        sections.extend(_address_space_lock_lines(class_name, "          ", "wiredAddressSpace"))
        sections.append(f"          complete({class_name}Result{{")
        sections.append(f"            {class_name}{{std::move(*wiredAddressSpace), std::move(nodeId), std::move(*ownedSubtree)}}, code}});")
        sections.append("        });")
    else:
        sections.append(f"      complete({class_name}Result{{")
        sections.append(f"        {class_name}{{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}}, code}});")
    sections.append("    });")
    sections.append("}")
    sections.append("")

    # try_create_sync
    sections.append(f"{class_name}Result {class_name}::try_create_sync(AddressSpace addressSpace,")
    sections.append(f"  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options,")
    sections.append(f"  const VariableInstantiationAttributes& attributes) noexcept")
    sections.append("{")
    sections.append("  try")
    sections.append("  {")
    sections.append(sync_guard(class_name + "Result", "addressSpace.executor()").rstrip("\n"))
    sections.append(f"    {class_name}::create_async(std::move(addressSpace),")
    sections.append(f"      parent,")
    sections.append(f"      browseName,")
    sections.append(f"      options,")
    sections.append(f"      attributes,")
    sections.append(f"      std::move(complete));")
    sections.append("")
    sections.append(sync_wait_expr())
    sections.append("  }")
    sections.append("  catch (...)")
    sections.append("  {")
    sections.append("    return ::ua::exception_to_status_code(std::current_exception());")
    sections.append("  }")
    sections.append("}")
    sections.append("")
    # create_sync (throwing)
    sections.append(f"{class_name} {class_name}::create_sync(AddressSpace addressSpace,")
    sections.append(f"  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options,")
    sections.append(f"  const VariableInstantiationAttributes& attributes)")
    sections.append("{")
    sections.append(f"  return ::ua::detail::good_value(")
    sections.append(f"    try_create_sync(std::move(addressSpace), parent, browseName, options, attributes));")
    sections.append("}")
    sections.append("")

    # create_async
    sections.append(f"void {class_name}::create_async(AddressSpace addressSpace, const NodeId& parent,")
    sections.append(f"  const QualifiedName& browseName, const InstantiationOptions& options,")
    sections.append(f"  const VariableInstantiationAttributes& attributes, CreateCompleteCallback complete) noexcept")
    sections.append("{")
    sections.append(f"  create_impl_async(std::move(addressSpace),")
    sections.append(f"    NodeId{{parent}},")
    sections.append(f"    QualifiedName{{browseName}},")
    sections.append(f"    InstantiationOptions{{options}},")
    sections.append(f"    VariableInstantiationAttributes{{attributes}},")
    sections.append(f"    std::move(complete));")
    sections.append("}")
    sections.append("")

    # attach_impl_async
    if instance_type.is_final:
        attach_fn = "attach_exact_async"
        comment = f"// {type_name} is final - exact match."
    else:
        attach_fn = "attach_subtype_async"
        comment = f"// {type_name} has subtypes - subtype match."

    sections.append(f"void {class_name}::attach_impl_async(")
    sections.append(f"  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept")
    sections.append("{")
    sections.append(f"  {comment}")
    sections.append(f"  instance_utils::{attach_fn}(addressSpace,")
    sections.append(f"    existingInstance,")
    sections.append(f"    {traits_name}::{td_id_call},")
    sections.append(f"    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](VoidResult st) mutable")
    sections.append("    {")
    sections.append(f"      if (!st.is_good())")
    sections.append("      {")
    sections.append(f"        complete({class_name}Result{{st.status_code(), st.shared_detail()}});")
    sections.append("        return;")
    sections.append("      }")
    sections.extend(_address_space_lock_lines(class_name, "      "))
    sections.append(f"      complete({class_name}{{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt}});")
    sections.append("    });")
    sections.append("}")
    sections.append("")

    # try_attach_sync
    sections.append(f"{class_name}Result {class_name}::try_attach_sync(")
    sections.append(f"  AddressSpace addressSpace, const NodeId& existingInstance) noexcept")
    sections.append("{")
    sections.append("  try")
    sections.append("  {")
    sections.append(sync_guard(class_name + "Result", "addressSpace.executor()").rstrip("\n"))
    sections.append(f"    {class_name}::attach_async(std::move(addressSpace),")
    sections.append(f"      existingInstance,")
    sections.append(f"      std::move(complete));")
    sections.append("")
    sections.append(sync_wait_expr())
    sections.append("  }")
    sections.append("  catch (...)")
    sections.append("  {")
    sections.append("    return ::ua::exception_to_status_code(std::current_exception());")
    sections.append("  }")
    sections.append("}")
    sections.append("")
    # attach_sync (throwing)
    sections.append(f"{class_name} {class_name}::attach_sync(")
    sections.append(f"  AddressSpace addressSpace, const NodeId& existingInstance)")
    sections.append("{")
    sections.append(f"  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));")
    sections.append("}")
    sections.append("")

    # attach_async
    sections.append(f"void {class_name}::attach_async(")
    sections.append(f"  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept")
    sections.append("{")
    sections.append(f"  attach_impl_async(std::move(addressSpace), NodeId{{existingInstance}}, std::move(complete));")
    sections.append("}")

    # find_property_async helper
    if has_props:
        sections.append("")
        sections.append("// --- Common property helper ---")
        sections.append("")
        sections.append(find_property_async(class_name))

    # Property accessors
    prop_impls = property_accessor_impls(class_name, traits_name, instance_type.children, ctx)
    if prop_impls:
        sections.append("")
        sections.append("// --- Property accessors ---")
        sections.append("")
        sections.append(prop_impls)

    # Typed read shortcuts
    read_impl = typed_read_impls(class_name, traits_name, instance_type.children, ctx)
    if read_impl:
        sections.append("")
        sections.append("// --- Typed value read shortcuts ---")
        sections.append("")
        sections.append(read_impl)

    # Typed write shortcuts
    write_impl = typed_write_impls(class_name, traits_name, instance_type.children, ctx)
    if write_impl:
        sections.append("")
        sections.append("// --- Typed value write shortcuts ---")
        sections.append("")
        sections.append(write_impl)

    # Child-object accessors
    child_impl = child_object_accessor_impls(class_name, traits_name, instance_type.children, ctx)
    if child_impl:
        sections.append("")
        sections.append("// --- Child-object accessors ---")
        sections.append("")
        sections.append(child_impl)

    sections.append("")
    sections.append(ctx.cpp_namespace_close())
    sections.append("")

    out_path = ctx.implementation_dir_for("variable_types") / ctx.source_file_name(class_name)
    write_file(out_path, _qualify_core_references("\n".join(sections), ctx))
    return out_path
