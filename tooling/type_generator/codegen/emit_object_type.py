# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Emit object-type instance handles (header + source).

Each ``ObjectTypeEmitter`` is bound to one ``EmitContext`` and exposes
``emit_header(instance_type)`` / ``emit_source(instance_type)``.  The
underlying generators are module-private functions kept here for
locality.
"""

from __future__ import annotations

from pathlib import Path

from ..io import load_template, write_file
from ..naming import to_camel_back, cpp_identifier
from ..types.model import ChildInfo, ChildKind, InstanceType
from .context import EmitContext
from .emit_instance_common import (
    snake as _snake,
    require_bound as _require_bound,
    default_value as _default_value,
    property_accessor_declarations as _property_accessor_declarations,
    typed_read_declarations as _typed_read_declarations,
    typed_write_declarations as _typed_write_declarations,
    find_property_async as _find_property_async,
    property_accessor_impls as _property_accessor_impls,
    typed_read_impls as _typed_read_impls,
    typed_write_impls as _typed_write_impls,
    child_object_accessor_declarations as _child_object_accessor_declarations,
    child_object_accessor_impls as _child_object_accessor_impls,
    child_object_includes as _child_object_includes,
    qualify_core_references as _qualify_core_references,
    child_browse_name_expr as _child_browse_name_expr,
    _is_placeholder_browse_name,
    sync_guard,
    sync_wait_expr,
    HANDLE_EXECUTOR,
)


def _pascal(name: str) -> str:
    """Ensure first letter is uppercase (for struct names)."""
    if not name:
        return name
    return name[0].upper() + name[1:]


def _argument_brief(arg_name: str) -> str:
    """Honest noun-phrase brief for a method argument, derived from its name.

    The OPC UA model carries no per-argument documentation string here, so we
    de-camel-case the wire name into a readable phrase (``FileHandle`` ->
    "File handle.") rather than inventing a contract.
    """
    phrase = _snake(arg_name).replace("_", " ").strip()
    if not phrase:
        return f"The `{arg_name}` argument."
    return phrase[0].upper() + phrase[1:] + "."


def _method_argument_structs_and_typedefs(type_name: str, children: list[ChildInfo], core: str) -> str:
    """Generate argument structs and handler typedefs for methods."""
    methods = [c for c in children if c.kind == ChildKind.method]
    if not methods:
        return ""

    lines: list[str] = []
    for m in methods:
        bn = _pascal(m.cpp_name)

        # Input arguments struct
        if m.input_arguments:
            lines.append(f"  /// Input arguments for the {type_name} {m.cpp_name}() method.")
            lines.append(f"  struct {bn}InputArguments")
            lines.append("  {")
            for arg in m.input_arguments:
                field_type = f"std::vector<{arg.cpp_type}>" if arg.is_array else arg.cpp_type
                init = "{}" if not arg.is_move_type else ""
                lines.append(f"    {field_type} {to_camel_back(arg.name)}{init};  ///< {_argument_brief(arg.name)}")
            lines.append("  };")
            lines.append("")

        # Output arguments struct
        if m.output_arguments:
            lines.append(f"  /// Output arguments for the {type_name} {m.cpp_name}() method.")
            lines.append(f"  struct {bn}OutputArguments")
            lines.append("  {")
            for arg in m.output_arguments:
                field_type = f"std::vector<{arg.cpp_type}>" if arg.is_array else arg.cpp_type
                init = "{}" if not arg.is_move_type else ""
                lines.append(f"    {field_type} {to_camel_back(arg.name)}{init};  ///< {_argument_brief(arg.name)}")
            lines.append("  };")
            lines.append("")

        # The two handler forms (public API review 2026-10, item 8b section 9.9): a lambda matches exactly
        # one, because std::function converts only from a callable with its signature and they differ
        # in arity.
        out_type = f"{bn}OutputArguments" if m.output_arguments else ""
        in_param = f", const {bn}InputArguments&" if m.input_arguments else ""
        lines.append(f"  /// Synchronous handler for {m.cpp_name}(): returns the outputs, a failure or a rejected input"
                     " argument (see ua::MethodResult), for work that waits for nothing.")
        lines.append(f"  using {bn}Handler = std::function<{core}MethodResult<{out_type}>(const {core}MethodCall&{in_param})>;")
        lines.append(f"  /// Asynchronous handler for {m.cpp_name}(): starts the work and completes it through the"
                     " callback, once, from any thread.")
        lines.append(f"  using {bn}AsyncHandler = std::function<void(const {core}MethodCall&{in_param},"
                     f" {core}MethodResultCallback<{out_type}>)>;")
        lines.append("")

    return "\n".join(lines) + "\n"


def _method_handler_declarations(children: list[ChildInfo]) -> str:
    """Generate set_*_handler declarations."""
    methods = [c for c in children if c.kind == ChildKind.method]
    if not methods:
        return ""

    lines: list[str] = []
    lines.append("  // --- Method handler registration ---")
    lines.append("")

    for m in methods:
        sn = _snake(m.cpp_name)
        bn = _pascal(m.cpp_name)
        for form, what in (("Handler", "synchronous"), ("AsyncHandler", "asynchronous")):
            lines.append(f"  /// Registers the {what} handler invoked when a client calls the `{m.cpp_name}` method,"
                         " in place of any earlier one.")
            lines.append(f"  /// @param handler The {what} handler.")
            lines.append(f"  /// @param done    Receives the registration outcome, or an @ref ErrorDetail on failure."
                         " Never throws.")
            lines.append(f"  /// @see try_set_{sn}_handler_sync, set_{sn}_handler_sync")
            lines.append(f"  void set_{sn}_handler_async({bn}{form} handler, std::function<void(VoidResult)> done) const noexcept;")
            lines.append(f"  /// Registers the {what} `{m.cpp_name}` handler, blocking until complete.")
            lines.append(f"  /// @param handler The {what} handler.")
            lines.append(f"  /// @return Success, or an @ref ErrorDetail on failure. Never throws.")
            lines.append(f"  VoidResult try_set_{sn}_handler_sync({bn}{form} handler) const noexcept;")
            lines.append(f"  /// Registers the {what} `{m.cpp_name}` handler, blocking until complete.")
            lines.append(f"  /// @param handler The {what} handler.")
            lines.append(f"  /// A Good subcode is not returned; @ref try_set_{sn}_handler_sync returns it.")
            lines.append(f"  /// @throws UaException when the registration is not Good, an Uncertain answer included.")
            lines.append(f"  void set_{sn}_handler_sync({bn}{form} handler) const;")
            lines.append("")

    return "\n".join(lines) + "\n"


def _method_accessor_declarations(children: list[ChildInfo]) -> str:
    methods = [c for c in children if c.kind == ChildKind.method]
    if not methods:
        return ""

    lines: list[str] = []
    lines.append("  // --- Method accessors ---")
    lines.append("")
    lines.append("  /// Completion callback for a method-accessor attach: receives a @ref MethodAccessor,"
                 " or an @ref ErrorDetail on failure.")
    lines.append("  using MethodAccessorCompleteCallback = std::function<void(MethodAccessorResult)>;")
    lines.append("")

    for m in methods:
        sn = _snake(m.cpp_name)
        lines.append(f"  /// Attaches a `MethodAccessor` for client-side invocation of the `{m.cpp_name}` method.")
        lines.append(f"  /// @param complete Receives the accessor, or an @ref ErrorDetail on failure. Never throws.")
        lines.append(f"  /// @see try_{sn}_method_sync, {sn}_method_sync")
        lines.append(f"  void {sn}_method_async(MethodAccessorCompleteCallback complete) const noexcept;")
        lines.append(f"  /// Attaches a `MethodAccessor` for the `{m.cpp_name}` method, blocking until complete.")
        lines.append(f"  /// @return The accessor, or an @ref ErrorDetail on failure. Never throws.")
        lines.append(f"  MethodAccessorResult try_{sn}_method_sync() const noexcept;")
        lines.append(f"  /// Attaches a `MethodAccessor` for the `{m.cpp_name}` method, blocking until complete.")
        lines.append(f"  /// @return The `MethodAccessor`. A Good subcode is not returned; @ref try_{sn}_method_sync"
                     " returns it.")
        lines.append(f"  /// @throws UaException when the answer is not Good, an Uncertain one included.")
        lines.append(f"  MethodAccessor {sn}_method_sync() const;")
        lines.append("")

    return "\n".join(lines) + "\n"


class ObjectTypeEmitter:
    """Emits object-type instance-handle header + source."""

    def __init__(self, ctx: EmitContext):
        self._ctx = ctx

    def emit_header(self, instance_type: InstanceType) -> Path:
        return _emit_object_type_header(self._ctx, instance_type)

    def emit_source(self, instance_type: InstanceType) -> Path:
        return _emit_object_type_source(self._ctx, instance_type)


def _emit_object_type_header(ctx: EmitContext, instance_type: InstanceType) -> Path:
    text = ctx.apply_template(load_template("object_type_header.in"))

    class_name = instance_type.class_name
    header_guard = ctx.simple_header_guard(class_name)

    # The type name is the browse name (e.g. "FileType") - used in comments
    type_name = instance_type.browse_name
    if not type_name.endswith("Type"):
        type_name = type_name + "Type"

    # NS0 forward-declares ``ua::MethodCallContext``; a companion spec pulls the
    # real NS0 type into its namespace via a using-declaration (it is available
    # transitively through ua_node_accessor.h -> ua_node.h). A plain forward decl
    # would declare ``ua::di::MethodCallContext`` and the method-handler lambdas
    # would then mismatch ``ua::MethodAdapter``'s expected handler signature.
    if ctx.cpp_namespace == "ua":
        text = text.replace("PLACEHOLDER_METHOD_CALL_CONTEXT_FWD", "struct MethodCallContext;")
    else:
        text = text.replace("PLACEHOLDER_METHOD_CALL_CONTEXT_FWD", "using ::ua::MethodCallContext;")

    text = text.replace("PLACEHOLDER_HEADER_GUARD", header_guard)
    # Qualify the SDK Result<> template (see emit_variable_type) - "" for NS0,
    # "::ua::" for a companion spec - before the class-name pass.
    text = text.replace("PLACEHOLDER_CORE_QUAL", ctx.core_qualifier)
    text = text.replace("PLACEHOLDER_CLASS_NAME", class_name)
    text = text.replace("PLACEHOLDER_TYPE_NAME", type_name)
    text = text.replace(
        "PLACEHOLDER_DOC",
        ctx.doc_comment(
            f"Address-space handle for the OPC UA {type_name} ObjectType.",
            "ua_information_model",
            fallback=(
                f"// Helper representing an instantiated OPC UA `{type_name}` "
                "object in the address space."
            ),
        ),
    )
    text = text.replace("PLACEHOLDER_METHOD_ARGUMENT_STRUCTS", _method_argument_structs_and_typedefs(type_name, instance_type.children, ctx.core_qualifier))
    text = text.replace("PLACEHOLDER_METHOD_ACCESSOR_DECLARATIONS", _method_accessor_declarations(instance_type.children))
    text = text.replace("PLACEHOLDER_PROPERTY_ACCESSOR_DECLARATIONS", _property_accessor_declarations(instance_type.children))
    text = text.replace("PLACEHOLDER_TYPED_READ_DECLARATIONS", _typed_read_declarations(instance_type.children))
    text = text.replace("PLACEHOLDER_TYPED_WRITE_DECLARATIONS", _typed_write_declarations(instance_type.children))
    text = text.replace("PLACEHOLDER_METHOD_HANDLER_DECLARATIONS", _method_handler_declarations(instance_type.children))
    text = text.replace("PLACEHOLDER_CHILD_OBJECT_DECLARATIONS", _child_object_accessor_declarations(instance_type.children))

    # Add child-object includes after the base includes
    child_includes = _child_object_includes(instance_type.children)
    if child_includes:
        include_block = "\n".join(child_includes) + "\n"
        text = text.replace('#include "ua_property.h"\n', '#include "ua_property.h"\n' + include_block)

    out_path = ctx.interface_dir_for("object_types") / ctx.header_file_name(class_name)
    write_file(out_path, text)
    return out_path


def _traits_struct(instance_type: InstanceType, ctx: EmitContext) -> str:
    """Generate the traits struct with browse name accessors."""
    lines: list[str] = []
    type_name = instance_type.browse_name
    if not type_name.endswith("Type"):
        type_name = type_name + "Type"

    lines.append(f"struct {cpp_identifier(type_name)}Traits")
    lines.append("{")
    # NS0 type ids live in namespace 0 - the ``ObjectTypeId`` enum ctor is correct
    # and needs no context. A companion spec's type lives in the spec's namespace,
    # whose runtime index is only known from the live namespace table, so resolve
    # it from the AddressSpace the handle is bound to.
    if ctx.cpp_namespace == "ua":
        lines.append("  static NodeId type_definition_id()")
        lines.append("  {")
        # The enum member is the raw browse name (what emit_identifiers wrote from
        # the CSV). type_name's "+Type" fabrication is for human-readable docs only -
        # using it here breaks types whose browse name doesn't end in "Type" (e.g.
        # Sercos "ClassSet" -> ObjectTypeId::ClassSet, not ::ClassSetType).
        lines.append(f"    return NodeId{{ObjectTypeId::{cpp_identifier(instance_type.browse_name)}}};")
        lines.append("  }")
    else:
        lines.append("  static NodeId type_definition_id(const AddressSpace& addressSpace)")
        lines.append("  {")
        lines.append("    return NodeId{addressSpace.namespace_array().get_namespace_index(specNamespaceUri),")
        lines.append(f"      static_cast<uint32_t>(ObjectTypeId::{cpp_identifier(instance_type.browse_name)})}};")
        lines.append("  }")

    for child in instance_type.children:
        needs_browse_name = (
            child.kind in (ChildKind.property, ChildKind.method)
            or (child.child_type_class_name
                and child.kind in (ChildKind.child_object, ChildKind.data_variable)
                and not _is_placeholder_browse_name(child.browse_name))
        )
        if needs_browse_name:
            sn = _snake(child.cpp_name)
            lines.append("")
            lines.append(f"  static QualifiedName {sn}_browse_name()")
            lines.append("  {")
            lines.append(f'    return QualifiedName{{0, "{child.browse_name}"}};')
            lines.append("  }")

    lines.append("};")
    return "\n".join(lines)


def _create_impl_async(class_name: str, traits_name: str, td_id_call: str) -> str:
    return f"""void {class_name}::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    {traits_name}::{td_id_call},
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {{
      if (!r.has_value())
      {{
        complete({class_name}Result{{r.status_code(), r.shared_detail()}});
        return;
      }}
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete({class_name}Result{{
        {class_name}{{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)}}, code}});
    }});
}}"""


def _constructor(class_name: str) -> str:
    return f"""{class_name}::{class_name}(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{{}}"""


def _create_sync(class_name: str) -> str:
    return f"""{class_name}Result {class_name}::try_create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{{
  try
  {{
{sync_guard(class_name + "Result", "addressSpace.executor()")}    {class_name}::create_async(std::move(addressSpace),
      parent,
      browseName,
      options,
      std::move(complete));

{sync_wait_expr()}
  }}
  catch (...)
  {{
    return ::ua::exception_to_status_code(std::current_exception());
  }}
}}

{class_name} {class_name}::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}}"""


def _create_async(class_name: str) -> str:
    return f"""void {class_name}::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options, CreateCompleteCallback complete) noexcept
{{
  create_impl_async(std::move(addressSpace),
    NodeId{{parent}},
    QualifiedName{{browseName}},
    InstantiationOptions{{options}},
    std::move(complete));
}}"""


def _attach_impl_async(class_name: str, traits_name: str, is_final: bool, td_id_call: str) -> str:
    type_name = class_name
    if not type_name.endswith("Type"):
        type_name = type_name + "Type"

    if is_final:
        attach_fn = "attach_exact_async"
        comment = f"// {type_name} is final - exact match."
    else:
        attach_fn = "attach_subtype_async"
        comment = f"// {type_name} has subtypes - subtype match."

    return f"""void {class_name}::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{{
  {comment}
  instance_utils::{attach_fn}(addressSpace,
    existingInstance,
    {traits_name}::{td_id_call},
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](VoidResult st) mutable
    {{
      if (!st.is_good())
      {{
        complete({class_name}Result{{st.status_code(), st.shared_detail()}});
        return;
      }}
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {{
        complete({class_name}Result{{::ua::detail::address_space_gone("{class_name}")}});
        return;
      }}
      complete({class_name}{{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt}});
    }});
}}"""


def _attach_sync(class_name: str) -> str:
    return f"""{class_name}Result {class_name}::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{{
  try
  {{
{sync_guard(class_name + "Result", "addressSpace.executor()")}    {class_name}::attach_async(std::move(addressSpace),
      existingInstance,
      std::move(complete));

{sync_wait_expr()}
  }}
  catch (...)
  {{
    return ::ua::exception_to_status_code(std::current_exception());
  }}
}}

{class_name} {class_name}::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}}"""


def _attach_async(class_name: str) -> str:
    return f"""void {class_name}::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{{
  attach_impl_async(std::move(addressSpace), NodeId{{existingInstance}}, std::move(complete));
}}"""


def _method_accessor_impls(class_name: str, traits_name: str, children: list[ChildInfo], ctx) -> str:
    methods = [c for c in children if c.kind == ChildKind.method]
    if not methods:
        return ""

    parts: list[str] = []
    for m in methods:
        sn = _snake(m.cpp_name)
        browse_name = _child_browse_name_expr(ctx, traits_name, sn, m)
        parts.append(f"""void {class_name}::{sn}_method_async(MethodAccessorCompleteCallback complete) const noexcept
{{
{_require_bound('complete', 'MethodAccessorResult')}  instance_utils::find_child_method_accessor_by_browse_name_async(*mAddressSpace,
    mNodeId,
    NodeId{{ReferenceTypeId::HasComponent}},
    {browse_name},
    std::move(complete));
}}""")

        parts.append(f"""MethodAccessorResult {class_name}::try_{sn}_method_sync() const noexcept
{{
  try
  {{
{sync_guard("MethodAccessorResult", HANDLE_EXECUTOR)}    {sn}_method_async(std::move(complete));
{sync_wait_expr()}
  }}
  catch (...)
  {{
    return ::ua::exception_to_status_code(std::current_exception());
  }}
}}""")

        parts.append(f"""MethodAccessor {class_name}::{sn}_method_sync() const
{{
  return ::ua::detail::good_value(try_{sn}_method_sync());
}}""")

    return "\n\n".join(parts)


def _method_handler_impls(class_name: str, traits_name: str, children: list[ChildInfo], ctx) -> str:
    """The handler registrations: each form of handler is wrapped in the typed MethodAdapter (public API
    review 2026-10, item 8b section 9.9), which decodes the input arguments one by one, so the binding
    only rebuilds the input struct for the handler and takes its struct result apart for the encoding."""
    methods = [c for c in children if c.kind == ChildKind.method]
    if not methods:
        return ""

    parts: list[str] = []
    for m in methods:
        sn = _snake(m.cpp_name)
        bn = _pascal(m.cpp_name)
        browse_name = _child_browse_name_expr(ctx, traits_name, sn, m)

        in_types = [f"Array<{a.cpp_type}>" if a.is_array else a.cpp_type for a in m.input_arguments]
        out_types = [f"std::vector<{a.cpp_type}>" if a.is_array else a.cpp_type for a in m.output_arguments]
        in_list = ", ".join(in_types)
        out_list = ", ".join(out_types)
        adapter_type = f"MethodAdapter<std::tuple<{in_list}>, std::tuple<{out_list}>>"
        params = "".join(f", const {t}& in{i}" for i, t in enumerate(in_types))
        field_inits = ", ".join(
            f".{to_camel_back(a.name)} = in{i}{'.payload()' if a.is_array else ''}"
            for i, a in enumerate(m.input_arguments)
        )
        typed_in = f"      {bn}InputArguments typedIn{{{field_inits}}};\n" if m.input_arguments else ""
        handler_args = "call, typedIn" if m.input_arguments else "call"
        to_tuple = (
            f"[](const {bn}OutputArguments& out) {{ return std::tuple<{out_list}>{{"
            + ", ".join(f"out.{to_camel_back(a.name)}" for a in m.output_arguments)
            + "}; }"
        )
        argument_names = ", ".join(f'Arg<{t}>{{.name = "{a.name}"}}' for a, t in zip(m.input_arguments, in_types))
        inputs_expr = f"Inputs<{in_list}>{{{{{argument_names}}}}}" if m.input_arguments else "Inputs<>{}"

        if m.output_arguments:
            sync_body = (f"      return detail::method_result_from_struct<{out_list}>(handler({handler_args}),"
                         f" {to_tuple});\n")
            async_body = (f"      handler({handler_args}, detail::struct_method_result_callback<{bn}OutputArguments>("
                          f"std::move(complete), {to_tuple}, logger, call.method_id()));\n")
        else:
            sync_body = f"      return handler({handler_args});\n"
            async_body = f"      handler({handler_args}, std::move(complete));\n"

        forms = (
            ("Handler",
             f"[handler = std::move(handler)](const MethodCall& call{params}) -> MethodResult<{out_list}>\n"
             f"    {{\n{typed_in}{sync_body}    }}"),
            ("AsyncHandler",
             f"[handler = std::move(handler), logger = mAddressSpace->logger()](const MethodCall& call{params},"
             f" MethodResultCallback<{out_list}> complete)\n"
             f"    {{\n{typed_in}{async_body}    }}"),
        )
        for form, wrapper in forms:
            parts.append(f"""void {class_name}::set_{sn}_handler_async({bn}{form} handler, std::function<void(VoidResult)> done) const noexcept
{{
  if (!instance_utils::detail::begin_handler_registration(mAddressSpace,
        static_cast<bool>(handler),
        "{class_name}",
        "{class_name}::set_{sn}_handler_async",
        done))
  {{
    return;
  }}
  try
  {{
    {adapter_type} adapter{{
    {wrapper},
    {inputs_expr},
    mAddressSpace->logger()}};
    instance_utils::resolve_and_set_method_handler_async(*mAddressSpace,
      mNodeId,
      {browse_name},
      std::move(adapter),
      done);
  }}
  catch (...)
  {{
    done(VoidResult{{::ua::exception_to_status_code(std::current_exception())}});
  }}
}}""")
            parts.append(f"""VoidResult {class_name}::try_set_{sn}_handler_sync({bn}{form} handler) const noexcept
{{
  try
  {{
{sync_guard("VoidResult", HANDLE_EXECUTOR)}    set_{sn}_handler_async(std::move(handler), std::move(complete));
{sync_wait_expr()}
  }}
  catch (...)
  {{
    return ::ua::exception_to_status_code(std::current_exception());
  }}
}}""")
            parts.append(f"""void {class_name}::set_{sn}_handler_sync({bn}{form} handler) const
{{
  try_set_{sn}_handler_sync(std::move(handler)).value();
}}""")

    return "\n\n".join(parts)


def _emit_object_type_source(ctx: EmitContext, instance_type: InstanceType) -> Path:
    class_name = instance_type.class_name

    type_name = instance_type.browse_name
    if not type_name.endswith("Type"):
        type_name = type_name + "Type"
    traits_name = f"{cpp_identifier(type_name)}Traits"

    sections: list[str] = []

    has_methods = any(c.kind == ChildKind.method for c in instance_type.children)

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
    sections.append("#include <tuple>")
    sections.append("")
    if has_methods:
        sections.append('#include "ua_call_method_result.h"')
        sections.append('#include "ua_method_adapter.h"')
    sections.append(f'#include "{ctx.include_prefix}objecttype_id.h"')
    sections.append('#include "ua_referencetype_id.h"')
    # A companion spec resolves its type-definition id's namespace index at
    # runtime from the live table (see the traits struct), so it needs the spec
    # URI constant and the namespace-array accessor.
    if ctx.cpp_namespace != "ua":
        sections.append(f'#include "{ctx.include_prefix}namespace_uri.h"')
        sections.append('#include "ua_namespace_array.h"')
    sections.append("")

    # Namespace open (cpp_namespace_open returns `namespace ua\n{`)
    sections.append(ctx.cpp_namespace_open())
    sections.append("namespace")
    sections.append("{")
    sections.append("")
    sections.append(_traits_struct(instance_type, ctx))
    sections.append("")
    sections.append("}  // namespace")

    # The type-definition id is resolved differently per spec: NS0 from the
    # ObjectTypeId enum (ns 0), a companion spec from the live namespace table
    # via the AddressSpace the attach/create flow already holds.
    td_id_call = "type_definition_id()" if ctx.cpp_namespace == "ua" else "type_definition_id(addressSpace)"

    # Constructor
    sections.append("")
    sections.append(_constructor(class_name))

    # create_impl_async, create_sync, create_async
    sections.append("")
    sections.append(_create_impl_async(class_name, traits_name, td_id_call))
    sections.append("")
    sections.append(_create_sync(class_name))
    sections.append("")
    sections.append(_create_async(class_name))

    # attach_impl_async, attach_sync, attach_async
    sections.append("")
    sections.append(_attach_impl_async(class_name, traits_name, instance_type.is_final, td_id_call))
    sections.append("")
    sections.append(_attach_sync(class_name))
    sections.append("")
    sections.append(_attach_async(class_name))

    # Method accessors
    method_impls = _method_accessor_impls(class_name, traits_name, instance_type.children, ctx)
    if method_impls:
        sections.append("")
        sections.append(method_impls)

    # find_property_async helper
    has_props = any(c.kind == ChildKind.property for c in instance_type.children)
    if has_props:
        sections.append("")
        sections.append("// --- Common property helper ---")
        sections.append("")
        sections.append(_find_property_async(class_name))

    # Property accessors
    prop_impls = _property_accessor_impls(class_name, traits_name, instance_type.children, ctx)
    if prop_impls:
        sections.append("")
        sections.append("// --- Property accessors ---")
        sections.append("")
        sections.append(prop_impls)

    # Typed read shortcuts
    read_impls = _typed_read_impls(class_name, traits_name, instance_type.children, ctx)
    if read_impls:
        sections.append("")
        sections.append("// --- Typed value read shortcuts ---")
        sections.append("")
        sections.append(read_impls)

    # Typed write shortcuts
    write_impls = _typed_write_impls(class_name, traits_name, instance_type.children, ctx)
    if write_impls:
        sections.append("")
        sections.append("// --- Typed value write shortcuts ---")
        sections.append("")
        sections.append(write_impls)

    # Method handler registration
    handler_impls = _method_handler_impls(class_name, traits_name, instance_type.children, ctx)
    if handler_impls:
        sections.append("")
        sections.append("// --- Method handler registration ---")
        sections.append("")
        sections.append(handler_impls)

    # Child-object accessors
    child_impls = _child_object_accessor_impls(class_name, traits_name, instance_type.children, ctx)
    if child_impls:
        sections.append("")
        sections.append("// --- Child-object accessors ---")
        sections.append("")
        sections.append(child_impls)

    # Namespace close
    sections.append("")
    sections.append(ctx.cpp_namespace_close())

    out_path = ctx.implementation_dir_for("object_types") / ctx.source_file_name(class_name)
    write_file(out_path, _qualify_core_references("\n".join(sections) + "\n", ctx))
    return out_path
