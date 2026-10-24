# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Generate compilation, instantiation, and accessor-exercise tests for
instance-handle types.

Three concerns are covered per generated type:
- ``<Class>_DefaultConstruction``: a smoke test that the empty handle type
  is constructible (catches link/visibility regressions).
- ``<Class>_CreateAndAttach``: end-to-end create/attach round-trip against
  the in-test ``AddressSpace`` fixture.
- ``<Class>_Properties``: walks every generated property accessor - typed
  ``read_X_sync`` / ``write_X_sync`` pairs plus untyped ``X_property_sync``
  handles. Asserts read-back equality whenever a write actually succeeds,
  so a real regression that drops written values is caught while
  read-only properties (which surface ``BadNotWritable``) still exercise
  the failure branch of the generated write helper.
- ``<Class>_Children``: walks typed child-object accessors and exercises
  per-method handler registration plus method-accessor lookup.
"""
from __future__ import annotations

from pathlib import Path

from ..io import load_template, write_file
from ..naming import to_camel_back, to_snake_case
from ..nodeset.model import ModellingRule
from ..types.model import ChildInfo, ChildKind, InstanceType, InstanceTypeKind, MethodArgumentInfo
from .emit_variable_type import projects_value_as_text


def _snake(name: str) -> str:
    return to_snake_case(name)


def _pascal(name: str) -> str:
    if not name:
        return name
    return name[0].upper() + name[1:]


def _is_placeholder_browse_name(name: str) -> bool:
    """Mirror of emit_instance_common._is_placeholder_browse_name."""
    return "<" in name or ">" in name


# Sentinel expressions for typed-write/read property tests, keyed by the C++
# type the generator emits for the property. Values are deliberately
# distinct from the type's default so a regression that silently drops the
# write is caught by the read-back equality check.
_PROP_SENTINELS: dict[str, str] = {
    "bool": "true",
    "uint8_t": "uint8_t{123}",
    "uint16_t": "uint16_t{12345}",
    "uint32_t": "uint32_t{123456}",
    "uint64_t": "uint64_t{1234567}",
    "int8_t": "int8_t{123}",
    "int16_t": "int16_t{12345}",
    "int32_t": "int32_t{123456}",
    "int64_t": "int64_t{1234567}",
    "int": "int{123}",
    "float": "1.5f",
    "double": "1.5",
    "ByteString": "ByteString{1, 2, 3}",
    "String": 'String{"test"}',
    "DateTime": "DateTime::now()",
    "NodeId": "NodeId{1234}",
    "QualifiedName": 'QualifiedName{0, "test"}',
    "LocalizedText": 'LocalizedText{"en", "test"}',
}


def _sentinel_for(cpp_type: str) -> str | None:
    return _PROP_SENTINELS.get(cpp_type)


# Distinct second sentinel values used for method output args so that input vs
# output mix-ups in the generated adapter are caught - if the same value was
# used for both, an adapter that accidentally echoed inputs to outputs would
# silently pass.
_OUTPUT_SENTINELS: dict[str, str] = {
    "bool": "false",
    "uint8_t": "uint8_t{77}",
    "uint16_t": "uint16_t{7777}",
    "uint32_t": "uint32_t{777777}",
    "uint64_t": "uint64_t{7777777}",
    "int8_t": "int8_t{77}",
    "int16_t": "int16_t{7777}",
    "int32_t": "int32_t{777777}",
    "int64_t": "int64_t{7777777}",
    "int": "int{77}",
    "float": "2.5f",
    "double": "2.5",
    "ByteString": "ByteString{7, 8, 9}",
    "String": 'String{"out"}',
    "DateTime": "DateTime{}",
    "NodeId": "NodeId{4321}",
    "QualifiedName": 'QualifiedName{0, "out"}',
    "LocalizedText": 'LocalizedText{"en", "out"}',
}


def _can_invoke_method(method: ChildInfo) -> bool:
    """A method is invokable from a generated test when every input and output
    argument is a scalar of a type we have known sentinel values for."""
    if method.modelling_rule != ModellingRule.mandatory:
        return False
    for arg in list(method.input_arguments) + list(method.output_arguments):
        if arg.is_array:
            return False
        if _PROP_SENTINELS.get(arg.cpp_type) is None:
            return False
        if _OUTPUT_SENTINELS.get(arg.cpp_type) is None:
            return False
    return True


def _create_call(
    class_name: str,
    kind: InstanceTypeKind,
    browse_suffix: str,
    include_optionals: bool = False,
) -> str:
    """Return the C++ try_create_sync(...) call for the given instance type.

    When ``include_optionals`` is True, the call passes an
    ``InstantiationOptions`` whose ``optionalChildFilter`` returns true for
    every non-mandatory child, so optional properties / objects are
    instantiated alongside mandatory ones. Tests that exercise per-property
    write/read pairs need this so optional properties physically exist in
    the address space.
    """
    if include_optionals:
        opts_expr = "optionsWithAllOptionals"
    else:
        opts_expr = "{}"

    if kind == InstanceTypeKind.object_type:
        return (
            f"{class_name}::try_create_sync(*addressSpace,\n"
            f"        NodeId{{ObjectId::ObjectsFolder}},\n"
            f'        QualifiedName{{0, "Test{class_name}{browse_suffix}"}},\n'
            f"        {opts_expr})"
        )
    attributes_expr = "{}"
    if class_name == "YArrayItem":
        attributes_expr = (
            "VariableInstantiationAttributes{.dataType = NodeId{DataTypeId::Double}, "
            ".valueRank = 1}"
        )
    return (
        f"{class_name}::try_create_sync(*addressSpace,\n"
        f"        NodeId{{ObjectId::ObjectsFolder}},\n"
        f'        QualifiedName{{0, "Test{class_name}{browse_suffix}"}},\n'
        f"        {opts_expr}, {attributes_expr})"
    )


def _all_optionals_setup_lines(children: list[ChildInfo]) -> list[str]:
    """Lines that build an ``InstantiationOptions`` instance which includes
    every optional child. Emitted at the top of any test that asks for
    optional-inclusive instantiation.

    An optional child declared with an abstract type is declined: the test names
    no concrete type for it, and without one the instantiation is refused
    (OPC 10000-3 section 6.2.1; ``InstantiationOptions::memberTypeResolver``)."""
    abstract_typed = [
        c.browse_name for c in children
        if c.declared_type_abstract and c.modelling_rule == ModellingRule.optional
    ]
    if not abstract_typed:
        return [
            "    InstantiationOptions optionsWithAllOptionals;",
            "    optionsWithAllOptionals.optionalChildFilter =",
            "        [](const ChildFilterInfo&) { return true; };",
        ]
    declined = " && ".join(f'info.browseName.name() != "{name}"' for name in abstract_typed)
    return [
        "    InstantiationOptions optionsWithAllOptionals;",
        f"    // {', '.join(abstract_typed)}: declared with an abstract type, which this test names no",
        "    // concrete subtype for (memberTypeResolver), so it is not created.",
        "    optionsWithAllOptionals.optionalChildFilter =",
        f"        [](const ChildFilterInfo& info) {{ return {declined}; }};",
    ]


def _properties_test_body(class_name: str, kind: InstanceTypeKind, children: list[ChildInfo]) -> str:
    create_call = _create_call(class_name, kind, "Props", include_optionals=True)
    lines: list[str] = []
    lines.extend(_all_optionals_setup_lines(children))
    lines.append(f"    auto createResult = {create_call};")
    lines.append("    ASSERT_TRUE(createResult.is_good());")
    lines.append("    auto obj = std::move(createResult).value();")
    lines.append("")

    typed_props = [c for c in children if c.kind == ChildKind.property and c.variant_type_check]
    all_props = [c for c in children if c.kind == ChildKind.property]

    if all_props:
        lines.append("    // Untyped Property handle lookup - exercises the find-by-browse-name")
        lines.append("    // path for every declared property.")
        for p in all_props:
            sn = _snake(p.cpp_name)
            lines.append("    {")
            lines.append(f"        auto h = obj.try_{sn}_property_sync();")
            lines.append(f"        (void)h.status_code();")
            # Throwing variant (no try_ prefix): same find-by-browse-name path,
            # but `.value()`-unwraps. Tolerate a throw - a placeholder/absent
            # optional property surfaces as a bad status the try_ variant ignores.
            lines.append(f"        try {{ (void)obj.{sn}_property_sync(); }} catch (...) {{}}")
            lines.append("    }")
        lines.append("")

    if typed_props:
        lines.append("    // Typed read/write - every property (mandatory + optional) is")
        lines.append("    // instantiated by the optional-inclusive create above, so we can")
        lines.append("    // assert write+read both succeed and the read returns the sentinel.")
        for p in typed_props:
            sn = _snake(p.cpp_name)
            ct = p.cpp_type
            sentinel = _sentinel_for(ct)
            if p.browse_name == "ValueAsText" and projects_value_as_text(class_name):
                # Projected from the Variable's Value by a read-only source, so a write is refused
                # (Bad_NotWritable: a read-only value source takes no writes) and the read answers the
                # projection: the Variable here holds no value, which has no text.
                lines.append("    {")
                lines.append(
                    f"        EXPECT_EQ(obj.try_write_{sn}_sync({sentinel}).status_code().as_status(),"
                    f" Status::BadNotWritable);"
                )
                lines.append(f"        auto rd = obj.try_read_{sn}_sync();")
                lines.append(f"        ASSERT_TRUE(rd.is_good())")
                lines.append(
                    f"            << \"{sn} read failed: 0x\" << std::hex"
                    f" << rd.status_code().as_uint32();"
                )
                lines.append(f"        EXPECT_EQ(rd.value(), LocalizedText{{}});")
                lines.append("    }")
                continue
            if sentinel is None:
                # Unknown cpp_type - at least call try_read so we cover the read path.
                lines.append("    {")
                lines.append(f"        auto rd = obj.try_read_{sn}_sync();")
                lines.append(f"        (void)rd.status_code();")
                # Throwing read variant (no try_ prefix); tolerate a bad-status throw.
                lines.append(f"        try {{ (void)obj.read_{sn}_sync(); }} catch (...) {{}}")
                lines.append("    }")
                continue
            lines.append("    {")
            lines.append(f"        auto sentinel = {sentinel};")
            lines.append(f"        auto wr = obj.try_write_{sn}_sync(sentinel);")
            lines.append(f"        EXPECT_TRUE(wr.is_good())")
            lines.append(
                f"            << \"{sn} write failed: 0x\" << std::hex"
                f" << wr.status_code().as_uint32();"
            )
            lines.append(f"        auto rd = obj.try_read_{sn}_sync();")
            lines.append(f"        EXPECT_TRUE(rd.is_good())")
            lines.append(
                f"            << \"{sn} read failed: 0x\" << std::hex"
                f" << rd.status_code().as_uint32();"
            )
            lines.append(f"        if (wr.is_good() && rd.is_good())")
            lines.append(f"        {{")
            lines.append(f"            EXPECT_EQ(rd.value(), sentinel);")
            lines.append(f"            // Throwing variants (no try_ prefix): same write+read")
            lines.append(f"            // round-trip. Only reached when the try_ variants are good,")
            lines.append(f"            // so these never throw here; a regression that broke the")
            lines.append(f"            // throwing path would surface as a thrown UaException.")
            lines.append(f"            obj.write_{sn}_sync(sentinel);")
            lines.append(f"            EXPECT_EQ(obj.read_{sn}_sync(), sentinel);")
            lines.append(f"        }}")
            lines.append("    }")

    return "\n".join(lines)


def _children_test_body(class_name: str, kind: InstanceTypeKind, children: list[ChildInfo]) -> str:
    create_call = _create_call(class_name, kind, "Kids", include_optionals=True)
    lines: list[str] = []
    lines.extend(_all_optionals_setup_lines(children))
    lines.append(f"    auto createResult = {create_call};")
    lines.append("    ASSERT_TRUE(createResult.is_good());")
    lines.append("    auto obj = std::move(createResult).value();")
    lines.append("")

    typed_children = [
        c for c in children
        if c.child_type_class_name
        and c.kind in (ChildKind.child_object, ChildKind.data_variable)
        and not _is_placeholder_browse_name(c.browse_name)
    ]

    methods = [c for c in children if c.kind == ChildKind.method]

    if typed_children:
        lines.append("    // Typed child-object / data-variable accessors.")
        for c in typed_children:
            sn = _snake(c.cpp_name)
            lines.append("    {")
            lines.append(f"        auto r = obj.try_{sn}_sync();")
            lines.append(f"        (void)r.status_code();")
            # Throwing variant (no try_ prefix): same typed-child lookup, but
            # `.value()`-unwraps. Tolerate a throw (an absent optional child
            # surfaces as a bad status the try_ variant ignores).
            lines.append(f"        try {{ (void)obj.{sn}_sync(); }} catch (...) {{}}")
            lines.append("    }")
        lines.append("")

    if methods:
        lines.append("    // Method handler registration + method-accessor lookup.")
        for m in methods:
            sn = _snake(m.cpp_name)
            bn = _pascal(m.cpp_name)
            # Both handler forms register (item 8b section 9.9): the synchronous one returns the outputs,
            # the asynchronous one completes through its callback.
            in_param = f", const {class_name}::{bn}InputArguments&" if m.input_arguments else ""
            if m.output_arguments:
                out_type = f"{class_name}::{bn}OutputArguments"
                sync_return = f"{{ return {out_type}{{}}; }}"
                async_complete = f"{{ complete({out_type}{{}}); }}"
            else:
                out_type = ""
                sync_return = "{ return {}; }"
                async_complete = "{ complete({}); }"
            lines.append("    {")
            lines.append(f"        {class_name}::{bn}Handler handler = [](const MethodCall&{in_param}) -> MethodResult<{out_type}>")
            lines.append(f"        {sync_return};")
            lines.append(f"        auto sh = obj.try_set_{sn}_handler_sync(std::move(handler));")
            lines.append(f"        (void)sh.status_code();")
            lines.append(f"        {class_name}::{bn}AsyncHandler asyncHandler = [](const MethodCall&{in_param}, MethodResultCallback<{out_type}> complete)")
            lines.append(f"        {async_complete};")
            lines.append(f"        auto ash = obj.try_set_{sn}_handler_sync(std::move(asyncHandler));")
            lines.append(f"        (void)ash.status_code();")
            lines.append(f"        auto ma = obj.try_{sn}_method_sync();")
            lines.append(f"        (void)ma.status_code();")
            lines.append("    }")

    return "\n".join(lines)


def _unattached_accessor_sweep_body(class_name: str, children: list[ChildInfo]) -> str:
    """Body of the ``<Class>_UnattachedAccessorsFailClosed`` test.

    Every generated accessor, invoked on a DEFAULT-CONSTRUCTED (address-space-less)
    handle, must fail closed with a bad status rather than crash. This drives the
    ``if (!mAddressSpace)`` guard branch present in every ``read_*``/``write_*``
    async body - the branch the attached-instance Properties/Children tests (which
    always run against a live handle) never reach. Typed value read/write accessors
    return ``BadInvalidState`` deterministically, so they are asserted; the untyped
    handle / child / method lookups only need to run without crashing, so their
    status is drained.
    """
    all_props = [c for c in children if c.kind == ChildKind.property]
    typed_props = [c for c in all_props if c.variant_type_check]
    typed_children = [
        c for c in children
        if c.child_type_class_name
        and c.kind in (ChildKind.child_object, ChildKind.data_variable)
        and not _is_placeholder_browse_name(c.browse_name)
    ]
    methods = [c for c in children if c.kind == ChildKind.method]

    lines: list[str] = [
        f"    {class_name} obj;  // default-constructed: no bound address space",
    ]

    if typed_props:
        lines.append("")
        lines.append("    // Typed value read/write accessors fail closed with a bad status (the")
        lines.append("    // !mAddressSpace guard), never a crash, on an unattached handle.")
        for p in typed_props:
            sn = _snake(p.cpp_name)
            lines.append(f"    EXPECT_TRUE(obj.try_read_{sn}_sync().status_code().is_bad());")
            sentinel = _sentinel_for(p.cpp_type)
            if sentinel is not None:
                lines.append(
                    f"    EXPECT_TRUE(obj.try_write_{sn}_sync({sentinel}).status_code().is_bad());"
                )

    if all_props:
        lines.append("")
        lines.append("    // Untyped property-handle lookups also run their guard; drain the status")
        lines.append("    // (only that they do not crash on an unattached handle is required here).")
        for p in all_props:
            sn = _snake(p.cpp_name)
            lines.append(f"    (void)obj.try_{sn}_property_sync().status_code();")

    if typed_children:
        lines.append("")
        lines.append("    // Typed child-object / data-variable handle lookups.")
        for c in typed_children:
            sn = _snake(c.cpp_name)
            lines.append(f"    (void)obj.try_{sn}_sync().status_code();")

    if methods:
        lines.append("")
        lines.append("    // Method-accessor lookups.")
        for m in methods:
            sn = _snake(m.cpp_name)
            lines.append(f"    (void)obj.try_{sn}_method_sync().status_code();")

    return "\n".join(lines)


def _method_invocation_test(class_name: str, kind: InstanceTypeKind, method: ChildInfo) -> str:
    """Emit a per-method test that drives the full input-deserialise -> handler
    call -> output-serialise round-trip via MethodAccessor::try_call_sync."""
    sn = _snake(method.cpp_name)
    bn = _pascal(method.cpp_name)
    create_call = _create_call(class_name, kind, f"Method{bn}")

    input_args = list(method.input_arguments)
    output_args = list(method.output_arguments)

    lines: list[str] = []
    lines.append(f"    auto createResult = {create_call};")
    lines.append("    ASSERT_TRUE(createResult.is_good());")
    lines.append("    auto obj = std::move(createResult).value();")
    lines.append("")
    lines.append("    std::atomic<bool> handlerCalled{false};")

    # The synchronous handler form (item 8b section 9.9).
    out_type = f"{class_name}::{bn}OutputArguments" if output_args else ""
    if input_args:
        handler_sig = f"[&](const MethodCall&, const {class_name}::{bn}InputArguments& in) -> MethodResult<{out_type}>"
    else:
        handler_sig = f"[&](const MethodCall&) -> MethodResult<{out_type}>"

    lines.append(f"    {class_name}::{bn}Handler handler = {handler_sig}")
    lines.append("    {")
    lines.append("        handlerCalled = true;")
    # Capture each sentinel into a local before EXPECT_EQ - multi-element
    # brace-init literals like ``ByteString{1, 2, 3}`` confuse the macro
    # preprocessor when used as a direct argument.
    for arg in input_args:
        in_sentinel = _PROP_SENTINELS[arg.cpp_type]
        lines.append(f"        auto expected_in_{arg.name} = {in_sentinel};")
        lines.append(f"        EXPECT_EQ(in.{to_camel_back(arg.name)}, expected_in_{arg.name});")
    if output_args:
        lines.append(f"        {class_name}::{bn}OutputArguments out;")
        for arg in output_args:
            out_sentinel = _OUTPUT_SENTINELS[arg.cpp_type]
            lines.append(f"        out.{to_camel_back(arg.name)} = {out_sentinel};")
        lines.append("        return out;")
    else:
        lines.append("        return {};")
    lines.append("    };")
    lines.append("")

    lines.append(f"    auto setRes = obj.try_set_{sn}_handler_sync(std::move(handler));")
    lines.append("    ASSERT_TRUE(setRes.is_good())")
    lines.append('        << "set handler failed: 0x" << std::hex << setRes.status_code().as_uint32();')
    lines.append("")
    lines.append(f"    auto maRes = obj.try_{sn}_method_sync();")
    lines.append("    ASSERT_TRUE(maRes.is_good())")
    lines.append('        << "method accessor lookup failed: 0x" << std::hex << maRes.status_code().as_uint32();')
    lines.append("    auto ma = std::move(maRes).value();")
    lines.append("")

    lines.append("    CallMethodRequest req;")
    lines.append("    req.object_id() = obj.node_id();")
    lines.append("    req.method_id() = ma.get_node_id();")
    if input_args:
        lines.append(f"    req.input_arguments().resize({len(input_args)});")
        for i, arg in enumerate(input_args):
            in_sentinel = _PROP_SENTINELS[arg.cpp_type]
            lines.append(f"    req.input_arguments()[{i}] = Variant{{{in_sentinel}}};")
    lines.append("")
    lines.append("    auto callRes = ma.try_call_sync(req);")
    lines.append("    ASSERT_TRUE(callRes.is_good())")
    lines.append('        << "call failed: 0x" << std::hex << callRes.status_code().as_uint32();')
    lines.append("    EXPECT_TRUE(handlerCalled.load());")
    if output_args:
        lines.append("    const auto& outArgs = callRes.value().output_arguments();")
        lines.append(f"    ASSERT_EQ(outArgs.size(), {len(output_args)}u);")
        for i, arg in enumerate(output_args):
            out_sentinel = _OUTPUT_SENTINELS[arg.cpp_type]
            lines.append(f"    auto expected_out_{arg.name} = {out_sentinel};")
            lines.append(
                f"    EXPECT_EQ(outArgs[{i}].as<{arg.cpp_type}>(), expected_out_{arg.name});"
            )

    body = "\n".join(lines)
    return (
        f"\nTEST_F(GeneratedInstanceTypeTests, {class_name}_Method_{bn}) {{\n"
        f"{body}\n"
        "}\n"
    )


class InstanceTypeTestsEmitter:
    """Emits the generated instance-type tests source.

    The output lives at
    ``<impl>/address_space/generated/ua/generated_instance_type_tests.cpp``
    (note: at the ``ua/`` level, not under any category subdir; the instance
    handles it exercises are the address-space layer's, so it sits in that
    layer's generated tree - library_layering.md section 2.3/section 5).  The tests reference
    NS0 types; downstream specs should not invoke this.
    """

    def __init__(self, ctx):
        self._ctx = ctx

    def emit(self, instance_types: list[InstanceType]) -> Path:
        # One level above the per-category subdirs, in the address-space layer's
        # generated tree (instance handles are address-space).
        output_dir = (
            self._ctx.output_root
            / "implementation" / self._ctx.layer_segment_for("object_types") / "generated" / "ua"
        )
        return emit_instance_type_tests(output_dir, instance_types)


# The NS0 dictionary-entry types whose direct instances OPC 10000-19 5.3 and 5.4 place in a fixed
# namespace, and the public constant naming it. Instantiation never registers a namespace, so a test
# that creates one of these registers the namespace first.
_DICTIONARY_NAMESPACES = {
    "i=17598": "irdiDictionaryNamespaceUri",  # IrdiDictionaryEntryType
    "i=17600": "uriDictionaryNamespaceUri",  # UriDictionaryEntryType
}

_REGISTER_DICTIONARY_NAMESPACE = """
namespace
{

/// Registers a Part 19 dictionary namespace in the suite's shared address space unless it already is.
void register_dictionary_namespace(AddressSpace& space, std::string_view uri)
{
    try
    {
        (void)space.namespace_array().get_namespace_index(uri);
        return;
    }
    catch (const UaException&)
    {
    }
    (void)space.add_namespace_sync(space.create_namespace(uri, {}));
}

}  // namespace
"""


def _with_dictionary_namespace(body_open: str, it: InstanceType) -> str:
    """@p body_open (a test's opening line) followed by the namespace registration @p it needs, if any."""
    uri = _DICTIONARY_NAMESPACES.get(it.node_id)
    if uri is None:
        return body_open
    return body_open + f"    register_dictionary_namespace(*addressSpace, {uri});\n"


def emit_instance_type_tests(
    output_dir: Path,
    instance_types: list[InstanceType],
) -> Path:
    text = load_template("generated_instance_type_tests.in")

    # Each generated type header (e.g. ``ua_file.h``) already forward-declares
    # ``MethodCallContext`` for its handler typedefs. Method invocation tests
    # need the request type plus ``<atomic>`` for the shared "handler ran" flag.
    includes: list[str] = [
        "#include <atomic>",
        '#include "ua_call_method_request.h"',
        '#include "ua_datatype_id.h"',
        '#include "ua_instantiation_options.h"',
    ]
    seen: set[str] = set()
    for it in instance_types:
        header = f"ua_{_snake(it.class_name)}.h"
        if header not in seen:
            seen.add(header)
            includes.append(f'#include "{header}"')

    test_cases: list[str] = []
    if any(it.node_id in _DICTIONARY_NAMESPACES for it in instance_types):
        includes.append('#include "ua_namespace_array.h"')
        includes.append("#include <string_view>")
        test_cases.append(_REGISTER_DICTIONARY_NAMESPACE)

    for it in instance_types:
        cn = it.class_name
        kind = it.kind

        # --- DefaultConstruction ---
        test_cases.append(
            f"\nTEST_F(GeneratedInstanceTypeTests, {cn}_DefaultConstruction) {{\n"
            f"    {cn} obj;\n"
            "    (void)obj;\n"
            "}\n"
        )

        # --- CreateAndAttach ---
        create_call = _create_call(cn, kind, "")
        # Throwing-variant create (no try_ prefix), with a distinct browse name so
        # it does not collide with the try_create node above.
        throwing_create = _create_call(cn, kind, "Throwing").replace(
            "try_create_sync", "create_sync"
        )
        test_cases.append(
            _with_dictionary_namespace(f"\nTEST_F(GeneratedInstanceTypeTests, {cn}_CreateAndAttach) {{\n", it)
            + f"    auto createResult = {create_call};\n"
            "    ASSERT_TRUE(createResult.is_good());\n"
            "    auto obj = std::move(createResult).value();\n"
            f"    auto attachResult = {cn}::try_attach_sync(*addressSpace, obj.node_id());\n"
            "    EXPECT_TRUE(attachResult.is_good());\n"
            "    // Throwing-variant create/attach (no try_ prefix): same contract,\n"
            "    // .value()-unwrapping. On the valid fixture these never throw.\n"
            f"    auto attached = {cn}::attach_sync(*addressSpace, obj.node_id());\n"
            "    (void)attached;\n"
            f"    auto created2 = {throwing_create};\n"
            "    (void)created2;\n"
            "}\n"
        )

        # --- Properties test (only emitted if this type has properties) ---
        if any(c.kind == ChildKind.property for c in it.children):
            body = _properties_test_body(cn, kind, it.children)
            test_cases.append(
                _with_dictionary_namespace(f"\nTEST_F(GeneratedInstanceTypeTests, {cn}_Properties) {{\n", it)
                + f"{body}\n"
                "}\n"
            )

        # --- Children test (typed children and/or methods) ---
        has_typed_children = any(
            c.child_type_class_name
            and c.kind in (ChildKind.child_object, ChildKind.data_variable)
            and not _is_placeholder_browse_name(c.browse_name)
            for c in it.children
        )
        has_methods = any(c.kind == ChildKind.method for c in it.children)
        if has_typed_children or has_methods:
            body = _children_test_body(cn, kind, it.children)
            test_cases.append(
                _with_dictionary_namespace(f"\nTEST_F(GeneratedInstanceTypeTests, {cn}_Children) {{\n", it)
                + f"{body}\n"
                "}\n"
            )

        # --- Unattached-accessor guard sweep (every accessor's !mAddressSpace
        # fail-closed branch, which the attached Properties/Children tests never
        # reach) - emitted whenever the type exposes any accessor at all. ---
        has_properties = any(c.kind == ChildKind.property for c in it.children)
        if has_properties or has_typed_children or has_methods:
            body = _unattached_accessor_sweep_body(cn, it.children)
            test_cases.append(
                f"\nTEST_F(GeneratedInstanceTypeTests, {cn}_UnattachedAccessorsFailClosed) {{\n"
                f"{body}\n"
                "}\n"
            )

        # Per-method end-to-end invocation tests - only for mandatory methods
        # whose argument shape we know how to drive from a generated test.
        for child in it.children:
            if child.kind != ChildKind.method:
                continue
            if not _can_invoke_method(child):
                continue
            test_cases.append(_method_invocation_test(cn, kind, child))

    text = text.replace("PLACEHOLDER_INCLUDES", "\n".join(includes))
    text = text.replace("PLACEHOLDER_TEST_CASES", "".join(test_cases).rstrip("\n"))

    out_path = output_dir / "generated_instance_type_tests.cpp"
    write_file(out_path, text)
    return out_path
