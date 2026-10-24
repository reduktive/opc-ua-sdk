# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Unit tests for ``codegen.context.EmitContext``.

Standalone (no pytest dependency).  Invoke via:

    python -m tooling.type_generator.tests.test_emit_context
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from ..codegen.context import EmitContext
from ..codegen.emit_ua_data_types_cpp import _create_structure_source_content
from ..codegen.emit_unions import _create_union_source_content
from ..io import load_template
from ..manifest import NS0_URI, NodesetConfig
from ..nodeset.index import NodeSetIndex
from ..nodeset.model import UaDataTypeDefinition, UaDataTypeField, UaDataTypeNodeWithDefinition


def _ns0_cfg() -> NodesetConfig:
    return NodesetConfig(
        uri=NS0_URI, sources=["ns0.xml"],
        include_prefix="ua_", cpp_namespace="ua", target="sdk", emit=True,
    )


def _di_cfg() -> NodesetConfig:
    return NodesetConfig(
        uri="http://opcfoundation.org/UA/DI/", sources=["di.xml"],
        include_prefix="ua_di_", cpp_namespace="ua::di",
        target="ua_di_types", emit=True,
    )


# -- Spec-derived shortcuts -------------------------------------------------


def test_ctx_exposes_spec_metadata():
    ctx = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert ctx.cpp_namespace == "ua::di"
    assert ctx.include_prefix == "ua_di_"
    assert ctx.target_name == "ua_di_types"


def test_guard_prefix_strips_trailing_underscore():
    """``ua_`` -> ``UA``; ``ua_di_`` -> ``UA_DI``."""
    ns0 = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    di = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert ns0.guard_prefix == "UA"
    assert di.guard_prefix == "UA_DI"


# -- File-naming helpers ----------------------------------------------------


def test_header_file_name_uses_prefix_and_snake_case():
    ns0 = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    di = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert ns0.header_file_name("DeviceType") == "ua_device_type.h"
    assert di.header_file_name("DeviceType") == "ua_di_device_type.h"


def test_source_file_name_mirrors_header():
    ctx = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert ctx.source_file_name("DeviceType") == "ua_di_device_type.cpp"


# -- Header guards ----------------------------------------------------------


def test_header_guard_concatenates_prefix_kind_typename():
    ns0 = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    di = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert ns0.header_guard("DATA_TYPE", "Foo") == "UA_DATA_TYPE_FOO_H"
    assert di.header_guard("DATA_TYPE", "DeviceType") == "UA_DI_DATA_TYPE_DEVICE_TYPE_H"


def test_header_guard_screaming_snakes_camelcase():
    ctx = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert ctx.header_guard("DATA_TYPE", "BaseObjectType") == "UA_DATA_TYPE_BASE_OBJECT_TYPE_H"


# -- Namespace blocks -------------------------------------------------------


def test_namespace_blocks_use_config_cpp_namespace():
    ns0 = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    di = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert ns0.cpp_namespace_open() == "namespace ua\n{"
    assert ns0.cpp_namespace_close() == "} // namespace ua"
    assert di.cpp_namespace_open() == "namespace ua::di\n{"
    assert di.cpp_namespace_close() == "} // namespace ua::di"


def test_structure_source_helpers_stay_internal_to_their_type_namespace():
    """Every helper group has internal linkage without changing qualified calls."""
    count = UaDataTypeField(name="Count", data_type="i=7")
    for cpp_namespace in ("ua", "ua::di"):
        for fields, abstract, encodings, groups, helpers in (
            ([count], False, None, 3,
             ["encode", "encode", "decode", "decode", "encode_id", "encode_id", "create"]),
            ([], False, None, 2, ["encode_id", "encode_id", "create"]),
            ([count], True, None, 1, ["encode", "encode", "decode", "decode"]),
            ([count], False, set(), 1, ["encode", "encode", "decode", "decode"]),
            ([], True, None, 0, []),
        ):
            node = UaDataTypeNodeWithDefinition(
                node_id="i=5001", browse_name="HelperProbe", parent_node_id="i=22",
                is_abstract=abstract, definition=UaDataTypeDefinition(name="HelperProbe", fields=fields),
            )
            index = NodeSetIndex(
                data_types={
                    "i=22": UaDataTypeNodeWithDefinition(
                        node_id="i=22", browse_name="Structure", is_abstract=True,
                    ),
                    "i=7": UaDataTypeNodeWithDefinition(node_id="i=7", browse_name="UInt32"),
                    node.node_id: node,
                },
                namespace_uris_by_nodeset={},
            )
            source = _create_structure_source_content(
                index, node.node_id, binary_encoding_type_names=encodings, cpp_namespace=cpp_namespace,
            )
            details, methods = source.split("bool HelperProbe::is_of_type", 1)
            assert details.count("namespace detail::HelperProbe\n{\nnamespace\n{\n") == groups, source
            assert details.count("}  // namespace\n}") == groups, source
            declarations = re.findall(r"^(?:void|unique_ptr<Structure>) (\w+)\(", details, re.MULTILINE)
            assert declarations == helpers, source
            assert not re.search(r"\bstatic\s+(?:void|unique_ptr<Structure>)\s+", details), source
            for helper in set(helpers):
                assert f"detail::HelperProbe::{helper}" in methods, source

    # These are class members, so the free-helper change must preserve static.
    parts = load_template("structure_parts.in")
    assert "static void register_type(" in parts
    assert "static const ObjectId defaultBinaryEncodingId" in parts
    assert "static const ObjectId defaultXmlEncodingId" in parts


def test_union_source_helpers_stay_internal_to_their_type_namespace():
    """Union codecs and factory stay inside one per-type unnamed namespace."""
    for cpp_namespace in ("ua", "ua::di"):
        for fields in ([], [UaDataTypeField(name="Count", data_type="i=7")]):
            node = UaDataTypeNodeWithDefinition(
                node_id="i=5002", browse_name="UnionProbe", parent_node_id="i=12756",
                definition=UaDataTypeDefinition(name="UnionProbe", is_union=True, fields=fields),
            )
            index = NodeSetIndex(
                data_types={
                    "i=7": UaDataTypeNodeWithDefinition(node_id="i=7", browse_name="UInt32"),
                    node.node_id: node,
                },
                namespace_uris_by_nodeset={},
            )
            source = _create_union_source_content(index, node.node_id, cpp_namespace=cpp_namespace)
            details, methods = source.split("bool UnionProbe::is_of_type", 1)
            assert details.count("namespace detail::UnionProbe\n{\nnamespace\n{\n") == 1, source
            assert "}  // namespace\n}  // namespace detail::UnionProbe" in details, source
            declarations = re.findall(r"^(?:void|unique_ptr<Structure>) (\w+)\(", details, re.MULTILINE)
            assert declarations == [
                "encode", "encode", "decode", "decode", "encode_id", "encode_id", "create",
            ], source
            assert not re.search(r"\bstatic\s+(?:void|unique_ptr<Structure>)\s+", details), source
            for helper in set(declarations):
                assert f"detail::UnionProbe::{helper}" in methods, source


# -- Template substitution --------------------------------------------------


def test_apply_template_substitutes_namespace_placeholders():
    ctx = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    src = "PLACEHOLDER_NS_OPEN\nclass Foo {};\nPLACEHOLDER_NS_CLOSE\n"
    out = ctx.apply_template(src)
    assert "namespace ua::di\n{" in out
    assert "} // namespace ua::di" in out
    assert "PLACEHOLDER_NS_OPEN" not in out
    assert "PLACEHOLDER_NS_CLOSE" not in out


def test_apply_template_preserves_other_placeholders():
    """``apply_template`` touches only its own keys."""
    ctx = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    src = "PLACEHOLDER_CLASS_NAME PLACEHOLDER_NS_OPEN PLACEHOLDER_HEADER_GUARD"
    out = ctx.apply_template(src)
    assert "PLACEHOLDER_CLASS_NAME" in out
    assert "PLACEHOLDER_HEADER_GUARD" in out


# -- Conditional spec includes ----------------------------------------------


def test_spec_includes_ns0_no_namespace_uri_use_emits_nothing():
    """NS0 header that never references ``specNamespaceUri`` gets neither include.

    NS0 emits into ``namespace ua`` (aliases header is empty) and an
    object-type / enum / optionset / simple header body never references
    ``specNamespaceUri`` - so the substitution must be empty.
    """
    ctx = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    src = "#include \"ua_includes.h\"\nPLACEHOLDER_SPEC_INCLUDES\nclass Foo {};"
    out = ctx.apply_template(src)
    assert "ua_namespace_uri.h" not in out
    assert "ua_aliases.h" not in out


def test_spec_includes_ns0_namespace_uri_use_emits_only_namespace_uri():
    """NS0 structure/union body referencing ``specNamespaceUri`` pulls in only that header."""
    ctx = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    src = "PLACEHOLDER_SPEC_INCLUDES\nstatic constexpr auto x = specNamespaceUri;"
    out = ctx.apply_template(src)
    assert '#include "ua_namespace_uri.h"' in out
    assert "ua_aliases.h" not in out


def test_spec_includes_companion_spec_always_pulls_aliases():
    """A companion spec (nested namespace) always needs the aliases header."""
    ctx = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    src = "PLACEHOLDER_SPEC_INCLUDES\nclass Foo {};"
    out = ctx.apply_template(src)
    assert '#include "ua_di_aliases.h"' in out
    assert "ua_di_namespace_uri.h" not in out


def test_spec_includes_companion_spec_with_namespace_uri_emits_both():
    """Companion-spec structure/union header pulls in both prefixed headers."""
    ctx = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    src = "PLACEHOLDER_SPEC_INCLUDES\nstatic constexpr auto x = specNamespaceUri;"
    out = ctx.apply_template(src)
    assert '#include "ua_di_namespace_uri.h"' in out
    assert '#include "ua_di_aliases.h"' in out


def test_spec_includes_ns0_datatype_id_token_pulls_datatype_id_header():
    """A structure/union header sourcing ``typeId`` from ``DataTypeId``
    pulls in ``ua_datatype_id.h`` - it is NOT reachable transitively via
    ``ua_node_id.h`` the way ``ObjectId`` is."""
    ctx = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    src = (
        "PLACEHOLDER_SPEC_INCLUDES\n"
        "static constexpr DataTypeId typeId{DataTypeId::Foo};"
    )
    out = ctx.apply_template(src)
    assert '#include "ua_datatype_id.h"' in out


def test_spec_includes_companion_datatype_id_token_pulls_prefixed_header():
    """Companion spec pulls in its OWN ``<prefix>datatype_id.h`` so bare
    ``DataTypeId`` binds to e.g. ``ua::di::DataTypeId``."""
    ctx = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    src = (
        "PLACEHOLDER_SPEC_INCLUDES\n"
        "static constexpr DataTypeId typeId{DataTypeId::Foo};"
    )
    out = ctx.apply_template(src)
    assert '#include "ua_di_datatype_id.h"' in out


def test_spec_includes_no_datatype_id_token_omits_datatype_id_header():
    """Headers that never reference ``DataTypeId`` (object-type, enum, ...) do
    not pay for the include."""
    ns0 = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    di = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    src = "PLACEHOLDER_SPEC_INCLUDES\nclass Foo {};"
    assert "datatype_id.h" not in ns0.apply_template(src)
    assert "datatype_id.h" not in di.apply_template(src)


# -- Output dir derivation --------------------------------------------------


def test_build_derives_canonical_output_layout():
    # NS0's generated tree is layered (library_layering.md section 2.3/section 5): the
    # wire/type categories land in core/, the instance-handle categories in
    # address_space/.  data_types is core.
    ctx = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert ctx.interface_dir == Path("/tmp/out/interface/core/generated/ua/data_types")
    assert ctx.implementation_dir == Path("/tmp/out/implementation/core/generated/ua/data_types")


def test_interface_dir_for_category():
    """Per-category subdirectories under the layered layout."""
    ctx = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    # Instance-handle categories live in the address-space layer.
    assert ctx.interface_dir_for("object_types") == Path(
        "/tmp/out/interface/address_space/generated/ua/object_types"
    )
    assert ctx.implementation_dir_for("object_types") == Path(
        "/tmp/out/implementation/address_space/generated/ua/object_types"
    )
    assert ctx.interface_dir_for("variable_types") == Path(
        "/tmp/out/interface/address_space/generated/ua/variable_types"
    )
    # Wire/type categories stay in core.
    assert ctx.interface_dir_for("status") == Path(
        "/tmp/out/interface/core/generated/ua/status"
    )


# -- Layout / amalgamation (NS0 vs consumer) --------------------------------


def test_flat_layout_false_for_ns0_true_for_consumer():
    """The interface/implementation split is hardcoded to NS0; every other spec
    emits a flat tree."""
    ns0 = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    di = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert ns0.flat_layout is False
    assert di.flat_layout is True


def test_flat_layout_collapses_interface_and_implementation_dirs():
    """A consumer spec co-locates headers + sources under ``<out>/<category>``."""
    di = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert di.interface_dir_for("data_types") == Path("/tmp/out/data_types")
    assert di.implementation_dir_for("data_types") == Path("/tmp/out/data_types")
    assert di.interface_dir_for("ids") == Path("/tmp/out/ids")
    # Header and source dirs are the SAME object for a flat spec.
    assert di.interface_dir_for("data_types") == di.implementation_dir_for("data_types")


def test_amalgamate_sources_reflects_manifest_field():
    """``amalgamate_sources`` is a manifest option, default off; NS0 turns it on."""
    off = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert off.amalgamate_sources is False

    on_cfg = NodesetConfig(
        uri=NS0_URI, sources=["ns0.xml"], include_prefix="ua_",
        cpp_namespace="ua", target="sdk", emit=True, amalgamate_sources=True,
    )
    on = EmitContext.build(on_cfg, NodeSetIndex.empty(), Path("/tmp/out"))
    assert on.amalgamate_sources is True


# -- Generated doc comments (is_ns0 / doc_comment) --------------------------


def test_is_ns0_true_for_ns0_false_for_companion():
    ns0 = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    di = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    assert ns0.is_ns0 is True
    assert di.is_ns0 is False


def test_doc_comment_ns0_emits_brief_and_ingroup():
    """NS0 (the documented public surface) gets the brief + @ingroup block."""
    ctx = EmitContext.build(_ns0_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    out = ctx.doc_comment("OPC UA Foo structured data type.", "ua_data_types")
    assert out == "/// OPC UA Foo structured data type.\n/// @ingroup ua_data_types"


def test_doc_comment_companion_returns_fallback_keeping_output_identical():
    """A companion spec gets the fallback (its original ``//`` comment, or an
    empty string) - never the ``///`` + @ingroup block - so committed
    companion-spec output stays byte-identical to before this feature."""
    ctx = EmitContext.build(_di_cfg(), NodeSetIndex.empty(), Path("/tmp/out"))
    # No fallback supplied -> empty (the placeholder line collapses under clang-format).
    assert ctx.doc_comment("OPC UA Foo structured data type.", "ua_data_types") == ""
    # Fallback supplied (e.g. an instance type's original // comment) -> preserved verbatim.
    assert (
        ctx.doc_comment("brief", "ua_information_model", fallback="// helper comment")
        == "// helper comment"
    )


# -- runner -----------------------------------------------------------------


def _run() -> int:
    failed = 0
    tests = [
        (name, fn)
        for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    ]
    for name, fn in tests:
        try:
            fn()
            print(f"OK   {name}")
        except AssertionError as ex:
            failed += 1
            print(f"FAIL {name}: {ex}", file=sys.stderr)
        except Exception as ex:
            failed += 1
            print(f"ERR  {name}: {type(ex).__name__}: {ex}", file=sys.stderr)
    if failed:
        print(f"\n{failed} test(s) failed", file=sys.stderr)
    else:
        print(f"\n{len(tests)} test(s) passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
