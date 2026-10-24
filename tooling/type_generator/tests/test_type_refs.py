# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Unit tests for the unified type-reference resolver.

Standalone (no pytest dependency).  Invoke via:

    python -m tooling.type_generator.tests.test_type_refs
"""

from __future__ import annotations

import sys

from ..manifest import NS0_URI, NodesetConfig
from ..nodeset.index import NodeSetIndex
from ..nodeset.model import (
    UaDataTypeDefinition,
    UaDataTypeField,
    UaDataTypeNodeWithDefinition,
)
from ..types.refs import TypeRef, TypeResolver


# -- Fixtures ---------------------------------------------------------------


def _ns0_cfg() -> NodesetConfig:
    return NodesetConfig(
        uri=NS0_URI,
        sources=["ns0.xml"],
        include_prefix="ua_",
        cpp_namespace="ua",
        target="sdk",
        emit=True,
    )


def _di_cfg() -> NodesetConfig:
    return NodesetConfig(
        uri="http://opcfoundation.org/UA/DI/",
        sources=["di.xml"],
        include_prefix="ua_di_",
        cpp_namespace="ua::di",
        target="ua_di_types",
        emit=True,
    )


def _two_spec_index() -> tuple[NodeSetIndex, NodesetConfig, NodesetConfig]:
    """Index with NS0 ``Structure`` (i=22) + DI ``DeviceHealth`` (ns=1;i=15001)."""

    ns0_node = UaDataTypeNodeWithDefinition(
        node_id="i=22",
        browse_name="Structure",
        parent_node_id=None,
        source_nodeset="/abs/ns0.xml",
        is_abstract=True,
        definition=UaDataTypeDefinition(name="Structure", fields=[]),
    )
    di_node = UaDataTypeNodeWithDefinition(
        node_id="ns=1;i=15001",
        browse_name="DeviceHealth",
        parent_node_id="i=22",
        source_nodeset="/abs/di.xml",
        is_abstract=False,
        definition=UaDataTypeDefinition(
            name="DeviceHealth",
            fields=[UaDataTypeField(name="Status", data_type="i=22")],
        ),
    )
    index = NodeSetIndex(
        data_types={"i=22": ns0_node, "ns=1;i=15001": di_node},
        namespace_uris_by_nodeset={
            "/abs/ns0.xml": [],
            "/abs/di.xml": ["http://opcfoundation.org/UA/DI/"],
        },
    )
    ns0 = _ns0_cfg()
    di = _di_cfg()
    index = index.with_config_by_source(
        {"/abs/ns0.xml": ns0, "/abs/di.xml": di}
    )
    return index, ns0, di


# -- TypeRef invariants -----------------------------------------------------


def test_in_spec_ref_has_bare_qualified_name():
    """In-spec qualification is bare - no leading `::`."""
    index, ns0, _di = _two_spec_index()
    resolver = TypeResolver(index, current_config=ns0)
    ref = resolver.resolve("i=22")  # NS0 referencing its own type
    assert ref.is_in_spec is True
    assert ref.qualified_class_name == "Structure"
    assert ref.short_name == "Structure"
    assert ref.header_include == "ua_structure.h"


def test_cross_spec_ref_is_leading_colon_qualified():
    """Cross-spec qualification leads with `::` to short-circuit ADL."""
    index, _ns0, di = _two_spec_index()
    resolver = TypeResolver(index, current_config=di)
    ref = resolver.resolve("i=22")  # DI emit context, NS0 type
    assert ref.is_in_spec is False
    assert ref.qualified_class_name == "::ua::Structure"
    assert ref.short_name == "Structure"
    assert ref.header_include == "ua_structure.h"


def test_cross_spec_ref_uses_owning_spec_prefix():
    """When the owner is DI, headers/qualifications come from DI's metadata."""
    index, ns0, _di = _two_spec_index()
    resolver = TypeResolver(index, current_config=ns0)
    # NS0 referencing a DI type (hypothetical - NS0 wouldn't normally do
    # this, but the resolver shouldn't care).
    ref = resolver.resolve("ns=1;i=15001")
    assert ref.is_in_spec is False
    assert ref.qualified_class_name == "::ua::di::DeviceHealth"
    assert ref.header_include == "ua_di_device_health.h"


# -- Always-returns-a-value contract ----------------------------------------


def test_resolver_returns_external_qualified_when_no_current_config():
    """``current_config=None`` (introspection: no spec in scope).

    A node that has a *known* owner resolves to an external, fully-qualified
    ref against its owner's namespace - there is no "current" spec for it to be
    in-spec relative to, so the qualified name is explicit (``::ua::Structure``).
    (A node with *no* owner still falls back to the legacy bare in-spec form;
    see ``test_resolver_returns_in_spec_when_owner_unknown``.)"""
    index, _ns0, _di = _two_spec_index()
    resolver = TypeResolver(index, current_config=None)
    ref = resolver.resolve("i=22")
    assert ref.is_in_spec is False
    assert ref.header_include == "ua_structure.h"
    assert ref.qualified_class_name == "::ua::Structure"


def test_resolver_returns_in_spec_when_owner_unknown():
    """No manifest annotation on the source -> treat as in-spec."""
    ns0_node = UaDataTypeNodeWithDefinition(
        node_id="i=22", browse_name="Structure",
        parent_node_id=None, source_nodeset="ns0.xml",
        is_abstract=True,
    )
    index = NodeSetIndex(
        data_types={"i=22": ns0_node},
        namespace_uris_by_nodeset={"ns0.xml": []},
    )
    resolver = TypeResolver(index, current_config=_di_cfg())
    ref = resolver.resolve("i=22")
    assert ref.is_in_spec is True


def test_resolver_returns_placeholder_for_unknown_node():
    """Unknown node-id -> a loud-but-valid TypeRef, never None."""
    index, _ns0, di = _two_spec_index()
    resolver = TypeResolver(index, current_config=di)
    ref = resolver.resolve("ns=99;i=9999")
    assert isinstance(ref, TypeRef)
    assert "unresolved" in ref.qualified_class_name


# -- Equivalence by URI when instances differ ------------------------------


def test_resolver_treats_same_uri_as_in_spec():
    """Two NodesetConfig instances with same URI -> same spec."""
    index, ns0, _di = _two_spec_index()
    ns0_other = _ns0_cfg()
    assert ns0 is not ns0_other
    resolver = TypeResolver(index, current_config=ns0_other)
    ref = resolver.resolve("i=22")
    assert ref.is_in_spec is True


# -- runner ----------------------------------------------------------------


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
